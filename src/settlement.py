"""结算核心：一次取数在同一数据库事务内完成
签名校验 → 幂等终态复用 → 密钥状态 → 时钟偏差（contracts）→ 权限判定
→ 防重放 → 额度扣减 → 只追加审计。

幂等：同 (机构, idempotency_key) 的最终结果只产生一次。终态读取放在时钟偏差、
权限与额度检查之前，因此即使重试发生在时钟偏差窗口之外，也仍交付初次结果，
且绝不二次扣额度。
额度：对当 UTC 账期行加行锁后扣减，CHECK(consumed <= quota) 兜底，绝不超扣。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Mapping

from .db import cursor
from .signing import request_hash, verify_request
from .validators import ValidationError, parse_timestamp, validate

# 拒绝原因 → HTTP 状态码
REASON_STATUS = {
    "invalid_payload": 400,
    "unknown_key": 401,
    "bad_signature": 401,
    "key_inactive": 401,
    "stale_timestamp": 400,
    "future_timestamp": 400,
    "contract_missing": 500,
    "units_exceeded": 422,
    "scope_denied": 403,
    "idempotency_conflict": 409,
    "idempotency_in_flight": 409,
    "nonce_replayed": 409,
    "quota_exceeded": 429,
}


@dataclass
class Outcome:
    http_status: int
    body: dict[str, Any]

    @property
    def approved(self) -> bool:
        return self.http_status == 200


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return parse_timestamp(value)
    except (ValueError, TypeError):
        return None


def _audit(
    cur,
    *,
    organization_id: str | None,
    key_id: str | None,
    payload: Mapping[str, Any] | None,
    signature: str | None,
    rhash: str | None,
    result: str,
    reason: str | None,
    period_date: Any = None,
    consumption_event_id: int | None = None,
    remaining_after: int | None = None,
) -> None:
    cur.execute(
        """
        INSERT INTO audit_log (
            organization_id, key_id, idempotency_key, nonce, resource_scope,
            units, period_date, request_timestamp, signature, request_hash,
            result, reason, consumption_event_id, remaining_after
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        """,
        (
            organization_id,
            key_id,
            (payload or {}).get("idempotency_key"),
            (payload or {}).get("nonce"),
            (payload or {}).get("resource_scope"),
            (payload or {}).get("units"),
            period_date,
            _coerce_ts((payload or {}).get("timestamp")),
            signature,
            rhash,
            result,
            reason,
            consumption_event_id,
            remaining_after,
        ),
    )


def _reject(
    cur,
    *,
    status: int,
    reason: str,
    organization_id: str | None = None,
    key_id: str | None = None,
    payload: Mapping[str, Any] | None = None,
    signature: str | None = None,
    rhash: str | None = None,
    period_date: Any = None,
    remaining_after: int | None = None,
    detail: str | None = None,
) -> Outcome:
    body: dict[str, Any] = {
        "status": "rejected",
        "reason": reason,
        "idempotency_key": (payload or {}).get("idempotency_key"),
    }
    if detail:
        body["detail"] = detail
    _audit(
        cur,
        organization_id=organization_id,
        key_id=key_id,
        payload=payload,
        signature=signature,
        rhash=rhash,
        result="rejected",
        reason=reason,
        period_date=period_date,
        remaining_after=remaining_after,
    )
    return Outcome(status, body)


def _jsonb(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False)


def _existing_idempotent_outcome(
    cur,
    existing: tuple,
    *,
    organization_id: str,
    key_id: str,
    payload: Mapping[str, Any],
    signature: str | None,
    rhash: str,
    today: date,
) -> Outcome | None:
    """对已存在的幂等记录给出结论；processing/冲突/完全一致重试三种情形。"""
    state, old_hash, old_status, old_response, old_reason = existing

    if state == "processing":
        return _reject(
            cur, status=409, reason="idempotency_in_flight",
            organization_id=organization_id, key_id=key_id,
            payload=payload, signature=signature, rhash=rhash,
            period_date=today,
            detail="a request with this idempotency_key is still in flight",
        )
    if old_hash != rhash:
        return _reject(
            cur, status=409, reason="idempotency_conflict",
            organization_id=organization_id, key_id=key_id,
            payload=payload, signature=signature, rhash=rhash,
            period_date=today,
            detail="idempotency_key was already used for a different request",
        )

    # 完全相同的重试：交付初次结果，不再扣额度
    replay_period = old_response.get("period_date")
    if isinstance(replay_period, str):
        try:
            replay_period = date.fromisoformat(replay_period)
        except ValueError:
            replay_period = today
    _audit(
        cur,
        organization_id=organization_id,
        key_id=key_id,
        payload=payload,
        signature=signature,
        rhash=rhash,
        result="idempotent_replay",
        reason=old_reason,
        period_date=replay_period,
        consumption_event_id=old_response.get("consumption_event_id"),
        remaining_after=old_response.get("remaining"),
    )
    return Outcome(old_status, dict(old_response))


def settle(
    conn,
    payload: Any,
    signature: str | None,
    *,
    now: datetime | None = None,
) -> Outcome:
    """在调用方连接上执行一次结算（自行提交/回滚）。"""
    now = now or utc_now()
    today = now.date()

    # 0. 结构校验（不依赖机构身份）
    try:
        payload = validate(payload)
    except ValidationError as exc:
        with cursor(conn) as cur:
            outcome = _reject(
                cur,
                status=400,
                reason="invalid_payload",
                key_id=(payload or {}).get("key_id") if isinstance(payload, dict) else None,
                payload=payload if isinstance(payload, dict) else None,
                signature=signature,
                detail=str(exc),
            )
        conn.commit()
        return outcome

    rhash = request_hash(payload)
    key_id = payload["key_id"]

    try:
        with cursor(conn) as cur:
            # 1. 查找密钥（密钥行可轮换/停用；历史事件另存 key_id 不可变快照）
            cur.execute(
                "SELECT organization_id, secret, status FROM api_keys "
                "WHERE key_id = %s",
                (key_id,),
            )
            row = cur.fetchone()
            if row is None:
                outcome = _reject(
                    cur, status=401, reason="unknown_key", key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                )
                conn.commit()
                return outcome
            organization_id, secret, key_status = row

            # 2. 签名必须有效
            if not signature or not verify_request(secret, payload, signature):
                outcome = _reject(
                    cur, status=401, reason="bad_signature",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    period_date=today,
                )
                conn.commit()
                return outcome

            # 3. 幂等终态复用（优先于时戳/权限/额度，迟到重试也返回初次结果）。
            #    revoked 密钥一律不可用；rotated 密钥只允许取回历史初次结果。
            cur.execute(
                "SELECT state, request_hash, http_status, response, reason "
                "FROM idempotent_results "
                "WHERE organization_id = %s AND idempotency_key = %s",
                (organization_id, payload["idempotency_key"]),
            )
            existing = cur.fetchone()
            if existing is not None:
                if key_status == "revoked":
                    outcome = _reject(
                        cur, status=401, reason="key_inactive",
                        organization_id=organization_id, key_id=key_id,
                        payload=payload, signature=signature, rhash=rhash,
                        period_date=today,
                    )
                    conn.commit()
                    return outcome
                outcome = _existing_idempotent_outcome(
                    cur, existing,
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash, today=today,
                )
                conn.commit()
                return outcome

            # 4. 只有 active 密钥可以发起新消费；rotated/revoked 一律拒绝。
            #    历史 consumption_events.key_id 是不可变快照，不受轮换影响。
            if key_status != "active":
                outcome = _reject(
                    cur, status=401, reason="key_inactive",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    period_date=today,
                )
                conn.commit()
                return outcome

            # 5. 合同参数（允许的时钟偏差从 contracts 读取）
            cur.execute(
                "SELECT clock_skew_seconds, max_units_per_request "
                "FROM contracts WHERE organization_id = %s",
                (organization_id,),
            )
            contract = cur.fetchone()
            if contract is None:
                outcome = _reject(
                    cur, status=500, reason="contract_missing",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    period_date=today,
                )
                conn.commit()
                return outcome
            clock_skew_seconds, max_units = contract

            # 6. 时钟偏差（过去与未来对称，阈值取自合同）
            request_ts = parse_timestamp(payload["timestamp"])
            delta = (request_ts - now).total_seconds()
            if delta < -clock_skew_seconds:
                outcome = _reject(
                    cur, status=400, reason="stale_timestamp",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    detail=f"timestamp older than {clock_skew_seconds}s",
                    period_date=today,
                )
                conn.commit()
                return outcome
            if delta > clock_skew_seconds:
                outcome = _reject(
                    cur, status=400, reason="future_timestamp",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    detail=f"timestamp more than {clock_skew_seconds}s in the future",
                    period_date=today,
                )
                conn.commit()
                return outcome

            # 7. 单笔上限
            if max_units is not None and payload["units"] > max_units:
                outcome = _reject(
                    cur, status=422, reason="units_exceeded",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    detail=f"units exceed per-request maximum {max_units}",
                    period_date=today,
                )
                conn.commit()
                return outcome

            # 8. 资源范围必须获准
            cur.execute(
                "SELECT 1 FROM scope_grants "
                "WHERE organization_id = %s AND resource_scope = %s "
                "AND revoked_at IS NULL",
                (organization_id, payload["resource_scope"]),
            )
            if cur.fetchone() is None:
                outcome = _reject(
                    cur, status=403, reason="scope_denied",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    period_date=today,
                )
                conn.commit()
                return outcome

            # 9. 占用幂等键。SELECT 与 INSERT 之间若被并发请求抢先，则按
            #    已存在记录（processing/终态）处理。
            cur.execute(
                """
                INSERT INTO idempotent_results
                    (organization_id, idempotency_key, state, request_hash,
                     approved, key_id)
                VALUES (%s, %s, 'processing', %s, FALSE, %s)
                ON CONFLICT (organization_id, idempotency_key) DO NOTHING
                """,
                (organization_id, payload["idempotency_key"], rhash, key_id),
            )
            if cur.rowcount == 0:
                cur.execute(
                    "SELECT state, request_hash, http_status, response, reason "
                    "FROM idempotent_results "
                    "WHERE organization_id = %s AND idempotency_key = %s",
                    (organization_id, payload["idempotency_key"]),
                )
                outcome = _existing_idempotent_outcome(
                    cur, cur.fetchone(),
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash, today=today,
                )
                conn.commit()
                return outcome

            # 10. nonce 防重放（仅签名/时戳通过且键已占用后才登记）
            cur.execute(
                "INSERT INTO used_nonces(organization_id, nonce, first_key_id) "
                "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (organization_id, payload["nonce"], key_id),
            )
            if cur.rowcount == 0:
                outcome = _reject(
                    cur, status=409, reason="nonce_replayed",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    period_date=today,
                )
                cur.execute(
                    "UPDATE idempotent_results SET state = 'final', "
                    "approved = FALSE, http_status = %s, reason = %s, "
                    "response = %s::jsonb, finalized_at = now() "
                    "WHERE organization_id = %s AND idempotency_key = %s",
                    (409, "nonce_replayed", _jsonb(outcome.body),
                     organization_id, payload["idempotency_key"]),
                )
                conn.commit()
                return outcome

            # 11. 当 UTC 账期额度行：插入后加行锁再扣减
            cur.execute(
                "SELECT daily_quota FROM organizations WHERE id = %s",
                (organization_id,),
            )
            daily_quota = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO quota_periods(organization_id, period_date, quota)
                VALUES (%s, %s, %s)
                ON CONFLICT (organization_id, period_date) DO NOTHING
                """,
                (organization_id, today, daily_quota),
            )
            cur.execute(
                "SELECT quota, consumed FROM quota_periods "
                "WHERE organization_id = %s AND period_date = %s "
                "FOR UPDATE",
                (organization_id, today),
            )
            quota, consumed = cur.fetchone()
            remaining = quota - consumed
            if payload["units"] > remaining:
                outcome = _reject(
                    cur, status=429, reason="quota_exceeded",
                    organization_id=organization_id, key_id=key_id,
                    payload=payload, signature=signature, rhash=rhash,
                    period_date=today, remaining_after=remaining,
                    detail=f"need {payload['units']}, remaining {remaining}",
                )
                # 终态化：同样的重试之后仍返回这次“额度不足”的结论
                cur.execute(
                    "UPDATE idempotent_results SET state = 'final', "
                    "approved = FALSE, http_status = %s, reason = %s, "
                    "response = %s::jsonb, finalized_at = now() "
                    "WHERE organization_id = %s AND idempotency_key = %s",
                    (429, "quota_exceeded", _jsonb(outcome.body),
                     organization_id, payload["idempotency_key"]),
                )
                conn.commit()
                return outcome

            # 12. 扣减（CHECK(consumed <= quota) 为最后防线）
            cur.execute(
                "UPDATE quota_periods SET consumed = consumed + %s, "
                "updated_at = now() "
                "WHERE organization_id = %s AND period_date = %s "
                "RETURNING consumed",
                (payload["units"], organization_id, today),
            )
            new_consumed = cur.fetchone()[0]
            remaining_after = quota - new_consumed

            # 13. 获批台账：key_id 为不可变快照
            cur.execute(
                """
                INSERT INTO consumption_events
                    (organization_id, period_date, key_id, idempotency_key,
                     nonce, resource_scope, units, request_timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    organization_id, today, key_id, payload["idempotency_key"],
                    payload["nonce"], payload["resource_scope"], payload["units"],
                    request_ts,
                ),
            )
            event_id = cur.fetchone()[0]

            response = {
                "status": "approved",
                "idempotency_key": payload["idempotency_key"],
                "organization_id": organization_id,
                "key_id": key_id,
                "resource_scope": payload["resource_scope"],
                "units": payload["units"],
                "period_date": str(today),
                "quota": quota,
                "remaining": remaining_after,
                "consumption_event_id": event_id,
                "request_timestamp": payload["timestamp"],
            }

            # 14. 终态化幂等结果
            cur.execute(
                "UPDATE idempotent_results SET state = 'final', approved = TRUE, "
                "http_status = %s, reason = NULL, response = %s::jsonb, "
                "finalized_at = now() "
                "WHERE organization_id = %s AND idempotency_key = %s",
                (200, _jsonb(response), organization_id, payload["idempotency_key"]),
            )

            # 15. 只追加审计
            _audit(
                cur,
                organization_id=organization_id,
                key_id=key_id,
                payload=payload,
                signature=signature,
                rhash=rhash,
                result="approved",
                reason=None,
                period_date=today,
                consumption_event_id=event_id,
                remaining_after=remaining_after,
            )
        conn.commit()
        return Outcome(200, response)
    except Exception:
        conn.rollback()
        raise
