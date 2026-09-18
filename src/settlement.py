"""结算核心：在单个数据库事务内串行完成

签名校验 -> 时钟偏差（读合约）-> 防重放 -> 权限判定 -> 额度扣减
-> 只追加流水/审计 -> 幂等初次结果持久化。

并发触及额度边界时，依赖 ``daily_quota_usage`` 同一行的谓词 UPDATE
（``WHERE consumed + %s <= daily_quota``）行锁串行化，绝不多扣：
后到的事务在锁上等待，提交后谓词失败即记拒绝并返回 QUOTA_EXCEEDED。
"""

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

import json

import psycopg
from psycopg.errors import UniqueViolation

from .signing import request_fingerprint, signing_string, verify

# 拒绝原因码（同时作为审计 / 拒绝汇总的稳定枚举）。
REJECT_SIGNATURE_INVALID = "SIGNATURE_INVALID"
REJECT_KEY_UNKNOWN = "KEY_UNKNOWN"
REJECT_KEY_INACTIVE = "KEY_INACTIVE"
REJECT_CLOCK_SKEW = "CLOCK_SKEW_EXCEEDED"
REJECT_TIMESTAMP_MALFORMED = "TIMESTAMP_MALFORMED"
REJECT_REPLAY = "NONCE_REPLAY"
REJECT_SCOPE_DENIED = "SCOPE_DENIED"
REJECT_QUOTA = "QUOTA_EXCEEDED"
REJECT_IDEMPOTENCY_MISMATCH = "IDEMPOTENCY_KEY_REUSE"

REJECT_HTTP_STATUS = {
    REJECT_SIGNATURE_INVALID: 401,
    REJECT_KEY_UNKNOWN: 401,
    REJECT_KEY_INACTIVE: 401,
    REJECT_CLOCK_SKEW: 401,
    REJECT_TIMESTAMP_MALFORMED: 400,
    REJECT_REPLAY: 409,
    REJECT_SCOPE_DENIED: 403,
    REJECT_QUOTA: 429,
    REJECT_IDEMPOTENCY_MISMATCH: 409,
}

REQUIRED_FIELDS = ("key_id", "timestamp", "nonce", "resource_scope", "units", "idempotency_key")


@dataclass
class SettleResult:
    status: int
    approved: bool
    body: dict[str, Any] = field(default_factory=dict)
    replayed: bool = False  # True 表示命中幂等记录，返回的是初次结果


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str) -> datetime:
    """解析 ISO-8601；把朴素时间视为 UTC，统一返回带时区时间。"""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _reject(status: int, reason: str, detail: str | None = None, **extra: Any) -> SettleResult:
    body: dict[str, Any] = {"decision": "rejected", "reject_reason": reason}
    if detail:
        body["detail"] = detail
    body.update(extra)
    return SettleResult(status=status, approved=False, body=body)


def _load_existing_result(cur: psycopg.Cursor, organization_id: str, idem_key: str) -> SettleResult | None:
    """读取并组装幂等初次结果；记录尚不存在（异常竞态）时返回 None。"""
    cur.execute(
        "SELECT http_status, response FROM idempotency_records "
        "WHERE organization_id = %s AND idempotency_key = %s FOR UPDATE",
        (organization_id, idem_key),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return SettleResult(
        status=row["http_status"],
        approved=row["response"].get("decision") == "approved",
        body=dict(row["response"]),
        replayed=True,
    )


def _reject_recorded(
    cur: psycopg.Cursor,
    *,
    organization_id: str | None,
    key_id: str,
    resource_scope: str | None,
    units: int | None,
    nonce: str | None,
    request_timestamp: datetime | None,
    idempotency_key: str | None,
    signature_valid: bool,
    reason: str,
    detail: str | None,
    fingerprint: str | None = None,
) -> SettleResult:
    """写入只追加审计与幂等记录（若具备机构上下文与幂等键），返回拒绝结果。"""
    cur.execute(
        """
        INSERT INTO audit_log (
            organization_id, key_id, resource_scope, units, nonce,
            request_timestamp, idempotency_key, signature_valid,
            decision, reject_reason
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'rejected', %s)
        RETURNING id
        """,
        (
            organization_id, key_id, resource_scope, units, nonce,
            request_timestamp, idempotency_key, signature_valid, reason,
        ),
    )
    cur.fetchone()
    body: dict[str, Any] = {"decision": "rejected", "reject_reason": reason}
    if detail:
        body["detail"] = detail
    status = REJECT_HTTP_STATUS[reason]
    if organization_id is not None and idempotency_key is not None:
        cur.execute(
            """
            INSERT INTO idempotency_records (
                organization_id, idempotency_key, key_id, request_fingerprint,
                outcome, reject_reason, http_status, response
            ) VALUES (%s, %s, %s, %s, 'rejected', %s, %s, %s::jsonb)
            """,
            (
                organization_id, idempotency_key, key_id, fingerprint or "",
                reason, status, json.dumps(body),
            ),
        )
    return SettleResult(status=status, approved=False, body=body)


def settle(
    conn: psycopg.Connection,
    payload: dict[str, Any],
    *,
    signature: str,
    method: str = "POST",
    path: str = "/v1/settlement",
    now: datetime | None = None,
) -> SettleResult:
    now = now or _utcnow()
    key_id = payload["key_id"]
    timestamp_raw = payload["timestamp"]
    nonce = payload["nonce"]
    scope = payload["resource_scope"]
    units = int(payload["units"])
    idem_key = payload["idempotency_key"]

    try:
        req_ts = parse_timestamp(timestamp_raw)
    except (ValueError, TypeError):
        req_ts = None

    with conn.cursor() as cur:
        # ---- 1. 取密钥（FOR UPDATE 让同 key 并发请求在密钥行上有序，
        #         并保证轮换状态在事务内稳定）。----
        cur.execute(
            "SELECT key_id, organization_id, shared_secret, status "
            "FROM api_keys WHERE key_id = %s FOR UPDATE",
            (key_id,),
        )
        key_row = cur.fetchone()
        if key_row is None:
            # 未知 key：无法定位机构/合约，只审计、不写幂等。
            if req_ts is None:
                result = _reject(400, REJECT_TIMESTAMP_MALFORMED, f"bad timestamp: {timestamp_raw!r}")
            else:
                result = _reject(401, REJECT_KEY_UNKNOWN, f"unknown key_id {key_id!r}")
            cur.execute(
                """
                INSERT INTO audit_log (
                    organization_id, key_id, resource_scope, units, nonce,
                    request_timestamp, idempotency_key, signature_valid,
                    decision, reject_reason, debug_info
                ) VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, 'rejected', %s, %s::jsonb)
                """,
                (
                    key_id, scope, units, nonce, req_ts, idem_key, False,
                    result.body["reject_reason"],
                    json.dumps({"detail": result.body.get("detail")}),
                ),
            )
            conn.commit()
            return result

        org_id = key_row["organization_id"]
        fingerprint = request_fingerprint(key_id, timestamp_raw, nonce, payload)

        # 同一 (机构, 幂等键) 的所有请求在事务级咨询锁上串行，
        # 使“先 SELECT 后 INSERT”的幂等判定在并发下严格成立。
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (f"{org_id}:{idem_key}",))

        # ---- 2. 签名校验必须先于一切业务判定（含幂等），
        #         否则篡改体会借幂等键复用之名掩盖鉴权失败。----
        message = signing_string(method, path, key_id, timestamp_raw, nonce, idem_key, payload)
        sig_valid = bool(verify(key_row["shared_secret"].encode("utf-8"), message, signature or ""))
        if not sig_valid:
            # 安全类失败不写幂等记录：未掌握密钥者不能占位幂等键。
            result = _reject_recorded(
                cur,
                organization_id=org_id, key_id=key_id, resource_scope=scope,
                units=units, nonce=nonce, request_timestamp=req_ts,
                idempotency_key=None, signature_valid=False,
                reason=REJECT_SIGNATURE_INVALID, detail="HMAC-SHA256 verification failed",
            )
            conn.commit()
            return result

        # ---- 3. 幂等：同机构 + 同幂等键且指纹一致，直接返回初次结果
        #         （含相同 HTTP 状态）。签名已验证；重试不再受时钟偏差/
        #         nonce/密钥状态的二次影响，保证“重试返回初次结果”。----
        cur.execute(
            """
            SELECT request_fingerprint, http_status, response
            FROM idempotency_records
            WHERE organization_id = %s AND idempotency_key = %s
            FOR UPDATE
            """,
            (org_id, idem_key),
        )
        existing = cur.fetchone()
        if existing is not None:
            if existing["request_fingerprint"] != fingerprint:
                # 幂等键被不同请求体复用：明确拒绝，不能让重试语义被污染。
                result = _reject_recorded(
                    cur,
                    organization_id=org_id,
                    key_id=key_id,
                    resource_scope=scope,
                    units=units,
                    nonce=nonce,
                    request_timestamp=req_ts,
                    idempotency_key=None,
                    signature_valid=True,
                    reason=REJECT_IDEMPOTENCY_MISMATCH,
                    detail=f"idempotency_key {idem_key!r} already used with a different request",
                )
                conn.commit()
                return result
            cur.execute(
                """
                INSERT INTO audit_log (
                    organization_id, key_id, resource_scope, units, nonce,
                    request_timestamp, idempotency_key, signature_valid,
                    decision, reject_reason, debug_info
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE,
                          CASE WHEN %s THEN 'approved' ELSE 'rejected' END,
                          %s, %s::jsonb)
                """,
                (
                    org_id, key_id, scope, units, nonce, req_ts, idem_key,
                    existing["response"].get("decision") == "approved",
                    existing["response"].get("reject_reason"),
                    json.dumps({"idempotent_replay": True}),
                ),
            )
            conn.commit()
            return SettleResult(
                status=existing["http_status"],
                approved=existing["response"].get("decision") == "approved",
                body=dict(existing["response"]),
                replayed=True,
            )

        if key_row["status"] != "active":
            result = _reject_recorded(
                cur,
                organization_id=org_id, key_id=key_id, resource_scope=scope,
                units=units, nonce=nonce, request_timestamp=req_ts,
                idempotency_key=idem_key, signature_valid=True,
                reason=REJECT_KEY_INACTIVE, detail=f"key status is {key_row['status']}",
                fingerprint=fingerprint,
            )
            conn.commit()
            return result

        # ---- 4. 时间戳与合约时钟偏差（偏差从 contracts 读取）。----
        if req_ts is None:
            # 协议格式错误：审计但不占幂等键，客户端修正后可原样重试。
            result = _reject_recorded(
                cur,
                organization_id=org_id, key_id=key_id, resource_scope=scope,
                units=units, nonce=nonce, request_timestamp=None,
                idempotency_key=None, signature_valid=True,
                reason=REJECT_TIMESTAMP_MALFORMED, detail=f"bad timestamp: {timestamp_raw!r}",
            )
            conn.commit()
            return result

        cur.execute(
            "SELECT allowed_clock_skew_seconds, nonce_retention_seconds "
            "FROM contracts WHERE organization_id = %s FOR SHARE",
            (org_id,),
        )
        contract = cur.fetchone()
        skew = contract["allowed_clock_skew_seconds"] if contract else 300

        if abs((now - req_ts).total_seconds()) > skew:
            result = _reject_recorded(
                cur,
                organization_id=org_id, key_id=key_id, resource_scope=scope,
                units=units, nonce=nonce, request_timestamp=req_ts,
                idempotency_key=idem_key, signature_valid=True,
                reason=REJECT_CLOCK_SKEW,
                detail=f"timestamp skew exceeds contract allowance of {skew}s",
                fingerprint=fingerprint,
            )
            conn.commit()
            return result

        # ---- 5. 防重放：唯一约束 + 先行插入；重复 nonce 即拒绝。
        #         若初次请求已提交，则这是并发/迟到重试，原样返回初次结果。
        try:
            cur.execute(
                "INSERT INTO used_nonces (key_id, nonce, request_timestamp) "
                "VALUES (%s, %s, %s)",
                (key_id, nonce, req_ts),
            )
        except UniqueViolation:
            conn.rollback()
            with conn.cursor() as cur2:
                existing_result = _load_existing_result(cur2, org_id, idem_key)
                if existing_result is not None and existing_result.body:
                    # 幂等指纹必须一致；不一致属于幂等键复用。
                    cur2.execute(
                        "SELECT request_fingerprint FROM idempotency_records "
                        "WHERE organization_id = %s AND idempotency_key = %s",
                        (org_id, idem_key),
                    )
                    stored_fp = cur2.fetchone()["request_fingerprint"]
                    if stored_fp != fingerprint:
                        result = _reject_recorded(
                            cur2,
                            organization_id=org_id, key_id=key_id, resource_scope=scope,
                            units=units, nonce=nonce, request_timestamp=req_ts,
                            idempotency_key=None, signature_valid=True,
                            reason=REJECT_IDEMPOTENCY_MISMATCH,
                            detail=f"idempotency_key {idem_key!r} already used with a different request",
                        )
                        conn.commit()
                        return result
                    cur2.execute(
                        """
                        INSERT INTO audit_log (
                            organization_id, key_id, resource_scope, units, nonce,
                            request_timestamp, idempotency_key, signature_valid,
                            decision, reject_reason, debug_info
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE,
                                  CASE WHEN %s THEN 'approved' ELSE 'rejected' END,
                                  %s, %s::jsonb)
                        """,
                        (
                            org_id, key_id, scope, units, nonce, req_ts, idem_key,
                            existing_result.approved,
                            existing_result.body.get("reject_reason"),
                            json.dumps({"idempotent_replay": True, "concurrent": True}),
                        ),
                    )
                    conn.commit()
                    return existing_result
                result = _reject_recorded(
                    cur2,
                    organization_id=org_id, key_id=key_id, resource_scope=scope,
                    units=units, nonce=nonce, request_timestamp=req_ts,
                    idempotency_key=idem_key, signature_valid=True,
                    reason=REJECT_REPLAY, detail="nonce already consumed",
                )
            conn.commit()
            return result

        # ---- 6. 资源范围判定。----
        cur.execute(
            "SELECT 1 FROM key_scopes WHERE key_id = %s AND resource_scope = %s",
            (key_id, scope),
        )
        if cur.fetchone() is None:
            result = _reject_recorded(
                cur,
                organization_id=org_id, key_id=key_id, resource_scope=scope,
                units=units, nonce=nonce, request_timestamp=req_ts,
                idempotency_key=idem_key, signature_valid=True,
                reason=REJECT_SCOPE_DENIED,
                detail=f"scope {scope!r} not granted to key",
                fingerprint=fingerprint,
            )
            conn.commit()
            return result

        # ---- 7. 额度扣减：按 UTC 账期，谓词 UPDATE 原子判定。----
        billing_day = now.date()
        cur.execute(
            """
            INSERT INTO daily_quota_usage (organization_id, billing_day, consumed)
            VALUES (%s, %s, 0)
            ON CONFLICT (organization_id, billing_day) DO NOTHING
            """,
            (org_id, billing_day),
        )
        cur.execute(
            """
            UPDATE daily_quota_usage
               SET consumed = consumed + %s, updated_at = now()
             WHERE organization_id = %s
               AND billing_day = %s
               AND consumed + %s <= (
                     SELECT daily_quota FROM organizations WHERE id = %s)
            RETURNING consumed
            """,
            (units, org_id, billing_day, units, org_id),
        )
        updated = cur.fetchone()
        if updated is None:
            # 未取到行锁或额度不足：读取当前余量给出确定原因。
            cur.execute(
                "SELECT u.consumed, o.daily_quota "
                "FROM daily_quota_usage u JOIN organizations o ON o.id = u.organization_id "
                "WHERE u.organization_id = %s AND u.billing_day = %s",
                (org_id, billing_day),
            )
            row = cur.fetchone()
            remaining = row["daily_quota"] - row["consumed"]
            result = _reject_recorded(
                cur,
                organization_id=org_id, key_id=key_id, resource_scope=scope,
                units=units, nonce=nonce, request_timestamp=req_ts,
                idempotency_key=idem_key, signature_valid=True,
                reason=REJECT_QUOTA,
                detail=f"requested {units}, remaining {remaining}",
                fingerprint=fingerprint,
            )
            conn.commit()
            return result

        # ---- 8. 全部满足：写只追加流水、审计、幂等初次结果。----
        cur.execute(
            """
            INSERT INTO consumption_events
                (organization_id, key_id, resource_scope, units, idempotency_key, billing_day)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (org_id, key_id, scope, units, idem_key, billing_day),
        )
        event_id = cur.fetchone()["id"]
        cur.execute(
            """
            INSERT INTO audit_log (
                organization_id, key_id, resource_scope, units, nonce,
                request_timestamp, idempotency_key, signature_valid,
                decision, consumption_event_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, 'approved', %s)
            RETURNING id
            """,
            (org_id, key_id, scope, units, nonce, req_ts, idem_key, event_id),
        )
        audit_id = cur.fetchone()["id"]

        cur.execute(
            "SELECT daily_quota FROM organizations WHERE id = %s", (org_id,)
        )
        daily_quota = cur.fetchone()["daily_quota"]
        consumed_after = updated["consumed"]
        body = {
            "decision": "approved",
            "organization_id": org_id,
            "resource_scope": scope,
            "units": units,
            "billing_day": billing_day.isoformat(),
            "consumed": consumed_after,
            "daily_quota": daily_quota,
            "remaining": daily_quota - consumed_after,
            "consumption_event_id": event_id,
            "audit_cursor": audit_id,
        }
        try:
            cur.execute(
                """
                INSERT INTO idempotency_records (
                    organization_id, idempotency_key, key_id, request_fingerprint,
                    outcome, consumption_event_id, http_status, response
                ) VALUES (%s, %s, %s, %s, 'approved', %s, 201, %s::jsonb)
                """,
                (org_id, idem_key, key_id, fingerprint, event_id, json.dumps(body)),
            )
        except UniqueViolation:
            # 跨 key 同幂等键的并发：另一方已先提交，放弃本次扣减，返回初次结果。
            conn.rollback()
            with conn.cursor() as cur2:
                existing_result = _load_existing_result(cur2, org_id, idem_key)
            if existing_result is not None:
                with conn.cursor() as cur2:
                    cur2.execute(
                        """
                        INSERT INTO audit_log (
                            organization_id, key_id, resource_scope, units, nonce,
                            request_timestamp, idempotency_key, signature_valid,
                            decision, reject_reason, debug_info
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE,
                                  CASE WHEN %s THEN 'approved' ELSE 'rejected' END,
                                  %s, %s::jsonb)
                        """,
                        (
                            org_id, key_id, scope, units, nonce, req_ts, idem_key,
                            existing_result.approved,
                            existing_result.body.get("reject_reason"),
                            json.dumps({"idempotent_replay": True, "concurrent": True}),
                        ),
                    )
                conn.commit()
                return existing_result
            raise
        conn.commit()
        return SettleResult(status=201, approved=True, body=body)


# ---------------------------------------------------------------------------
# 查询面：额度 / 拒绝汇总 / 连续审计游标 / 密钥轮换
# ---------------------------------------------------------------------------

def quota_view(conn: psycopg.Connection, organization_id: str, day: str | None = None) -> dict[str, Any]:
    """按 UTC 账期返回剩余额度。"""
    billing_day = date.fromisoformat(day) if day else _utcnow().date()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT o.daily_quota,
                   COALESCE(u.consumed, 0) AS consumed
              FROM organizations o
              LEFT JOIN daily_quota_usage u
                ON u.organization_id = o.id AND u.billing_day = %s
             WHERE o.id = %s
            """,
            (billing_day, organization_id),
        )
        row = cur.fetchone()
        if row is None:
            raise KeyError(organization_id)
        return {
            "organization_id": organization_id,
            "billing_day": billing_day.isoformat(),
            "daily_quota": row["daily_quota"],
            "consumed": row["consumed"],
            "remaining": row["daily_quota"] - row["consumed"],
        }


def rejection_summary(conn: psycopg.Connection, organization_id: str, day: str | None = None) -> dict[str, Any]:
    billing_day = date.fromisoformat(day) if day else _utcnow().date()
    start = datetime(billing_day.year, billing_day.month, billing_day.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT reject_reason, count(*) AS count
              FROM audit_log
             WHERE organization_id = %s
               AND decision = 'rejected'
               AND occurred_at >= %s AND occurred_at < %s
             GROUP BY reject_reason
             ORDER BY count(*) DESC, reject_reason
            """,
            (organization_id, start, end),
        )
        rows = cur.fetchall()
    return {
        "organization_id": organization_id,
        "billing_day": billing_day.isoformat(),
        "rejections": [{"reason": r["reject_reason"], "count": r["count"]} for r in rows],
        "total": sum(r["count"] for r in rows),
    }


# 机构调用方可读字段；debug_info / signature_valid / nonce 等排障字段被裁剪。
ORG_AUDIT_COLUMNS = (
    "id", "occurred_at", "organization_id", "key_id", "resource_scope", "units",
    "request_timestamp", "idempotency_key", "decision", "reject_reason",
    "consumption_event_id",
)


def audit_cursor(
    conn: psycopg.Connection,
    *,
    organization_id: str | None,
    after_id: int = 0,
    limit: int = 100,
    caller: str = "org",
) -> dict[str, Any]:
    """连续审计游标：按 ``audit_log.id`` 严格递增向前翻页。

    caller='org' 时强制按本机构范围裁剪（WHERE organization_id）且裁剪排障列；
    caller='operator' 可见全部机构与全部字段。重启后只需保存 next_cursor。
    """
    limit = max(1, min(limit, 1000))
    with conn.cursor() as cur:
        if caller == "operator":
            if organization_id is not None:
                cur.execute(
                    """
                    SELECT * FROM audit_log
                     WHERE id > %s AND organization_id = %s
                     ORDER BY id ASC LIMIT %s
                    """,
                    (after_id, organization_id, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM audit_log WHERE id > %s ORDER BY id ASC LIMIT %s",
                    (after_id, limit),
                )
        else:
            cols = ", ".join(ORG_AUDIT_COLUMNS)
            cur.execute(
                f"""
                SELECT {cols} FROM audit_log
                 WHERE id > %s AND organization_id = %s
                 ORDER BY id ASC LIMIT %s
                """,
                (after_id, organization_id, limit),
            )
        rows = cur.fetchall()

    entries = []
    for r in rows:
        entry = {}
        for k, v in r.items():
            if isinstance(v, datetime):
                v = v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            entry[k] = v
        entries.append(entry)
    next_cursor = rows[-1]["id"] if rows else after_id
    return {
        "entries": entries,
        "next_cursor": next_cursor,
        "has_more": len(rows) == limit,
    }


def rotate_key(conn: psycopg.Connection, old_key_id: str, new_key_id: str, new_secret: str) -> dict[str, Any]:
    """密钥轮换：旧 key 置 rotated 并指向新 key；授权范围平移；旧记录的 key_id 不动。"""
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM api_keys WHERE key_id = %s FOR UPDATE", (old_key_id,))
        old = cur.fetchone()
        if old is None:
            raise KeyError(old_key_id)
        if old["status"] != "active":
            raise ValueError(f"key {old_key_id!r} is not active (status={old['status']})")
        cur.execute(
            "INSERT INTO api_keys (key_id, organization_id, shared_secret, status) "
            "VALUES (%s, %s, %s, 'active')",
            (new_key_id, old["organization_id"], new_secret),
        )
        cur.execute(
            "INSERT INTO key_scopes (key_id, resource_scope) "
            "SELECT %s, resource_scope FROM key_scopes WHERE key_id = %s",
            (new_key_id, old_key_id),
        )
        cur.execute(
            "UPDATE api_keys SET status = 'rotated', superseded_by = %s, rotated_at = now() "
            "WHERE key_id = %s",
            (new_key_id, old_key_id),
        )
        cur.execute(
            """
            INSERT INTO audit_log (organization_id, key_id, signature_valid,
                                   decision, debug_info)
            VALUES (%s, %s, TRUE, 'admin', %s::jsonb)
            """,
            (old["organization_id"], old_key_id,
             json.dumps({"event": "key_rotation", "rotated_from": old_key_id, "rotated_to": new_key_id})),
        )
    conn.commit()
    return {"old_key_id": old_key_id, "new_key_id": new_key_id, "organization_id": old["organization_id"]}


def ledger_reconciliation(conn: psycopg.Connection, organization_id: str, day: str | None = None) -> dict[str, Any]:
    """账面核对：逐笔流水必须对应获准范围；汇总与 daily_quota_usage 必须相等。"""
    billing_day = date.fromisoformat(day) if day else _utcnow().date()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT e.id, e.key_id, e.resource_scope, e.units, e.idempotency_key,
                   (s.resource_scope IS NOT NULL) AS scope_granted
              FROM consumption_events e
              LEFT JOIN key_scopes s ON s.key_id = e.key_id AND s.resource_scope = e.resource_scope
             WHERE e.organization_id = %s AND e.billing_day = %s
             ORDER BY e.id
            """,
            (organization_id, billing_day),
        )
        events = cur.fetchall()
        cur.execute(
            "SELECT consumed FROM daily_quota_usage WHERE organization_id = %s AND billing_day = %s",
            (organization_id, billing_day),
        )
        row = cur.fetchone()
    events_total = sum(e["units"] for e in events)
    ungranted = [
        {"event_id": e["id"], "key_id": e["key_id"], "resource_scope": e["resource_scope"]}
        for e in events if not e["scope_granted"]
    ]
    return {
        "organization_id": organization_id,
        "billing_day": billing_day.isoformat(),
        "event_count": len(events),
        "events_sum_units": events_total,
        "ledger_consumed": row["consumed"] if row else 0,
        "balanced": (row["consumed"] if row else 0) == events_total,
        "every_event_scope_granted": not ungranted,
        "ungranted_events": ungranted,
        "events": [
            {
                "event_id": e["id"], "key_id": e["key_id"],
                "resource_scope": e["resource_scope"], "units": e["units"],
                "idempotency_key": e["idempotency_key"], "scope_granted": e["scope_granted"],
            }
            for e in events
        ],
    }
