"""机构侧只读查询：全部按调用方所属机构与可见字段裁剪。

- 剩余额度按 UTC 账期返回
- 拒绝原因汇总按 UTC 账期统计
- 审计游标：只向前、不重不漏，以 (id) 为连续游标，可跨 PostgreSQL 重启续读
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Iterable

from .db import DEFAULT_VISIBLE, cursor

# 审计行可能对外暴露的全部字段（signature/request_hash 永不开放）
_AUDIT_COLUMNS = [
    "id",
    "created_at",
    "organization_id",
    "key_id",
    "idempotency_key",
    "nonce",
    "resource_scope",
    "units",
    "period_date",
    "request_timestamp",
    "result",
    "reason",
    "consumption_event_id",
    "remaining_after",
]

_DATE_FIELDS = {"period_date"}
_TS_FIELDS = {"created_at", "request_timestamp"}


class AuthorizationError(Exception):
    """调用方密钥无效或无权进行机构查询。"""


def caller_org(cur, key_id: str) -> tuple[str, list[str]]:
    """以查询头里的 key_id 鉴权，返回 (机构 id, 可见字段白名单)。

    请求签名由 HTTP 层另行校验；本函数只确认密钥存在且未吊销。
    """
    cur.execute(
        "SELECT organization_id, status FROM api_keys WHERE key_id = %s",
        (key_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise AuthorizationError("unknown_key")
    organization_id, status = row
    if status not in ("active", "rotated"):
        raise AuthorizationError("key_revoked")
    return organization_id, _visible_fields(cur, organization_id, key_id)


def _visible_fields(cur, organization_id: str, key_id: str) -> list[str]:
    cur.execute(
        "SELECT view_fields FROM api_keys WHERE key_id = %s", (key_id,)
    )
    fields = cur.fetchone()[0]
    if fields and fields == ["*"]:
        return list(_AUDIT_COLUMNS)
    allowed = set(fields or DEFAULT_VISIBLE)
    return [f for f in _AUDIT_COLUMNS if f in allowed]


def _iso(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _date(value: dt.date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _project(row: dict[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    return {f: row.get(f) for f in fields}


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for f in _TS_FIELDS:
        if f in out:
            out[f] = _iso(out[f])
    for f in _DATE_FIELDS:
        if f in out:
            out[f] = _date(out[f])
    return out


def quota_status(cur, organization_id: str, period_date: dt.date) -> dict[str, Any]:
    """UTC 账期剩余额度。"""
    cur.execute(
        "SELECT daily_quota FROM organizations WHERE id = %s", (organization_id,)
    )
    row = cur.fetchone()
    if row is None:
        raise AuthorizationError("unknown_organization")
    daily_quota = row[0]
    cur.execute(
        "SELECT quota, consumed FROM quota_periods "
        "WHERE organization_id = %s AND period_date = %s",
        (organization_id, period_date),
    )
    period = cur.fetchone()
    if period is None:
        quota, consumed = daily_quota, 0
    else:
        quota, consumed = period
    return {
        "organization_id": organization_id,
        "period_date": _date(period_date),
        "timezone": "UTC",
        "quota": quota,
        "consumed": consumed,
        "remaining": quota - consumed,
    }


def rejection_summary(cur, organization_id: str, period_date: dt.date) -> dict[str, Any]:
    """UTC 账期拒绝原因汇总（每条拒绝对应一行只追加审计）。"""
    cur.execute(
        """
        SELECT reason, COUNT(*) AS n
        FROM audit_log
        WHERE organization_id = %s
          AND period_date = %s
          AND result = 'rejected'
        GROUP BY reason
        ORDER BY n DESC, reason
        """,
        (organization_id, period_date),
    )
    rows = cur.fetchall()
    total = sum(r[1] for r in rows)
    return {
        "organization_id": organization_id,
        "period_date": _date(period_date),
        "timezone": "UTC",
        "total_rejected": total,
        "reasons": [{"reason": r[0], "count": r[1]} for r in rows],
    }


def audit_cursor(
    cur,
    organization_id: str,
    fields: list[str],
    *,
    after_id: int = 0,
    limit: int = 100,
    period_date: dt.date | None = None,
) -> dict[str, Any]:
    """连续审计游标：严格 id 升序，返回本机构在 after_id 之后的审计行。"""
    limit = max(1, min(limit, 1000))
    if period_date is None:
        cur.execute(
            f"""
            SELECT {', '.join(_AUDIT_COLUMNS)}
            FROM audit_log
            WHERE organization_id = %s AND id > %s
            ORDER BY id ASC
            LIMIT %s
            """,
            (organization_id, after_id, limit),
        )
    else:
        cur.execute(
            f"""
            SELECT {', '.join(_AUDIT_COLUMNS)}
            FROM audit_log
            WHERE organization_id = %s AND id > %s AND period_date = %s
            ORDER BY id ASC
            LIMIT %s
            """,
            (organization_id, after_id, period_date, limit),
        )
    keys = _AUDIT_COLUMNS
    entries = [
        _project(_serialize(dict(zip(keys, r))), fields) for r in cur.fetchall()
    ]
    next_cursor = entries[-1]["id"] if entries else after_id
    return {
        "organization_id": organization_id,
        "after_id": after_id,
        "next_cursor": next_cursor,
        "has_more": len(entries) == limit,
        "entries": entries,
    }


def ledger_reconciliation(cur, organization_id: str, period_date: dt.date,
                          fields: list[str] | None = None) -> dict[str, Any]:
    """对账：账面消费逐笔列出，并核对与 quota_periods.consumed 完全一致。

    逐笔明细按调用方字段白名单裁剪（与审计游标一致）；聚合计数不裁剪。
    """
    recon_columns = ["id", "key_id", "idempotency_key", "nonce", "resource_scope",
                     "units", "request_timestamp", "created_at"]
    if fields is None or "*" in fields:
        visible = recon_columns
    else:
        allowed = set(fields)
        visible = [c for c in recon_columns if c in allowed]
    cur.execute(
        """
        SELECT id, key_id, idempotency_key, nonce, resource_scope, units,
               request_timestamp, created_at
        FROM consumption_events
        WHERE organization_id = %s AND period_date = %s
        ORDER BY id ASC
        """,
        (organization_id, period_date),
    )
    keys = ["id", "key_id", "idempotency_key", "nonce", "resource_scope",
            "units", "request_timestamp", "created_at"]
    events = [
        _project(_serialize(dict(zip(keys, r))), visible) for r in cur.fetchall()
    ]
    # 聚合总额独立取自数据库，不受字段裁剪影响
    cur.execute(
        "SELECT COUNT(*), COALESCE(SUM(units),0) FROM consumption_events "
        "WHERE organization_id = %s AND period_date = %s",
        (organization_id, period_date),
    )
    event_count, event_units = cur.fetchone()
    cur.execute(
        "SELECT consumed FROM quota_periods "
        "WHERE organization_id = %s AND period_date = %s",
        (organization_id, period_date),
    )
    row = cur.fetchone()
    consumed = row[0] if row else 0
    return {
        "organization_id": organization_id,
        "period_date": _date(period_date),
        "event_count": len(events),
        "event_units_total": event_units,
        "ledger_consumed": consumed,
        "matches": event_units == consumed,
        "events": events,
    }
