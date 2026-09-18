"""数据库连接、迁移与种子数据（PostgreSQL 16，驱动 pg8000）。"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import pg8000.dbapi

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def _database_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql://ledger:ledger@127.0.0.1:55432/entitlements",
    )


def _parse_url(database_url: str) -> dict[str, str | int]:
    parts = urlsplit(database_url)
    return {
        "user": unquote(parts.username or "postgres"),
        "password": unquote(parts.password) if parts.password is not None else None,
        "host": parts.hostname or "127.0.0.1",
        "port": parts.port or 5432,
        "database": unquote(parts.path.lstrip("/") or "postgres"),
    }


def connect(database_url: str | None = None, *, autocommit: bool = False):
    """打开一个数据库连接。"""
    conn = pg8000.dbapi.connect(
        **_parse_url(database_url or _database_url()),
        timeout=30,
    )
    conn.autocommit = autocommit
    return conn


@contextmanager
def cursor(conn):
    """pg8000 的游标未实现上下文协议，统一在此关闭。"""
    cur = conn.cursor()
    try:
        yield cur
    finally:
        cur.close()


def run_migrations(conn) -> list[str]:
    """按文件名顺序执行 migrations/ 下的 SQL，并记录到 schema_migrations。"""
    applied: list[str] = []
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    with cursor(conn) as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        for path in files:
            cur.execute("SELECT 1 FROM schema_migrations WHERE version = %s", (path.name,))
            if cur.fetchone() is not None:
                continue
            cur.execute(path.read_text(encoding="utf-8"))
            cur.execute(
                "INSERT INTO schema_migrations(version) VALUES (%s)", (path.name,)
            )
            applied.append(path.name)
    conn.commit()
    return applied


# 演示种子：两个机构、两套密钥、合同、授权范围、当日额度。
# 仅用于本地/容器演示，秘密通过环境变量可覆盖。
SECRET_A = os.environ.get("DEMO_SECRET_A", "demo-secret-a")
SECRET_B = os.environ.get("DEMO_SECRET_B", "demo-secret-b")

# 机构查询时的默认可见字段（签名与摘要不对外开放）
DEFAULT_VISIBLE: list[str] = [
    "id",
    "created_at",
    "organization_id",
    "key_id",
    "idempotency_key",
    "nonce",
    "request_timestamp",
    "period_date",
    "resource_scope",
    "units",
    "result",
    "reason",
    "consumption_event_id",
    "remaining_after",
]

# 受限调用方的字段裁剪示例
RESTRICTED_VISIBLE: list[str] = [
    "id",
    "created_at",
    "period_date",
    "resource_scope",
    "units",
    "result",
    "reason",
    "remaining_after",
]

SEED: dict[str, Any] = {
    "organizations": [
        {"id": "org-a", "name": "甲机构", "daily_quota": 1000},
        {"id": "org-b", "name": "乙机构", "daily_quota": 100},
    ],
    "contracts": [
        {"organization_id": "org-a", "clock_skew_seconds": 300,
         "max_units_per_request": 500},
        {"organization_id": "org-b", "clock_skew_seconds": 120,
         "max_units_per_request": 50},
    ],
    "api_keys": [
        {"key_id": "demo-key-a", "organization_id": "org-a",
         "secret": SECRET_A, "status": "active", "superseded_by": None,
         "view_fields": ["*"]},
        {"key_id": "demo-key-a-old", "organization_id": "org-a",
         "secret": SECRET_A + "-old", "status": "rotated",
         "superseded_by": "demo-key-a", "view_fields": ["*"]},
        {"key_id": "demo-key-b", "organization_id": "org-b",
         "secret": SECRET_B, "status": "active", "superseded_by": None,
         "view_fields": RESTRICTED_VISIBLE},
    ],
    "scope_grants": [
        {"organization_id": "org-a", "resource_scope": "correction/basic"},
        {"organization_id": "org-a", "resource_scope": "correction/premium"},
        {"organization_id": "org-b", "resource_scope": "correction/basic"},
    ],
}


def seed(conn) -> None:
    """幂等写入演示数据。"""
    with cursor(conn) as cur:
        for org in SEED["organizations"]:
            cur.execute(
                "INSERT INTO organizations(id, name, daily_quota) VALUES "
                "(%s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (org["id"], org["name"], org["daily_quota"]),
            )
        for ctr in SEED["contracts"]:
            cur.execute(
                "INSERT INTO contracts(organization_id, clock_skew_seconds, "
                "max_units_per_request) VALUES (%s, %s, %s) "
                "ON CONFLICT (organization_id) DO NOTHING",
                (ctr["organization_id"], ctr["clock_skew_seconds"],
                 ctr["max_units_per_request"]),
            )
        for key in SEED["api_keys"]:
            cur.execute(
                "INSERT INTO api_keys(key_id, organization_id, secret, status, "
                "superseded_by, view_fields) VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (key_id) DO NOTHING",
                (key["key_id"], key["organization_id"], key["secret"],
                 key["status"], key["superseded_by"], key["view_fields"]),
            )
        for grant in SEED["scope_grants"]:
            cur.execute(
                "INSERT INTO scope_grants(organization_id, resource_scope) "
                "VALUES (%s, %s) "
                "ON CONFLICT (organization_id, resource_scope) DO NOTHING",
                (grant["organization_id"], grant["resource_scope"]),
            )
    conn.commit()


def prepare(database_url: str | None = None, *, with_seed: bool = True) -> None:
    """迁移并（可选）写入种子，供容器入口与测试使用。"""
    conn = connect(database_url)
    try:
        run_migrations(conn)
        if with_seed:
            seed(conn)
    finally:
        conn.close()
