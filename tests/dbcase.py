"""PostgreSQL 集成测试公共基址。

通过 DATABASE_URL 指向真实 PostgreSQL 16；不可达时跳过。
每个用例使用独立机构（唯一 id），因此可并发执行、且在持久卷上跨重启重复运行。
"""

from __future__ import annotations

import os
import time
import unittest
import uuid
from datetime import datetime, timezone

from src.db import connect, cursor, prepare
from src.signing import sign_request


def database_url() -> str:
    return os.environ.get(
        "DATABASE_URL", "postgresql://ledger@127.0.0.1:55432/entitlements"
    )


def pg_available(url: str | None = None) -> bool:
    try:
        conn = connect(url or database_url())
    except Exception:
        return False
    try:
        with cursor(conn) as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True
    finally:
        conn.close()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class PostgresCase(unittest.TestCase):
    """每个用例一个全新机构。"""

    org_id: str
    key_id: str
    secret: str

    # 可被子类覆盖的默认值
    daily_quota = 100
    clock_skew = 300
    max_units = 1_000_000
    scopes = ["correction/basic"]

    @classmethod
    def setUpClass(cls) -> None:
        cls.url = database_url()
        if not pg_available(cls.url):
            raise unittest.SkipTest(f"PostgreSQL 不可达：{cls.url}")
        prepare(cls.url)
        cls.admin = connect(cls.url)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.admin.close()

    def setUp(self) -> None:
        suffix = uuid.uuid4().hex[:12]
        self.org_id = f"org-test-{suffix}"
        self.key_id = f"key-{suffix}"
        self.old_key_id = f"key-old-{suffix}"
        self.secret = f"secret-{suffix}"
        self.old_secret = f"old-secret-{suffix}"
        with cursor(self.admin) as cur:
            cur.execute(
                "INSERT INTO organizations(id, name, daily_quota) VALUES (%s,%s,%s)",
                (self.org_id, self.org_id, getattr(self, "daily_quota", 100)),
            )
            cur.execute(
                "INSERT INTO contracts(organization_id, clock_skew_seconds, "
                "max_units_per_request) VALUES (%s,%s,%s)",
                (self.org_id, getattr(self, "clock_skew", 300),
                 getattr(self, "max_units", 1_000_000)),
            )
            cur.execute(
                "INSERT INTO api_keys(key_id, organization_id, secret, status, "
                "view_fields) VALUES (%s,%s,%s,'active',%s)",
                (self.key_id, self.org_id, self.secret, ["*"]),
            )
            cur.execute(
                "INSERT INTO api_keys(key_id, organization_id, secret, status, "
                "superseded_by, view_fields) VALUES (%s,%s,%s,'rotated',%s,%s)",
                (self.old_key_id, self.org_id, self.old_secret,
                 self.key_id, ["*"]),
            )
            for scope in getattr(self, "scopes", ["correction/basic"]):
                cur.execute(
                    "INSERT INTO scope_grants(organization_id, resource_scope) "
                    "VALUES (%s,%s)",
                    (self.org_id, scope),
                )
        self.admin.commit()
        self.connections: list = []

    def new_conn(self):
        conn = connect(self.url)
        self.connections.append(conn)
        return conn

    def tearDown(self) -> None:
        # 只追加审计不允许删除；每个用例使用 uuid 唯一机构，数据天然隔离，
        # 不在此处清理（持久卷上跨重启仍可被游标测试读到）。
        for conn in self.connections:
            try:
                conn.close()
            except Exception:
                pass

    def payload(self, *, units: int = 1, scope: str | None = None,
                idempotency_key: str | None = None, nonce: str | None = None,
                key_id: str | None = None, secret: str | None = None,
                timestamp: str | None = None) -> tuple[dict, str, str]:
        key_id = key_id or self.key_id
        secret = secret or self.secret
        idempotency_key = idempotency_key or f"idem-{uuid.uuid4().hex[:10]}"
        nonce = nonce or f"nonce-{uuid.uuid4().hex[:10]}"
        p = {
            "idempotency_key": idempotency_key,
            "key_id": key_id,
            "timestamp": timestamp or utc_timestamp(),
            "nonce": nonce,
            "resource_scope": scope or self.scopes[0],
            "units": units,
        }
        return p, sign_request(secret, p), key_id

    def settle(self, payload, sig, *, conn=None):
        from src.settlement import settle

        own = conn is None
        conn = conn or self.new_conn()
        try:
            return settle(conn, payload, sig)
        finally:
            if own:
                conn.close()

    def rotate(self) -> None:
        """把当前 key 标记为已轮换（由 old_key 指向它的反向演示不需要）。"""
        with cursor(self.admin) as cur:
            cur.execute(
                "UPDATE api_keys SET status='rotated', deactivated_at=now(), "
                "superseded_by=%s WHERE key_id=%s",
                (self.old_key_id, self.key_id),
            )
        self.admin.commit()

    def revoke(self, key: str) -> None:
        with cursor(self.admin) as cur:
            cur.execute(
                "UPDATE api_keys SET status='revoked', deactivated_at=now() "
                "WHERE key_id=%s",
                (key,),
            )
        self.admin.commit()
