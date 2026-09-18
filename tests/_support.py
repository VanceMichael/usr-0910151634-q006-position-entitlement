"""测试公共支持：连接、清表、构造已签名请求、在随机端口启动 HTTP 服务。"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from src.db import connect, run_migrations
from src.signing import sign_request

DEFAULT_DATABASE_URL = "postgresql://ledger@/entitlements?host=/tmp&port=55432"


def database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def fresh_database():
    """迁移到最新并清空业务表（测试库专用），返回一个连接。"""
    conn = connect(database_url())
    run_migrations(conn)
    with conn.cursor() as cur:
        cur.execute(
            """
            TRUNCATE audit_log, idempotency_records, consumption_events,
                     daily_quota_usage, used_nonces, key_scopes, api_keys,
                     contracts, organizations
            RESTART IDENTITY CASCADE
            """
        )
        cur.execute(
            """
            INSERT INTO organizations (id, display_name, daily_quota) VALUES
                ('org-alpha', 'Alpha', 100), ('org-beta', 'Beta', 20)
            """
        )
        cur.execute(
            """
            INSERT INTO contracts (organization_id, allowed_clock_skew_seconds, nonce_retention_seconds)
            VALUES ('org-alpha', 300, 86400), ('org-beta', 120, 86400)
            """
        )
        cur.execute(
            """
            INSERT INTO api_keys (key_id, organization_id, shared_secret, status) VALUES
                ('demo-key-a',   'org-alpha', 'local-demo-secret-alpha',   'active'),
                ('demo-key-a-c', 'org-alpha', 'local-demo-secret-alpha-2', 'active'),
                ('demo-key-b',   'org-beta',  'local-demo-secret-beta',    'active')
            """
        )
        cur.execute(
            """
            INSERT INTO key_scopes (key_id, resource_scope) VALUES
                ('demo-key-a', 'correction/basic'),
                ('demo-key-a', 'correction/rtk'),
                ('demo-key-a', 'ephemeris/nav'),
                ('demo-key-a-c', 'correction/basic'),
                ('demo-key-a-c', 'correction/rtk'),
                ('demo-key-b', 'correction/basic')
            """
        )
    conn.commit()
    return conn


SECRETS = {
    "demo-key-a": b"local-demo-secret-alpha",
    "demo-key-a-c": b"local-demo-secret-alpha-2",
    "demo-key-b": b"local-demo-secret-beta",
}


def make_payload(
    key_id="demo-key-a",
    scope="correction/basic",
    units=5,
    idem=None,
    nonce=None,
    ts=None,
):
    ts = ts or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "key_id": key_id,
        "timestamp": ts,
        "nonce": nonce or f"nonce-{uuid.uuid4().hex[:12]}",
        "resource_scope": scope,
        "units": units,
        "idempotency_key": idem or f"idem-{uuid.uuid4().hex[:12]}",
    }


def signed_headers(payload: dict, key_id: str, secret: bytes, path: str = "/v1/settlement") -> dict:
    sig = sign_request(
        secret, "POST", path,
        payload["key_id"], payload["timestamp"], payload["nonce"],
        payload["idempotency_key"], payload,
    )
    return {"X-Signature": sig, "Content-Type": "application/json"}


def settle_direct(conn, payload, key_id="demo-key-a", secret=None, tamper=False, signature=None):
    """直接调用领域层，自动签名。"""
    from src.settlement import settle

    secret = secret or SECRETS[key_id]
    if signature is None:
        sig = sign_request(
            secret, "POST", "/v1/settlement",
            payload["key_id"], payload["timestamp"], payload["nonce"],
            payload["idempotency_key"], payload,
        )
        if tamper:
            sig = "0" * 64
    else:
        sig = signature
    return settle(conn, payload, signature=sig)


class HttpServerThread(threading.Thread):
    """在随机端口上启动 src.app，daemon 线程。"""

    def __init__(self):
        super().__init__(daemon=True)
        self.port = 0
        self.base_url = ""

    def run(self):
        from src.app import build_server

        server = build_server("127.0.0.1", 0)
        self.port = server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        server.serve_forever()

    def wait_ready(self, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.base_url:
                time.sleep(0.02)
                continue
            try:
                with urllib.request.urlopen(f"{self.base_url}/healthz", timeout=1) as r:
                    if r.status == 200:
                        return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("test http server did not become ready")


def http_request(url, *, method="GET", headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read().decode())
