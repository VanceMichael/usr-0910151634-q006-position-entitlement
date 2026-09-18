"""HTTP 服务（标准库 http.server，无第三方 Web 框架依赖）。

路由：
  GET  /healthz
  POST /v1/settlement                      取数结算（HMAC 头 X-Signature）
  GET  /v1/orgs/{org}/quota                UTC 账期剩余额度
  GET  /v1/orgs/{org}/rejections           当日拒绝原因汇总
  GET  /v1/orgs/{org}/audit?cursor=&limit= 连续审计游标（按调用方裁剪）
  GET  /v1/orgs/{org}/reconciliation       账面逐笔核对
  GET  /v1/audit?cursor=&limit=            运营方全量审计（Bearer OPERATOR_TOKEN）
  POST /v1/admin/rotate                    运营方密钥轮换

机构查询通过 X-Key-Id 识别调用方，只能访问自己机构，且排障字段被裁剪。
"""

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import settlement
from .db import connect, run_migrations, wait_for_database
from .settlement import REQUIRED_FIELDS, settle

SETTLEMENT_PATH = "/v1/settlement"


class _JSONMixin:
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Handler(BaseHTTPRequestHandler, _JSONMixin):
    server_version = "EntitlementLedger/1.0"

    def log_message(self, fmt, *args):  # 静默默认访问日志，保留结构化错误即可
        return

    # -- 鉴权辅助 ----------------------------------------------------------

    def _caller_org(self) -> str | None:
        key_id = self.headers.get("X-Key-Id")
        if not key_id:
            return None
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT organization_id FROM api_keys WHERE key_id = %s AND status = 'active'",
                (key_id,),
            )
            row = cur.fetchone()
        return row["organization_id"] if row else None

    def _is_operator(self) -> bool:
        token = os.environ.get("OPERATOR_TOKEN", "operator-local-token")
        expected = f"Bearer {token}"
        return self.headers.get("Authorization", "") == expected

    def _org_scope(self, org_in_path: str) -> str | None:
        """返回获准访问的机构 id；越权 / 无凭证返回 None（调用方回 401/403）。"""
        caller = self._caller_org()
        if caller is None:
            return None
        return caller if caller == org_in_path else "__forbidden__"

    # -- 路由 --------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        try:
            if path == "/healthz":
                return self._healthz()
            if path == "/v1/audit":
                return self._audit_all(query)
            prefix = "/v1/orgs/"
            if path.startswith(prefix):
                rest = path[len(prefix):].split("/")
                if len(rest) == 2:
                    org, resource = rest
                    if resource == "quota":
                        return self._org_get(org, "quota", query)
                    if resource == "rejections":
                        return self._org_get(org, "rejections", query)
                    if resource == "audit":
                        return self._org_get(org, "audit", query)
                    if resource == "reconciliation":
                        return self._org_get(org, "reconciliation", query)
            self._send_json(404, {"error": "not_found", "path": path})
        except Exception as exc:  # pragma: no cover - 兜底
            self._send_json(500, {"error": "internal", "detail": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        try:
            if path == SETTLEMENT_PATH:
                return self._settle()
            if path == "/v1/admin/rotate":
                return self._rotate()
            self._send_json(404, {"error": "not_found", "path": path})
        except Exception as exc:  # pragma: no cover - 兜底
            self._send_json(500, {"error": "internal", "detail": str(exc)})

    # -- 处理器 ------------------------------------------------------------

    def _healthz(self) -> None:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT now() AS now")
            now = cur.fetchone()["now"]
        self._send_json(200, {
            "status": "ok",
            "database": "up",
            "db_time_utc": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    def _settle(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._send_json(400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return self._send_json(400, {"error": "body_must_be_object"})
        missing = [f for f in REQUIRED_FIELDS if f not in payload]
        if missing:
            return self._send_json(400, {"error": "missing_fields", "fields": missing})
        bad_types = []
        for f in ("key_id", "timestamp", "nonce", "resource_scope", "idempotency_key"):
            if not isinstance(payload[f], str) or not payload[f]:
                bad_types.append(f)
        units = payload["units"]
        units_ok = isinstance(units, int) and not isinstance(units, bool) and units >= 1
        if not units_ok:
            bad_types.append("units")
        if bad_types:
            return self._send_json(400, {"error": "invalid_fields", "fields": bad_types})

        signature = self.headers.get("X-Signature", "")
        with connect() as conn:
            result = settle(
                conn,
                payload,
                signature=signature,
                method="POST",
                path=SETTLEMENT_PATH,
            )
        headers = {"X-Idempotent-Replay": "true" if result.replayed else "false"}
        data = json.dumps(result.body, ensure_ascii=False).encode("utf-8")
        self.send_response(result.status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _org_get(self, org: str, resource: str, query: dict) -> None:
        scoped = self._org_scope(org)
        if scoped is None:
            return self._send_json(401, {"error": "authentication_required",
                                        "detail": "valid active X-Key-Id required"})
        if scoped == "__forbidden__":
            return self._send_json(403, {"error": "scope_denied",
                                         "detail": "key may only access its own organization"})
        day = query.get("day", [None])[0]
        with connect() as conn:
            try:
                if resource == "quota":
                    return self._send_json(200, settlement.quota_view(conn, org, day))
                if resource == "rejections":
                    return self._send_json(200, settlement.rejection_summary(conn, org, day))
                if resource == "reconciliation":
                    return self._send_json(200, settlement.ledger_reconciliation(conn, org, day))
                if resource == "audit":
                    cursor = int(query.get("cursor", ["0"])[0])
                    limit = int(query.get("limit", ["100"])[0])
                    return self._send_json(200, settlement.audit_cursor(
                        conn, organization_id=org, after_id=cursor, limit=limit, caller="org"))
            except ValueError as exc:
                return self._send_json(400, {"error": "invalid_query", "detail": str(exc)})
            except KeyError:
                return self._send_json(404, {"error": "unknown_organization", "organization_id": org})

    def _audit_all(self, query: dict) -> None:
        if not self._is_operator():
            return self._send_json(401, {"error": "operator_token_required"})
        try:
            cursor = int(query.get("cursor", ["0"])[0])
            limit = int(query.get("limit", ["100"])[0])
        except ValueError:
            return self._send_json(400, {"error": "invalid_query", "detail": "cursor/limit must be integers"})
        org_filter = query.get("organization", [None])[0]
        with connect() as conn:
            page = settlement.audit_cursor(
                conn, organization_id=org_filter, after_id=cursor, limit=limit, caller="operator")
        self._send_json(200, page)

    def _rotate(self) -> None:
        if not self._is_operator():
            return self._send_json(401, {"error": "operator_token_required"})
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._send_json(400, {"error": "invalid_json"})
        for f in ("old_key_id", "new_key_id", "new_secret"):
            if not isinstance(body.get(f), str) or not body[f]:
                return self._send_json(400, {"error": "invalid_fields", "fields": [f]})
        with connect() as conn:
            try:
                result = settlement.rotate_key(
                    conn, body["old_key_id"], body["new_key_id"], body["new_secret"])
            except KeyError:
                return self._send_json(404, {"error": "unknown_key", "key_id": body["old_key_id"]})
            except ValueError as exc:
                return self._send_json(409, {"error": "key_not_rotatable", "detail": str(exc)})
        self._send_json(200, result)


def build_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    import time

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    url = os.environ.get("DATABASE_URL")
    wait_for_database(url)
    with connect(url) as conn:
        applied = run_migrations(conn)
    if applied:
        print(f"applied migrations: {', '.join(applied)}", flush=True)
    server = build_server(host, port)
    print(f"settlement service listening on {host}:{port} at {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        time.sleep(0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
