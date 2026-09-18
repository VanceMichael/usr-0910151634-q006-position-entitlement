"""纯后端 HTTP 服务（标准库 http.server，零额外 Web 框架依赖）。

路由：
  POST /v1/settle              取数结算
  GET  /v1/quota?date=         UTC 账期剩余额度
  GET  /v1/rejections?date=    UTC 账期拒绝原因汇总
  GET  /v1/audit?cursor=&limit=&date=   连续审计游标
  GET  /v1/reconciliation?date=         账面逐笔对账
  GET  /healthz                健康检查

机构查询用 X-Key-Id + X-Signature 鉴权；签名串为
``METHOD\nPATH\ncanonical_query``（query 按 key 排序，无 query 时第三行为空）。
"""

from __future__ import annotations

import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from . import queries
from .db import connect, cursor
from .settlement import settle
from .signing import verify as hmac_verify


def _canonical_query(query: str) -> str:
    pairs = parse_qsl(query, keep_blank_values=True)
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def _parse_date(value: str | None) -> dt.date:
    if not value:
        return dt.datetime.now(dt.timezone.utc).date()
    return dt.date.fromisoformat(value)


class Handler(BaseHTTPRequestHandler):
    server_version = "EntitlementLedger/1.0"

    def log_message(self, fmt, *args):  # 安静日志，容器内仍可按需打开
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send_json(self, status: int, body: dict | list) -> None:
        data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # -- GET ----------------------------------------------------------------
    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path, query = parts.path, parts.query
        if path == "/healthz":
            self._healthz()
            return
        if path in ("/v1/quota", "/v1/rejections", "/v1/audit",
                    "/v1/reconciliation"):
            self._org_query(path, query)
            return
        self._send_json(404, {"error": "not_found"})

    def _healthz(self) -> None:
        try:
            conn = connect()
            try:
                with cursor(conn) as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            finally:
                conn.close()
            self._send_json(200, {"status": "ok"})
        except Exception as exc:  # noqa: BLE001
            self._send_json(503, {"status": "unhealthy", "detail": str(exc)})

    def _org_query(self, path: str, query: str) -> None:
        key_id = self.headers.get("X-Key-Id")
        signature = self.headers.get("X-Signature")
        params = dict(parse_qsl(query))
        try:
            period_date = _parse_date(params.get("date"))
        except ValueError:
            self._send_json(400, {"error": "bad_date", "detail": "use YYYY-MM-DD"})
            return

        conn = connect()
        try:
            with cursor(conn) as cur:
                try:
                    org_id, fields = queries.caller_org(cur, key_id or "")
                except queries.AuthorizationError as exc:
                    self._send_json(401, {"error": str(exc)})
                    return
                cur.execute(
                    "SELECT secret FROM api_keys WHERE key_id = %s", (key_id,)
                )
                secret = cur.fetchone()[0]
                if not signature or not hmac_verify(
                    secret.encode("utf-8"),
                    f"GET\n{path}\n{_canonical_query(query)}".encode("utf-8"),
                    signature,
                ):
                    self._send_json(401, {"error": "bad_signature"})
                    return

                if path == "/v1/quota":
                    self._send_json(200, queries.quota_status(cur, org_id, period_date))
                elif path == "/v1/rejections":
                    self._send_json(
                        200, queries.rejection_summary(cur, org_id, period_date)
                    )
                elif path == "/v1/reconciliation":
                    self._send_json(
                        200, queries.ledger_reconciliation(
                            cur, org_id, period_date, fields)
                    )
                else:
                    try:
                        after_id = int(params.get("cursor", "0"))
                        limit = int(params.get("limit", "100"))
                    except ValueError:
                        self._send_json(400, {"error": "bad_cursor_or_limit"})
                        return
                    filter_date = period_date if params.get("date") else None
                    self._send_json(
                        200,
                        queries.audit_cursor(
                            cur, org_id, fields,
                            after_id=after_id, limit=limit,
                            period_date=filter_date,
                        ),
                    )
        finally:
            conn.close()

    # -- POST ---------------------------------------------------------------
    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        if parts.path != "/v1/settle":
            self._send_json(404, {"error": "not_found"})
            return
        key_id = self.headers.get("X-Key-Id")
        signature = self.headers.get("X-Signature")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"status": "rejected", "reason": "invalid_payload",
                                  "detail": "body must be UTF-8 JSON"})
            return
        if isinstance(payload, dict) and key_id and "key_id" not in payload:
            payload["key_id"] = key_id

        conn = connect()
        try:
            outcome = settle(conn, payload, signature)
            self._send_json(outcome.http_status, outcome.body)
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"error": "internal_error", "detail": str(exc)})
        finally:
            conn.close()


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    # 默认积压只有 5，并发请求突刺时会被内核拒连；放大以容纳竞争
    request_queue_size = 256


def build_server(host: str = "0.0.0.0", port: int = 8000, *, verbose: bool = False):
    server = _Server((host, port), Handler)
    server.verbose = verbose  # type: ignore[attr-defined]
    return server


def serve(host: str = "0.0.0.0", port: int = 8000, *, verbose: bool = False) -> None:
    server = build_server(host, port, verbose=verbose)
    threading.current_thread().name = "http-main"
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
