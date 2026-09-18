"""命令行调试/冒烟客户端与签名辅助（非服务运行依赖）。

用法：
  python -m src.client settle --key demo-key-a --secret demo-secret-a \\
      --scope correction/basic --units 5
  python -m src.client quota   --key demo-key-a --secret demo-secret-a
  python -m src.client audit   --key demo-key-b --secret demo-secret-b --cursor 0
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlencode


def _canonical_query(query: str) -> str:
    from urllib.parse import parse_qsl

    pairs = parse_qsl(query, keep_blank_values=True)
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def sign_query(secret: str, method: str, path: str, query: str = "") -> str:
    message = f"{method}\n{path}\n{_canonical_query(query)}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def build_settle_request(key_id: str, secret: str, scope: str, units: int,
                         *, idempotency_key: str, nonce: str,
                         timestamp: str | None = None) -> tuple[dict, dict]:
    from .signing import sign_request

    payload = {
        "idempotency_key": idempotency_key,
        "key_id": key_id,
        "timestamp": timestamp
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": nonce,
        "resource_scope": scope,
        "units": units,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Key-Id": key_id,
        "X-Signature": sign_request(secret, payload),
    }
    return payload, headers


def request(base_url: str, method: str, path: str, *, secret: str | None = None,
            key_id: str | None = None, body: dict | None = None,
            query: dict[str, str] | None = None) -> tuple[int, dict]:
    query_str = urlencode(query or {})
    url = f"{base_url}{path}" + (f"?{query_str}" if query_str else "")
    headers: dict[str, str] = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if key_id is not None:
        headers["X-Key-Id"] = key_id
    if secret is not None:
        if method == "POST" and body is not None:
            from .signing import sign_request

            headers["X-Signature"] = sign_request(secret, body)
        else:
            headers["X-Signature"] = sign_query(secret, method, path, query_str)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_settle = sub.add_parser("settle")
    p_settle.add_argument("--key", required=True)
    p_settle.add_argument("--secret", required=True)
    p_settle.add_argument("--scope", required=True)
    p_settle.add_argument("--units", type=int, required=True)
    p_settle.add_argument("--idempotency-key", default=None)
    p_settle.add_argument("--nonce", default=None)

    for name in ("quota", "rejections", "reconciliation"):
        pq = sub.add_parser(name)
        pq.add_argument("--key", required=True)
        pq.add_argument("--secret", required=True)
        pq.add_argument("--date", default=None)

    pa = sub.add_parser("audit")
    pa.add_argument("--key", required=True)
    pa.add_argument("--secret", required=True)
    pa.add_argument("--cursor", default="0")
    pa.add_argument("--limit", default="100")
    pa.add_argument("--date", default=None)

    args = parser.parse_args(argv)
    if args.cmd == "settle":
        import uuid

        payload, _ = build_settle_request(
            args.key, args.secret, args.scope, args.units,
            idempotency_key=args.idempotency_key or f"cli-{uuid.uuid4().hex[:12]}",
            nonce=args.nonce or uuid.uuid4().hex,
        )
        status, body = request(args.base_url, "POST", "/v1/settle",
                               secret=args.secret, key_id=args.key, body=payload)
    else:
        query = {}
        if getattr(args, "date", None):
            query["date"] = args.date
        if args.cmd == "audit":
            query["cursor"] = args.cursor
            query["limit"] = args.limit
        status, body = request(
            args.base_url, "GET", f"/v1/{args.cmd}",
            secret=args.secret, key_id=args.key, query=query,
        )
    print(status)
    print(json.dumps(body, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
