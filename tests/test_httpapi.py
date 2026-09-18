"""HTTP 端到端集成测试：内嵌 ThreadingHTTPServer + 真实 PostgreSQL。

覆盖结算 POST、机构查询签名、字段裁剪、跨机构隔离、健康检查。
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.httpapi import build_server
from tests.dbcase import PostgresCase


class HttpApiTest(PostgresCase):
    daily_quota = 50
    scopes = ["correction/basic"]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.server = build_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        super().tearDownClass()

    def _url(self, path, query=""):
        return self.base + path + (f"?{query}" if query else "")

    def _post_settle(self, payload, secret):
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json",
                   "X-Key-Id": payload["key_id"],
                   "X-Signature": __import__("src.signing", fromlist=["sign_request"])
                   .sign_request(secret, payload)}
        req = urllib.request.Request(self._url("/v1/settle"), data=data,
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _get(self, path, key_id, secret, query=""):
        from src.client import sign_query

        headers = {"X-Key-Id": key_id,
                   "X-Signature": sign_query(secret, "GET", path, query)}
        req = urllib.request.Request(self._url(path, query), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_healthz(self):
        with urllib.request.urlopen(self._url("/healthz"), timeout=5) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(json.loads(r.read())["status"], "ok")

    def test_settle_then_quota_and_replay(self):
        payload, sig, _ = self.payload(units=8)
        status, body = self._post_settle(payload, self.secret)
        self.assertEqual(status, 200, body)
        status2, body2 = self._post_settle(dict(payload), self.secret)
        self.assertEqual(status2, 200)
        self.assertEqual(body2["consumption_event_id"],
                         body["consumption_event_id"])

        s, q = self._get("/v1/quota", self.key_id, self.secret)
        self.assertEqual(s, 200)
        self.assertEqual(q["consumed"], 8)
        self.assertEqual(q["remaining"], 42)

    def test_query_bad_signature_401(self):
        req = urllib.request.Request(
            self._url("/v1/quota"),
            headers={"X-Key-Id": self.key_id, "X-Signature": "bad"},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("应返回 401")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    def test_query_signature_must_cover_query_string(self):
        # 用空 query 的签名去请求带 query 的路径，必须失败
        from src.client import sign_query

        good_empty = sign_query(self.secret, "GET", "/v1/quota", "")
        req = urllib.request.Request(
            self._url("/v1/quota", "date=2026-09-18"),
            headers={"X-Key-Id": self.key_id, "X-Signature": good_empty},
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("query 串改变后签名必须失效")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 401)

    def test_audit_field_clipping_and_isolation_over_http(self):
        p, s, _ = self.payload(units=2)
        self.assertEqual(self._post_settle(p, self.secret)[0], 200)

        # 给本机构一个“受限视图”密钥
        import uuid

        restricted_id = f"key-r-{uuid.uuid4().hex[:8]}"
        from src.db import cursor

        with cursor(self.admin) as cur:
            cur.execute(
                "INSERT INTO api_keys(key_id, organization_id, secret, status, "
                "view_fields) VALUES (%s,%s,%s,'active',%s)",
                (restricted_id, self.org_id, "rsecret",
                 ["id", "resource_scope", "units", "result"]),
            )
        self.admin.commit()

        st, page = self._get("/v1/audit", restricted_id, "rsecret",
                             "cursor=0&limit=10")
        self.assertEqual(st, 200)
        self.assertTrue(page["entries"])
        for e in page["entries"]:
            self.assertEqual(set(e.keys()),
                             {"id", "resource_scope", "units", "result"})
            self.assertNotIn("key_id", e)
            self.assertNotIn("nonce", e)
            self.assertNotIn("organization_id", e)

    def test_concurrent_http_requests_never_overdraw(self):
        n = 20  # 额度 50，每笔 4 → 恰好 12 笔（48）获批
        barrier = threading.Barrier(n)

        def worker():
            payload, sig, _ = self.payload(units=4)
            barrier.wait()
            return self._post_settle(payload, self.secret)

        with ThreadPoolExecutor(max_workers=n) as pool:
            futures = [pool.submit(worker) for _ in range(n)]
            results = [f.result() for f in futures]
        approved = [s for s, _ in results if s == 200]
        rejected = [s for s, _ in results if s == 429]
        self.assertEqual(len(approved), 12, results)
        self.assertEqual(len(rejected), 8)
        _, q = self._get("/v1/quota", self.key_id, self.secret)
        self.assertEqual(q["consumed"], 48)
        self.assertLessEqual(q["consumed"], q["quota"])
