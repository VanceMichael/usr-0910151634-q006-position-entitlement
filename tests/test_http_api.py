"""HTTP 层测试：签名头、机构范围裁剪、运营端点、轮换、幂等响应头。"""

import json
import unittest
import urllib.error

from src.db import connect

from tests._support import (
    HttpServerThread,
    database_url,
    fresh_database,
    http_request,
    make_payload,
    signed_headers,
)


class HttpApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os

        os.environ["DATABASE_URL"] = database_url()
        os.environ["OPERATOR_TOKEN"] = "test-operator-token"
        cls.server = HttpServerThread()
        cls.server.start()
        cls.server.wait_ready()
        cls.base = cls.server.base_url

    def setUp(self):
        fresh_database().close()

    def _post_settlement(self, payload, key_id="demo-key-a", secret=b"local-demo-secret-alpha",
                         extra_headers=None):
        headers = signed_headers(payload, key_id, secret)
        if extra_headers:
            headers.update(extra_headers)
        return http_request(f"{self.base}/v1/settlement", method="POST", headers=headers, body=payload)

    def test_healthz(self):
        status, _, body = http_request(f"{self.base}/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_settlement_end_to_end_and_idempotent_header(self):
        payload = make_payload(units=8, idem="idem-http-1")
        status, headers, body = self._post_settlement(payload)
        self.assertEqual(status, 201)
        self.assertEqual(body["remaining"], 92)
        self.assertEqual(headers.get("X-Idempotent-Replay"), "false")

        status2, headers2, body2 = self._post_settlement(payload)
        self.assertEqual(status2, 201)
        self.assertEqual(body2, body)
        self.assertEqual(headers2.get("X-Idempotent-Replay"), "true")

    def test_missing_signature_header(self):
        payload = make_payload()
        status, _, body = self._post_settlement(payload, extra_headers={"X-Signature": ""})
        self.assertEqual(status, 401)
        self.assertEqual(body["reject_reason"], "SIGNATURE_INVALID")

    def test_validation_errors(self):
        status, _, body = http_request(
            f"{self.base}/v1/settlement", method="POST",
            headers={"Content-Type": "application/json"}, body={"key_id": "x"})
        self.assertEqual(status, 400)
        self.assertIn("fields", body)

    def test_org_quota_and_rejections_scoped(self):
        self._post_settlement(make_payload(units=10))
        self._post_settlement(make_payload(scope="forbidden/scope"))

        status, _, quota = http_request(
            f"{self.base}/v1/orgs/org-alpha/quota", headers={"X-Key-Id": "demo-key-a"})
        self.assertEqual(status, 200)
        self.assertEqual(quota["consumed"], 10)
        self.assertEqual(quota["remaining"], 90)

        status, _, rej = http_request(
            f"{self.base}/v1/orgs/org-alpha/rejections", headers={"X-Key-Id": "demo-key-a"})
        self.assertEqual(status, 200)
        self.assertEqual(rej["total"], 1)

    def test_org_cannot_read_other_org(self):
        # alpha 的 key 试图读 beta：403。
        status, _, body = http_request(
            f"{self.base}/v1/orgs/org-beta/quota", headers={"X-Key-Id": "demo-key-a"})
        self.assertEqual(status, 403)
        # 无凭证：401。
        status, _, body = http_request(f"{self.base}/v1/orgs/org-alpha/quota")
        self.assertEqual(status, 401)

    def test_org_audit_is_trimmed_and_scoped(self):
        self._post_settlement(make_payload(units=3))
        self._post_settlement(make_payload(scope="no/such-scope"))
        status, _, page = http_request(
            f"{self.base}/v1/orgs/org-alpha/audit?limit=10",
            headers={"X-Key-Id": "demo-key-a"})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(page["entries"]), 2)
        for entry in page["entries"]:
            self.assertEqual(entry["organization_id"], "org-alpha")
            self.assertNotIn("debug_info", entry)
            self.assertNotIn("signature_valid", entry)
        self.assertIn("next_cursor", page)

    def test_operator_audit_requires_token_and_sees_all_fields(self):
        status, _, _ = http_request(f"{self.base}/v1/audit")
        self.assertEqual(status, 401)
        self._post_settlement(make_payload(units=2))
        headers = {"Authorization": "Bearer test-operator-token"}
        status, _, page = http_request(f"{self.base}/v1/audit?limit=10", headers=headers)
        self.assertEqual(status, 200)
        self.assertTrue(any("debug_info" in e for e in page["entries"]))

    def test_rotate_then_old_key_fails_and_history_preserved(self):
        payload = make_payload(units=4, idem="idem-http-rotate")
        self.assertEqual(self._post_settlement(payload)[0], 201)

        headers = {"Authorization": "Bearer test-operator-token",
                   "Content-Type": "application/json"}
        status, _, body = http_request(
            f"{self.base}/v1/admin/rotate", method="POST", headers=headers,
            body={"old_key_id": "demo-key-a", "new_key_id": "demo-key-a3",
                  "new_secret": "rotated-secret-3"})
        self.assertEqual(status, 200)

        status, _, body = self._post_settlement(make_payload())
        self.assertEqual(status, 401)
        self.assertEqual(body["reject_reason"], "KEY_INACTIVE")

        status, _, body = self._post_settlement(
            make_payload(key_id="demo-key-a3"), key_id="demo-key-a3",
            secret=b"rotated-secret-3")
        self.assertEqual(status, 201)

        # 旧记录仍按旧 key_id 可审计。
        with connect(database_url()) as conn, conn.cursor() as cur:
            cur.execute("SELECT key_id FROM consumption_events WHERE idempotency_key='idem-http-rotate'")
            self.assertEqual(cur.fetchone()["key_id"], "demo-key-a")


if __name__ == "__main__":
    unittest.main()
