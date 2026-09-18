"""领域层测试：签名/时钟偏差（合约）/防重放/权限/额度/幂等/只追加。"""

import json
import unittest
from datetime import datetime, timedelta, timezone

from src.db import connect
from src.settlement import (
    REJECT_CLOCK_SKEW,
    REJECT_KEY_INACTIVE,
    REJECT_KEY_UNKNOWN,
    REJECT_QUOTA,
    REJECT_REPLAY,
    REJECT_SCOPE_DENIED,
    REJECT_SIGNATURE_INVALID,
    REJECT_IDEMPOTENCY_MISMATCH,
    settle,
)

from tests._support import database_url, fresh_database, make_payload, settle_direct


class SettlementTest(unittest.TestCase):
    def setUp(self):
        self.conn = fresh_database()

    def tearDown(self):
        self.conn.close()

    def test_happy_path_consumes_and_returns_remaining(self):
        payload = make_payload(units=5)
        result = settle_direct(self.conn, payload)
        self.assertEqual(result.status, 201)
        self.assertTrue(result.approved)
        self.assertEqual(result.body["consumed"], 5)
        self.assertEqual(result.body["remaining"], 95)
        self.assertIn("consumption_event_id", result.body)
        self.assertIn("audit_cursor", result.body)
        self.assertFalse(result.replayed)

    def test_signature_invalid_is_rejected(self):
        payload = make_payload()
        result = settle_direct(self.conn, payload, tamper=True)
        self.assertEqual(result.status, 401)
        self.assertEqual(result.body["reject_reason"], REJECT_SIGNATURE_INVALID)

    def test_body_tamper_after_signing_is_rejected(self):
        payload = make_payload(units=5)
        result = settle_direct(self.conn, payload)
        self.assertEqual(result.status, 201)
        # 用原签名发送被篡改的 body（签名对象在 HTTP 层按真实 body 重算，
        # 这里手工构造“签名与 body 不一致”）。
        from src.signing import sign_request

        forged = dict(payload)
        forged["units"] = 50
        sig = sign_request(
            b"local-demo-secret-alpha", "POST", "/v1/settlement",
            payload["key_id"], payload["timestamp"], payload["nonce"],
            payload["idempotency_key"], payload,  # 对旧 body 签名
        )
        result = settle(self.conn, forged, signature=sig)
        self.assertEqual(result.body["reject_reason"], REJECT_SIGNATURE_INVALID)

    def test_unknown_key_audited_with_null_org(self):
        payload = make_payload(key_id="ghost-key")
        result = settle_direct(self.conn, payload, key_id="ghost-key",
                               secret=b"whatever")
        self.assertEqual(result.body["reject_reason"], REJECT_KEY_UNKNOWN)
        with self.conn.cursor() as cur:
            cur.execute("SELECT organization_id FROM audit_log WHERE key_id = 'ghost-key'")
            self.assertIsNone(cur.fetchone()["organization_id"])

    def test_clock_skew_read_from_contract(self):
        # org-alpha 合约允许 300s；超出即拒。
        old_ts = (datetime.now(timezone.utc) - timedelta(seconds=301)).isoformat().replace("+00:00", "Z")
        payload = make_payload(ts=old_ts)
        result = settle_direct(self.conn, payload)
        self.assertEqual(result.body["reject_reason"], REJECT_CLOCK_SKEW)

        # 边界内通过（299s）。
        ok_ts = (datetime.now(timezone.utc) - timedelta(seconds=299)).isoformat().replace("+00:00", "Z")
        payload2 = make_payload(ts=ok_ts)
        result2 = settle_direct(self.conn, payload2)
        self.assertEqual(result2.status, 201)

        # org-beta 合约只允许 120s，同样 299s 偏差必须被拒——证明偏差来自合约。
        payload3 = make_payload(key_id="demo-key-b", ts=ok_ts, scope="correction/basic")
        result3 = settle_direct(self.conn, payload3, key_id="demo-key-b")
        self.assertEqual(result3.body["reject_reason"], REJECT_CLOCK_SKEW)

    def test_nonce_replay_rejected_but_original_consumed_once(self):
        payload = make_payload(units=7)
        first = settle_direct(self.conn, payload)
        self.assertEqual(first.status, 201)

        # 相同 nonce、换新幂等键：典型重放。
        replay_payload = dict(payload)
        replay_payload["idempotency_key"] = "idem-replay-attempt"
        second = settle_direct(self.conn, replay_payload)
        self.assertEqual(second.body["reject_reason"], REJECT_REPLAY)

        with self.conn.cursor() as cur:
            cur.execute("SELECT consumed FROM daily_quota_usage")
            self.assertEqual(cur.fetchone()["consumed"], 7)

    def test_scope_denied(self):
        payload = make_payload(scope="satellite/raw-downlink")
        result = settle_direct(self.conn, payload)
        self.assertEqual(result.status, 403)
        self.assertEqual(result.body["reject_reason"], REJECT_SCOPE_DENIED)

    def test_quota_exact_boundary_then_rejected(self):
        # org-beta 日额度 20。
        p1 = make_payload(key_id="demo-key-b", units=15)
        self.assertEqual(settle_direct(self.conn, p1, key_id="demo-key-b").status, 201)
        p2 = make_payload(key_id="demo-key-b", units=5)
        r2 = settle_direct(self.conn, p2, key_id="demo-key-b")
        self.assertEqual(r2.status, 201)  # 恰好打满
        p3 = make_payload(key_id="demo-key-b", units=1)
        r3 = settle_direct(self.conn, p3, key_id="demo-key-b")
        self.assertEqual(r3.status, 429)
        self.assertEqual(r3.body["reject_reason"], REJECT_QUOTA)

    def test_idempotent_retry_returns_first_result(self):
        payload = make_payload(units=9, idem="idem-stable-1")
        first = settle_direct(self.conn, payload)
        self.assertEqual(first.status, 201)
        second = settle_direct(self.conn, payload)
        self.assertTrue(second.replayed)
        self.assertEqual(second.status, first.status)
        self.assertEqual(second.body, first.body)
        # 重试不产生第二笔流水。
        with self.conn.cursor() as cur:
            cur.execute("SELECT count(*) AS c FROM consumption_events WHERE idempotency_key = 'idem-stable-1'")
            self.assertEqual(cur.fetchone()["c"], 1)
            cur.execute("SELECT consumed FROM daily_quota_usage WHERE organization_id='org-alpha'")
            self.assertEqual(cur.fetchone()["consumed"], 9)

    def test_idempotency_key_reuse_with_different_body_rejected(self):
        p1 = make_payload(units=3, idem="idem-dup")
        self.assertEqual(settle_direct(self.conn, p1).status, 201)
        p2 = make_payload(units=4, idem="idem-dup")
        r = settle_direct(self.conn, p2)
        self.assertEqual(r.body["reject_reason"], REJECT_IDEMPOTENCY_MISMATCH)

    def test_rejected_first_result_is_also_replayed(self):
        # 首单因额度不足被拒并落幂等；同样的重试返回同样的 429，不重复审计判定偏差。
        p1 = make_payload(key_id="demo-key-b", units=21)
        first = settle_direct(self.conn, p1, key_id="demo-key-b")
        self.assertEqual(first.status, 429)
        second = settle_direct(self.conn, p1, key_id="demo-key-b")
        self.assertTrue(second.replayed)
        self.assertEqual(second.status, 429)
        self.assertEqual(second.body, first.body)

    def test_rotated_key_is_refused_but_history_keeps_key_id(self):
        from src.settlement import rotate_key

        payload = make_payload(units=4, idem="idem-before-rotation")
        self.assertEqual(settle_direct(self.conn, payload).status, 201)
        rotate_key(self.conn, "demo-key-a", "demo-key-a2", "new-secret")

        # 旧 key 立即不可用。
        old_payload = make_payload(key_id="demo-key-a")
        r_old = settle_direct(self.conn, old_payload, secret=b"local-demo-secret-alpha")
        self.assertEqual(r_old.body["reject_reason"], REJECT_KEY_INACTIVE)

        # 新 key 继承范围与机构。
        new_payload = make_payload(key_id="demo-key-a2")
        r_new = settle_direct(self.conn, new_payload, secret=b"new-secret")
        self.assertEqual(r_new.status, 201)

        # 历史流水里的 key_id 没有被轮换抹去。
        with self.conn.cursor() as cur:
            cur.execute("SELECT key_id FROM consumption_events WHERE idempotency_key = 'idem-before-rotation'")
            self.assertEqual(cur.fetchone()["key_id"], "demo-key-a")
            cur.execute("SELECT count(*) AS c FROM api_keys WHERE key_id = 'demo-key-a'")
            self.assertEqual(cur.fetchone()["c"], 1)

    def test_append_only_tables_reject_update_and_delete(self):
        payload = make_payload(units=2)
        settle_direct(self.conn, payload)
        with self.conn.cursor() as cur:
            for table in ("consumption_events", "idempotency_records", "audit_log"):
                with self.assertRaises(Exception) as ctx:
                    cur.execute(f"UPDATE {table} SET units = 999 WHERE units IS NOT NULL")
                self.conn.rollback()
                with self.assertRaises(Exception):
                    cur.execute(f"DELETE FROM {table}")
                self.conn.rollback()

    def test_malformed_timestamp_rejected(self):
        payload = make_payload(ts="not-a-timestamp")
        result = settle_direct(self.conn, payload)
        self.assertEqual(result.status, 400)
        self.assertEqual(result.body["reject_reason"], "TIMESTAMP_MALFORMED")

    def test_prune_expired_nonces_uses_contract_retention(self):
        # 新鲜 nonce 不被清理；超出合约保留期的旧 nonce 被清理。
        settle_direct(self.conn, make_payload(units=1))
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO used_nonces (key_id, nonce, request_timestamp) "
                "VALUES ('demo-key-a', 'ancient-nonce', now() - interval '2 days')"
            )
            self.conn.commit()
            cur.execute("SELECT prune_expired_nonces() AS removed")
            removed = cur.fetchone()["removed"]
            self.assertEqual(removed, 1)
            cur.execute("SELECT count(*) AS c FROM used_nonces WHERE nonce = 'ancient-nonce'")
            self.assertEqual(cur.fetchone()["c"], 0)
            cur.execute("SELECT count(*) AS c FROM used_nonces")
            self.assertEqual(cur.fetchone()["c"], 1)

    def test_rejections_are_audited_and_summarized(self):
        settle_direct(self.conn, make_payload(scope="nope/x"))
        settle_direct(self.conn, make_payload(scope="nope/y"))
        settle_direct(self.conn, make_payload(), tamper=True)

        from src.settlement import rejection_summary

        summary = rejection_summary(self.conn, "org-alpha")
        reasons = {r["reason"]: r["count"] for r in summary["rejections"]}
        self.assertEqual(reasons[REJECT_SCOPE_DENIED], 2)
        self.assertEqual(reasons[REJECT_SIGNATURE_INVALID], 1)
        self.assertEqual(summary["total"], 3)

    def test_audit_cursor_is_continuous_and_trimmed_for_org(self):
        from src.settlement import audit_cursor

        settle_direct(self.conn, make_payload(units=6))
        settle_direct(self.conn, make_payload(units=3))
        page1 = audit_cursor(self.conn, organization_id="org-alpha", after_id=0, limit=1, caller="org")
        self.assertEqual(len(page1["entries"]), 1)
        self.assertTrue(page1["has_more"])
        cursor = page1["next_cursor"]
        page2 = audit_cursor(self.conn, organization_id="org-alpha", after_id=cursor, limit=100, caller="org")
        self.assertGreaterEqual(len(page2["entries"]), 1)
        ids = [e["id"] for e in page1["entries"] + page2["entries"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn("debug_info", page1["entries"][0])
        self.assertNotIn("signature_valid", page1["entries"][0])

        # 运营视角包含被裁剪的排障字段。
        op = audit_cursor(self.conn, organization_id=None, after_id=0, limit=100, caller="operator")
        self.assertIn("debug_info", op["entries"][0])


if __name__ == "__main__":
    unittest.main()
