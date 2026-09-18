"""结算判定的集成测试（真实 PostgreSQL 16）。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.db import cursor
from tests.dbcase import PostgresCase


class SettlementDecisionTest(PostgresCase):
    scopes = ["correction/basic", "correction/premium"]
    daily_quota = 100
    clock_skew = 300
    max_units = 1_000_000

    def test_happy_path_approves_and_records_event(self):
        payload, sig, _ = self.payload(units=7)
        out = self.settle(payload, sig)
        self.assertEqual(out.http_status, 200, out.body)
        self.assertEqual(out.body["remaining"], 93)
        self.assertEqual(out.body["resource_scope"], payload["resource_scope"])
        event_id = out.body["consumption_event_id"]

        with cursor(self.admin) as cur:
            cur.execute(
                "SELECT key_id, units, resource_scope FROM consumption_events "
                "WHERE id = %s",
                (event_id,),
            )
            key_id, units, scope = cur.fetchone()
        self.assertEqual(key_id, self.key_id)
        self.assertEqual(units, 7)
        self.assertEqual(scope, "correction/basic")

    def test_unknown_key_is_rejected(self):
        payload, sig, _ = self.payload(key_id="does-not-exist",
                                      secret="whatever")
        out = self.settle(payload, sig)
        self.assertEqual((out.http_status, out.body["reason"]),
                         (401, "unknown_key"))

    def test_bad_signature_is_rejected(self):
        payload, _, _ = self.payload(units=1)
        out = self.settle(payload, "0" * 64)
        self.assertEqual((out.http_status, out.body["reason"]),
                         (401, "bad_signature"))
        # 签名失败不得登记 nonce、不得扣额度
        with cursor(self.admin) as cur:
            cur.execute("SELECT consumed FROM quota_periods WHERE organization_id=%s",
                        (self.org_id,))
            row = cur.fetchone()
        self.assertIsNone(row)

    def test_clock_skew_threshold_comes_from_contract(self):
        self.assertEqual(self.clock_skew, 300)
        # 超过合同允许偏差：拒绝
        stale = (datetime.now(timezone.utc) - timedelta(seconds=301)) \
            .isoformat().replace("+00:00", "Z")
        payload, sig, _ = self.payload(timestamp=stale)
        out = self.settle(payload, sig)
        self.assertEqual((out.http_status, out.body["reason"]),
                         (400, "stale_timestamp"))
        # 恰在边界内（留一点处理耗时余量）：放行
        edge = (datetime.now(timezone.utc) - timedelta(seconds=295)) \
            .isoformat().replace("+00:00", "Z")
        payload2, sig2, _ = self.payload(timestamp=edge)
        out2 = self.settle(payload2, sig2)
        self.assertEqual(out2.http_status, 200, out2.body)

    def test_future_timestamp_rejected(self):
        future = (datetime.now(timezone.utc) + timedelta(seconds=301)) \
            .isoformat().replace("+00:00", "Z")
        payload, sig, _ = self.payload(timestamp=future)
        out = self.settle(payload, sig)
        self.assertEqual(out.body["reason"], "future_timestamp")

    def test_scope_not_granted_is_rejected(self):
        payload, sig, _ = self.payload(scope="tracking/secret")
        out = self.settle(payload, sig)
        self.assertEqual((out.http_status, out.body["reason"]),
                         (403, "scope_denied"))

    def test_nonce_replay_is_rejected(self):
        payload, sig, _ = self.payload(units=3)
        self.assertEqual(self.settle(payload, sig).http_status, 200)
        # 同 nonce、不同幂等键 → nonce 重放
        payload2, sig2, _ = self.payload(nonce=payload["nonce"])
        out = self.settle(payload2, sig2)
        self.assertEqual((out.http_status, out.body["reason"]),
                         (409, "nonce_replayed"))
        with cursor(self.admin) as cur:
            cur.execute("SELECT COUNT(*) FROM consumption_events WHERE nonce=%s",
                        (payload["nonce"],))
            self.assertEqual(cur.fetchone()[0], 1)

    def test_idempotent_retry_returns_first_result_without_double_charge(self):
        payload, sig, _ = self.payload(units=4)
        first = self.settle(payload, sig)
        self.assertEqual(first.http_status, 200)
        # 完全相同的请求体重放（签名同样有效）
        second = self.settle(dict(payload), sig)
        self.assertEqual(second.http_status, 200)
        self.assertEqual(second.body["consumption_event_id"],
                         first.body["consumption_event_id"])
        self.assertEqual(second.body["remaining"], first.body["remaining"])
        with cursor(self.admin) as cur:
            cur.execute(
                "SELECT COUNT(*), COALESCE(SUM(units),0) FROM consumption_events "
                "WHERE organization_id=%s AND idempotency_key=%s",
                (self.org_id, payload["idempotency_key"]),
            )
            count, total = cur.fetchone()
        self.assertEqual((count, total), (1, 4))

    def test_same_idempotency_key_different_request_conflicts(self):
        payload, sig, _ = self.payload(units=4)
        self.assertEqual(self.settle(payload, sig).http_status, 200)
        other, osig, _ = self.payload(units=5,
                                      idempotency_key=payload["idempotency_key"])
        out = self.settle(other, osig)
        self.assertEqual((out.http_status, out.body["reason"]),
                         (409, "idempotency_conflict"))

    def test_quota_exhaustion_rejects_with_remaining(self):
        p1, s1, _ = self.payload(units=60)
        self.assertEqual(self.settle(p1, s1).http_status, 200)
        p2, s2, _ = self.payload(units=41)
        out = self.settle(p2, s2)
        self.assertEqual((out.http_status, out.body["reason"]),
                         (429, "quota_exceeded"))
        self.assertEqual(out.body.get("detail", "").endswith("remaining 40"), True)
        # 额度不足的重试返回同一结论，且不扣减
        again = self.settle(dict(p2), s2)
        self.assertEqual(again.http_status, 429)
        with cursor(self.admin) as cur:
            cur.execute("SELECT consumed FROM quota_periods WHERE organization_id=%s",
                        (self.org_id,))
            self.assertEqual(cur.fetchone()[0], 60)

    def test_rotation_keeps_historical_key_id_and_allows_replay(self):
        payload, sig, _ = self.payload(units=9)
        first = self.settle(payload, sig)
        self.assertEqual(first.http_status, 200)

        self.rotate()
        # 旧 key_id 仍逐笔保留在台账上
        with cursor(self.admin) as cur:
            cur.execute(
                "SELECT key_id FROM consumption_events WHERE id=%s",
                (first.body["consumption_event_id"],),
            )
            self.assertEqual(cur.fetchone()[0], self.key_id)

        # rotated 密钥不能发起新消费
        newp, newsig, _ = self.payload()
        out = self.settle(newp, newsig)
        self.assertEqual(out.body["reason"], "key_inactive")

        # 但对同一历史请求的幂等重试仍交付初次结果
        replay = self.settle(dict(payload), sig)
        self.assertEqual(replay.http_status, 200)
        self.assertEqual(replay.body["consumption_event_id"],
                         first.body["consumption_event_id"])

    def test_revoked_key_cannot_even_replay(self):
        payload, sig, _ = self.payload(units=2)
        first = self.settle(payload, sig)
        self.assertEqual(first.http_status, 200)
        self.revoke(self.key_id)
        out = self.settle(dict(payload), sig)
        self.assertEqual(out.body["reason"], "key_inactive")

    def test_audit_log_is_append_only(self):
        payload, sig, _ = self.payload(units=1)
        self.settle(payload, sig)
        with cursor(self.admin) as cur:
            cur.execute("SELECT id FROM audit_log WHERE organization_id=%s LIMIT 1",
                        (self.org_id,))
            audit_id = cur.fetchone()[0]
            with self.assertRaises(Exception):
                cur.execute("UPDATE audit_log SET reason='hacked' WHERE id=%s",
                            (audit_id,))
            self.admin.rollback()
            with self.assertRaises(Exception):
                cur.execute("DELETE FROM audit_log WHERE id=%s", (audit_id,))
            self.admin.rollback()
        # 数据未受影响
        with cursor(self.admin) as cur:
            cur.execute("SELECT result FROM audit_log WHERE id=%s", (audit_id,))
            self.assertEqual(cur.fetchone()[0], "approved")
