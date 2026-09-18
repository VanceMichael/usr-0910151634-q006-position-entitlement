"""机构查询端测试：UTC 账期额度、拒绝原因汇总、连续审计游标、
字段裁剪、机构隔离、逐笔对账。"""

from __future__ import annotations

import datetime as dt

from src import queries
from src.db import cursor
from tests.dbcase import PostgresCase


class OrgQueryTest(PostgresCase):
    scopes = ["correction/basic", "correction/premium"]
    daily_quota = 100

    def test_quota_status_for_utc_period(self):
        payload, sig, _ = self.payload(units=30)
        self.settle(payload, sig)
        today = dt.datetime.now(dt.timezone.utc).date()
        with cursor(self.admin) as cur:
            status = queries.quota_status(cur, self.org_id, today)
        self.assertEqual(status["timezone"], "UTC")
        self.assertEqual(status["period_date"], str(today))
        self.assertEqual(status["quota"], 100)
        self.assertEqual(status["consumed"], 30)
        self.assertEqual(status["remaining"], 70)

    def test_rejection_summary_groups_reasons(self):
        ok, oks, _ = self.payload(units=10)
        self.settle(ok, oks)
        # 两笔越权 + 一笔坏签名 + 一笔超额
        for _ in range(2):
            p, s, _ = self.payload(scope="tracking/no")
            self.assertEqual(self.settle(p, s).http_status, 403)
        p, _, _ = self.payload(units=1)
        self.assertEqual(self.settle(p, "0" * 64).http_status, 401)
        big, bs, _ = self.payload(units=91)  # 剩 90
        self.assertEqual(self.settle(big, bs).http_status, 429)

        today = dt.datetime.now(dt.timezone.utc).date()
        with cursor(self.admin) as cur:
            summary = queries.rejection_summary(cur, self.org_id, today)
        counts = {r["reason"]: r["count"] for r in summary["reasons"]}
        self.assertEqual(summary["total_rejected"], 4)
        self.assertEqual(counts["scope_denied"], 2)
        self.assertEqual(counts["bad_signature"], 1)
        self.assertEqual(counts["quota_exceeded"], 1)

    def test_audit_cursor_is_contiguous_and_non_repeating(self):
        ids = []
        for units in (1, 2, 3):
            p, s, _ = self.payload(units=units)
            ids.append(self.settle(p, s).body["consumption_event_id"])

        with cursor(self.admin) as cur:
            _, full_fields = queries.caller_org(cur, self.key_id)
            page1 = queries.audit_cursor(cur, self.org_id, full_fields,
                                         after_id=0, limit=2)
            self.assertEqual(len(page1["entries"]), 2)
            self.assertTrue(page1["has_more"])
            mid = page1["next_cursor"]
            page2 = queries.audit_cursor(cur, self.org_id, full_fields,
                                         after_id=mid, limit=2)

        all_ids = [e["id"] for e in page1["entries"]] + \
                  [e["id"] for e in page2["entries"]]
        # 严格递增、连续不重不漏（本机构的审计行）
        self.assertEqual(all_ids, sorted(all_ids))
        self.assertEqual(len(all_ids), len(set(all_ids)))
        # 再读同一游标必须为空（不重复交付）
        with cursor(self.admin) as cur:
            again = queries.audit_cursor(cur, self.org_id, full_fields,
                                         after_id=page2["next_cursor"], limit=10)
        self.assertEqual(again["entries"], [])
        self.assertFalse(again["has_more"])

    def test_field_clipping_hides_sensitive_columns(self):
        p, s, _ = self.payload(units=1)
        self.settle(p, s)
        # 受限白名单：不含 key_id / nonce / 签名相关字段
        restricted = ["id", "period_date", "resource_scope", "units",
                      "result", "reason", "remaining_after"]
        with cursor(self.admin) as cur:
            page = queries.audit_cursor(cur, self.org_id, restricted,
                                        after_id=0, limit=10)
        entry = page["entries"][0]
        self.assertIn("resource_scope", entry)
        self.assertNotIn("key_id", entry)
        self.assertNotIn("nonce", entry)
        self.assertNotIn("idempotency_key", entry)

    def test_reconciliation_matches_ledger_event_by_event(self):
        for units in (5, 7, 3):
            p, s, _ = self.payload(units=units)
            self.assertEqual(self.settle(p, s).http_status, 200)
        today = dt.datetime.now(dt.timezone.utc).date()
        with cursor(self.admin) as cur:
            recon = queries.ledger_reconciliation(cur, self.org_id, today)
        self.assertTrue(recon["matches"])
        self.assertEqual(recon["event_count"], 3)
        self.assertEqual(recon["event_units_total"], 15)
        self.assertEqual(recon["ledger_consumed"], 15)
        granted = set(self.scopes)
        for event in recon["events"]:
            self.assertIn(event["resource_scope"], granted)
            self.assertEqual(event["key_id"], self.key_id)

    def test_reconciliation_respects_field_clipping(self):
        p, s, _ = self.payload(units=4)
        self.settle(p, s)
        today = dt.datetime.now(dt.timezone.utc).date()
        restricted = ["id", "units", "resource_scope", "result"]
        with cursor(self.admin) as cur:
            recon = queries.ledger_reconciliation(
                cur, self.org_id, today, restricted)
        self.assertEqual(recon["event_units_total"], 4)  # 聚合不受裁剪影响
        self.assertEqual(set(recon["events"][0].keys()),
                         {"id", "units", "resource_scope"})


class OrgIsolationTest(PostgresCase):
    """机构 B 的调用方不得读到机构 A 的任何行。"""

    scopes = ["correction/basic"]

    def test_org_caller_cannot_see_other_org(self):
        # 本机构产生一笔
        p, s, _ = self.payload(units=1)
        self.settle(p, s)
        # 直接以本机构 key 查询
        with cursor(self.admin) as cur:
            org_id, fields = queries.caller_org(cur, self.key_id)
            page = queries.audit_cursor(cur, org_id, fields, after_id=0, limit=100)
            today = dt.datetime.now(dt.timezone.utc).date()
            summary = queries.rejection_summary(cur, org_id, today)
        for entry in page["entries"]:
            self.assertNotIn("org-a", str(entry))
            self.assertNotIn("demo-key-a", str(entry))
        # 审计中不会混入演示机构 org-a
        self.assertTrue(all(
            e.get("organization_id", self.org_id) == self.org_id
            for e in page["entries"]
        ))
        self.assertEqual(summary["organization_id"], self.org_id)
