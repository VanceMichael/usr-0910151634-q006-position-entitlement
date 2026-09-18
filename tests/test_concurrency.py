"""并发竞争测试：多线程同时触及额度边界，验证绝不超扣。

每个线程独立连接、独立 idempotency_key/nonce，同时发起请求。
验收：
  - 获批总量 == quota_periods.consumed，且 <= quota
  - 每个获批事件 id 唯一；逐笔 units 之和逐笔对应
  - 额度边界处恰好 floor(quota/units_per_req) 个请求获批
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.db import cursor
from tests.dbcase import PostgresCase


class QuotaBoundaryRaceTest(PostgresCase):
    daily_quota = 100
    clock_skew = 300
    max_units = 1_000_000

    def _race(self, n_threads: int, units_each: int) -> list[tuple[int, dict]]:
        barrier = threading.Barrier(n_threads)
        results: list[tuple[int, dict]] = []
        lock = threading.Lock()

        def worker():
            payload, sig, _ = self.payload(units=units_each)
            conn = self.new_conn()
            barrier.wait()  # 尽量同时发起，逼出边界竞争
            try:
                out = self.settle(payload, sig, conn=conn)
                with lock:
                    results.append((out.http_status, out.body))
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            futures = [pool.submit(worker) for _ in range(n_threads)]
            for f in as_completed(futures):
                f.result()
        return results

    def test_concurrent_requests_never_overdraw(self):
        n_threads, units_each = 40, 6
        # 100 / 6 = 16 个可获批，共 96；其余 24 个必须 429
        results = self._race(n_threads, units_each)

        approved = [b for s, b in results if s == 200]
        rejected = [b for s, b in results if s == 429]
        self.assertEqual(len(approved), 16)
        self.assertEqual(len(rejected), 24)

        approved_units = sum(b["units"] for b in approved)
        self.assertEqual(approved_units, 96)

        # 每个获批响应指向唯一台账事件
        event_ids = [b["consumption_event_id"] for b in approved]
        self.assertEqual(len(event_ids), len(set(event_ids)))

        # 剩余额度序列严格为 100 - 6k（k=1..16），不出现负值
        remainings = sorted(b["remaining"] for b in approved)
        self.assertEqual(remainings, [100 - 6 * i for i in range(16, 0, -1)])
        self.assertGreaterEqual(min(remainings), 0)

        # 数据库账面与获批响应一致
        with cursor(self.admin) as cur:
            cur.execute(
                "SELECT consumed FROM quota_periods WHERE organization_id=%s",
                (self.org_id,),
            )
            ledger_consumed = cur.fetchone()[0]
            cur.execute(
                "SELECT COUNT(*), COALESCE(SUM(units),0) "
                "FROM consumption_events WHERE organization_id=%s",
                (self.org_id,),
            )
            event_count, event_sum = cur.fetchone()
        self.assertEqual(ledger_consumed, 96)
        self.assertEqual(event_count, 16)
        self.assertEqual(event_sum, 96)
        self.assertLessEqual(ledger_consumed, self.daily_quota)

    def test_concurrent_exact_boundary(self):
        # 20 个线程各要 10，额度正好 100，必须恰好 10 个成功
        results = self._race(20, 10)
        approved = [s for s, _ in results if s == 200]
        self.assertEqual(len(approved), 10)
        with cursor(self.admin) as cur:
            cur.execute(
                "SELECT consumed FROM quota_periods WHERE organization_id=%s",
                (self.org_id,),
            )
            self.assertEqual(cur.fetchone()[0], 100)

    def test_concurrent_same_idempotency_key_single_charge(self):
        """并发的同一幂等请求只能有一笔获批消费。"""
        n = 12
        base_payload, base_sig, _ = self.payload(units=5)
        barrier = threading.Barrier(n)
        statuses: list[int] = []
        lock = threading.Lock()

        def worker():
            # 同一请求体（含同一 idempotency_key 与 nonce）并发重放
            conn = self.new_conn()
            barrier.wait()
            try:
                out = self.settle(dict(base_payload), base_sig, conn=conn)
                with lock:
                    statuses.append(out.http_status)
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=n) as pool:
            futures = [pool.submit(worker) for _ in range(n)]
            for f in as_completed(futures):
                f.result()

        # 占用与终态化在同一事务内提交，因此其余并发请求要么插入冲突阻塞、
        # 要么读到终态并交付初次结果（200），但绝不二次扣费。
        self.assertTrue(all(s in (200, 409) for s in statuses), statuses)
        self.assertIn(200, statuses)
        with cursor(self.admin) as cur:
            cur.execute(
                "SELECT COUNT(*), COALESCE(SUM(units),0) FROM consumption_events "
                "WHERE organization_id=%s AND idempotency_key=%s",
                (self.org_id, base_payload["idempotency_key"]),
            )
            count, total = cur.fetchone()
        self.assertEqual((count, total), (1, 5))
