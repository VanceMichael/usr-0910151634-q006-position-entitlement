"""并发测试：多连接同时触及额度边界，验证谓词行锁绝不超扣；
以及同幂等键并发只生效一次。"""

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from src.db import connect

from tests._support import database_url, fresh_database, make_payload, settle_direct


class ConcurrencyTest(unittest.TestCase):
    def setUp(self):
        fresh_database().close()
        self.url = database_url()

    def _fire(self, payload, key_id):
        conn = connect(self.url)
        try:
            result = settle_direct(conn, payload, key_id=key_id)
            return result
        finally:
            conn.close()

    def test_concurrent_requests_never_oversell_quota(self):
        # org-alpha 额度 100；两把不同密钥各发 8 笔、每笔 10，
        # 总需求 160。获准必须恰为 10 笔 / 100 单位，其余 6 笔 429。
        requests = []
        for i in range(16):
            key = "demo-key-a" if i % 2 == 0 else "demo-key-a-c"
            requests.append((make_payload(key_id=key, units=10), key))

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda args: self._fire(*args), requests))

        approved = [r for r in results if r.status == 201]
        rejected = [r for r in results if r.status == 429]
        self.assertEqual(len(approved), 10)
        self.assertEqual(len(rejected), 6)

        conn = connect(self.url)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT consumed FROM daily_quota_usage WHERE organization_id='org-alpha'"
                )
                self.assertEqual(cur.fetchone()["consumed"], 100)
                cur.execute(
                    "SELECT count(*) AS c, coalesce(sum(units),0) AS s "
                    "FROM consumption_events WHERE organization_id='org-alpha'"
                )
                row = cur.fetchone()
                self.assertEqual(row["c"], 10)
                self.assertEqual(row["s"], 100)
        finally:
            conn.close()

    def test_concurrent_exact_boundary_request(self):
        # org-beta 额度 20：一笔 15 与一笔 10 同时到达，恰好一笔获准。
        p1 = make_payload(key_id="demo-key-b", units=15)
        p2 = make_payload(key_id="demo-key-b", units=10)
        barrier = threading.Barrier(2)

        def fire(payload):
            conn = connect(self.url)
            try:
                barrier.wait(timeout=10)
                return settle_direct(conn, payload, key_id="demo-key-b")
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(fire, p1)
            f2 = pool.submit(fire, p2)
            r1, r2 = f1.result(), f2.result()

        statuses = sorted([r1.status, r2.status])
        self.assertEqual(statuses, [201, 429])
        conn = connect(self.url)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT consumed FROM daily_quota_usage WHERE organization_id='org-beta'")
                consumed = cur.fetchone()["consumed"]
            self.assertLessEqual(consumed, 20)
            self.assertIn(consumed, (15, 10))
        finally:
            conn.close()

    def test_concurrent_identical_retries_settle_once(self):
        # 同一签名要素的重试并发到达：只能有一笔 201，其余全部重放初次结果。
        payload = make_payload(units=12, idem="idem-race-same")

        def fire(_):
            conn = connect(self.url)
            try:
                return settle_direct(conn, payload)
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(fire, range(8)))
        firsts = [r for r in results if r.status == 201 and not r.replayed]
        replays = [r for r in results if r.replayed]
        self.assertEqual(len(firsts), 1)
        self.assertEqual(len(replays), 7)
        for r in replays:
            self.assertEqual(r.body, firsts[0].body)

        conn = connect(self.url)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT consumed FROM daily_quota_usage WHERE organization_id='org-alpha'")
                self.assertEqual(cur.fetchone()["consumed"], 12)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
