"""PostgreSQL 重启后继续读取同一审计游标的两阶段测试。

由环境变量驱动，脚本 scripts/compose-test.sh 编排：
  RESTART_PHASE=write  从一组竞争请求开始 → 读一页游标 → 落盘状态
  （重启 PostgreSQL，持久卷保留数据）
  RESTART_PHASE=read   从落盘游标继续翻页到末尾，校验连续、不重不漏、账面一致

普通 `unittest discover`（未设置 RESTART_PHASE）下两阶段均跳过。
"""

from __future__ import annotations

import json
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from src import queries
from src.db import connect, cursor, prepare
from src.settlement import settle
from src.signing import sign_request
from tests.dbcase import PostgresCase, database_url, pg_available, utc_timestamp


def _state_dir() -> Path:
    return Path(os.environ.get("STATE_DIR", "/tmp/restart-cursor-state"))


def _state_path() -> Path:
    return _state_dir() / "restart-state.json"


QUOTA = 100
UNITS_EACH = 5
N_RACERS = 30          # 20 获批（100），10 因额度不足被拒
EXTRA_REJECTS = 2      # 额外越权拒绝
PAGE_LIMIT = 7


class RestartCursorTest(PostgresCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.url = database_url()
        if not pg_available(cls.url):
            raise unittest.SkipTest(f"PostgreSQL 不可达：{cls.url}")
        prepare(cls.url)
        cls.admin = connect(cls.url)
        cls.phase = os.environ.get("RESTART_PHASE")
        cls.state_path = _state_path()

    def setUp(self) -> None:
        self.connections = []
        # 两阶段共用同一机构：write 阶段创建，read 阶段从状态文件恢复
        if self.phase == "write":
            token = uuid.uuid4().hex[:12]
            self.org_id = f"org-restart-{token}"
            self.key_id = f"key-restart-{token}"
            self.secret = f"secret-{token}"
            with cursor(self.admin) as cur:
                cur.execute(
                    "INSERT INTO organizations(id, name, daily_quota) "
                    "VALUES (%s,%s,%s)",
                    (self.org_id, self.org_id, QUOTA),
                )
                cur.execute(
                    "INSERT INTO contracts(organization_id, clock_skew_seconds, "
                    "max_units_per_request) VALUES (%s,%s,%s)",
                    (self.org_id, 300, 1_000_000),
                )
                cur.execute(
                    "INSERT INTO api_keys(key_id, organization_id, secret, "
                    "status, view_fields) VALUES (%s,%s,%s,'active',%s)",
                    (self.key_id, self.org_id, self.secret, ["*"]),
                )
                cur.execute(
                    "INSERT INTO scope_grants(organization_id, resource_scope) "
                    "VALUES (%s,%s)",
                    (self.org_id, "correction/basic"),
                )
            self.admin.commit()
        elif self.phase == "read":
            data = json.loads(self.state_path.read_text())
            self.org_id = data["org_id"]
            self.key_id = data["key_id"]
            self.secret = data["secret"]
        self.scopes = ["correction/basic"]

    def _make_payload(self, *, units=UNITS_EACH, scope="correction/basic"):
        p = {
            "idempotency_key": f"idem-{uuid.uuid4().hex}",
            "key_id": self.key_id,
            "timestamp": utc_timestamp(),
            "nonce": f"nonce-{uuid.uuid4().hex}",
            "resource_scope": scope,
            "units": units,
        }
        return p, sign_request(self.secret, p)

    def test_phase_write_starts_with_race_then_reads_first_cursor_page(self):
        if self.phase != "write":
            self.skipTest("仅 RESTART_PHASE=write 执行")

        # 1) 一组竞争请求同时触及额度边界
        barrier = threading.Barrier(N_RACERS)
        statuses: list[int] = []
        lock = threading.Lock()

        def worker():
            payload, sig = self._make_payload()
            conn = self.new_conn()
            barrier.wait()
            try:
                out = settle(conn, payload, sig)
                with lock:
                    statuses.append(out.http_status)
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=N_RACERS) as pool:
            futures = [pool.submit(worker) for _ in range(N_RACERS)]
            for f in as_completed(futures):
                f.result()

        approved_n = statuses.count(200)
        rejected_n = statuses.count(429)
        self.assertEqual((approved_n, rejected_n), (20, 10), statuses)

        # 2) 再制造两笔越权拒绝，丰富审计流
        for _ in range(EXTRA_REJECTS):
            p, s = self._make_payload(scope="tracking/forbidden")
            conn = self.new_conn()
            try:
                self.assertEqual(settle(conn, p, s).http_status, 403)
            finally:
                conn.close()

        # 3) 读第一页游标并落盘
        with cursor(self.admin) as cur:
            page = queries.audit_cursor(
                cur, self.org_id, queries._AUDIT_COLUMNS,
                after_id=0, limit=PAGE_LIMIT,
            )
            cur.execute(
                "SELECT consumed FROM quota_periods WHERE organization_id=%s",
                (self.org_id,),
            )
            consumed = cur.fetchone()[0]
        self.assertEqual(len(page["entries"]), PAGE_LIMIT)
        self.assertTrue(page["has_more"])

        _state_dir().mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps({
            "org_id": self.org_id,
            "key_id": self.key_id,
            "secret": self.secret,
            "phase1_ids": [e["id"] for e in page["entries"]],
            "cursor": page["next_cursor"],
            "consumed": consumed,
            "approved_race": approved_n,
            "rejected_race": rejected_n,
            "extra_rejects": EXTRA_REJECTS,
        }))
        self.assertEqual(consumed, QUOTA)

    def test_phase_read_continues_same_cursor_after_restart(self):
        if self.phase != "read":
            self.skipTest("仅 RESTART_PHASE=read 执行")
        state = json.loads(self.state_path.read_text())

        # 重启后写链路仍存活：当日额度已用尽，再发一笔应得到 429（读链路游标
        # 续读才是本测试核心，随后校验）。
        extra_idem = f"idem-post-restart-{uuid.uuid4().hex}"
        ep = {
            "idempotency_key": extra_idem,
            "key_id": self.key_id,
            "timestamp": utc_timestamp(),
            "nonce": f"nonce-{uuid.uuid4().hex}",
            "resource_scope": "correction/basic",
            "units": 1,
        }
        esig = sign_request(self.secret, ep)
        conn = self.new_conn()
        try:
            post_out = settle(conn, ep, esig)
            self.assertEqual(post_out.http_status, 429)
        finally:
            conn.close()

        # 从落盘游标继续翻页直到穷尽
        seen = list(state["phase1_ids"])
        cursor_id = state["cursor"]
        with cursor(self.admin) as cur:
            while True:
                page = queries.audit_cursor(
                    cur, self.org_id, queries._AUDIT_COLUMNS,
                    after_id=cursor_id, limit=PAGE_LIMIT,
                )
                ids = [e["id"] for e in page["entries"]]
                seen.extend(ids)
                cursor_id = page["next_cursor"]
                if not page["has_more"]:
                    break

        # 取本机构审计全集，校验连续/不重/不漏
        with cursor(self.admin) as cur:
            cur.execute(
                "SELECT id FROM audit_log WHERE organization_id=%s ORDER BY id",
                (self.org_id,),
            )
            all_ids = [r[0] for r in cur.fetchall()]

        self.assertEqual(seen, all_ids)
        self.assertEqual(len(seen), len(set(seen)))

        # 账面消费逐笔对应获准范围，且总额与额度账期一致
        with cursor(self.admin) as cur:
            cur.execute(
                """
                SELECT ce.id, ce.units, ce.resource_scope, ce.key_id
                FROM consumption_events ce
                WHERE ce.organization_id = %s
                ORDER BY ce.id
                """,
                (self.org_id,),
            )
            events = cur.fetchall()
            cur.execute(
                """
                SELECT COUNT(*) FROM consumption_events ce
                LEFT JOIN scope_grants sg
                  ON sg.organization_id = ce.organization_id
                 AND sg.resource_scope = ce.resource_scope
                 AND sg.revoked_at IS NULL
                WHERE ce.organization_id = %s AND sg.resource_scope IS NULL
                """,
                (self.org_id,),
            )
            out_of_scope = cur.fetchone()[0]
        self.assertEqual(out_of_scope, 0)
        self.assertEqual(len(events), state["approved_race"])
        self.assertEqual(sum(e[1] for e in events), state["consumed"])
        self.assertEqual(sum(e[1] for e in events), QUOTA)
        # 每笔都落在唯一获准范围 correction/basic，且保留当时 key_id
        self.assertTrue(all(e[2] == "correction/basic" for e in events))
        self.assertTrue(all(e[3] == state["key_id"] for e in events))

        # 拒绝原因汇总在重启后仍可查询，且数量与 write 阶段吻合
        import datetime as dt
        today = dt.datetime.now(dt.timezone.utc).date()
        with cursor(self.admin) as cur:
            summary = queries.rejection_summary(cur, self.org_id, today)
        counts = {r["reason"]: r["count"] for r in summary["reasons"]}
        self.assertEqual(counts.get("quota_exceeded"),
                         state["rejected_race"] + 1)  # +1 重启后的那笔
        self.assertEqual(counts.get("scope_denied"), state["extra_rejects"])


if __name__ == "__main__":
    unittest.main()
