"""容器端到端场景（在 compose 的 test 容器内运行，通过 HTTP 打真实服务）。

阶段 1 ``fire``：
  * 健康检查通过后，用两把不同密钥并发发起 16 笔、每笔 10 单位的竞争请求
    （org-alpha 当日额度 100），断言恰好 10 笔获准、6 笔 429，绝不超扣；
  * 读取审计首页，把 next_cursor 与已见 id 写入状态卷中的 state.json。

阶段 2 ``verify``（在 PostgreSQL 重启之后运行）：
  * 从 state.json 的同一游标继续翻页，断言跨重启 id 连续、无缝无重；
  * 竞争请求的 16 条决策全部在审计中；10 笔获准合计 100；
  * 额度视图 consumed=100/remaining=0；账面逐笔核对 balanced 且
    每笔流水的范围均在 key_scopes 获准范围内。

全程只访问本服务与本数据库，不连接任何真实导航数据源。
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE_URL = os.environ.get("LEDGER_BASE_URL", "http://app:8000")
OPERATOR_TOKEN = os.environ.get("OPERATOR_TOKEN", "operator-local-token")
STATE_PATH_DEFAULT = "/state/state.json"

KEYS = {
    "demo-key-a": b"local-demo-secret-alpha",
    "demo-key-a-c": b"local-demo-secret-alpha-2",
}


def _request(path, *, method="GET", body=None, headers=None, base=BASE_URL, retries=0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers or {}, method=method)
    last = None
    for _ in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())
        except OSError as exc:
            last = exc
            time.sleep(1)
    raise RuntimeError(f"cannot reach {base}{path}: {last}")


def wait_healthy():
    for _ in range(60):
        try:
            status, _ = _request("/healthz")
            if status == 200:
                return
        except RuntimeError:
            pass
        time.sleep(1)
    raise RuntimeError("service never became healthy")


def _signed_request_payload(i):
    key_id = "demo-key-a" if i % 2 == 0 else "demo-key-a-c"
    payload = {
        "key_id": key_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": f"burst-nonce-{i}-{os.getpid()}",
        "resource_scope": "correction/basic",
        "units": 10,
        "idempotency_key": f"burst-idem-{i}-{os.getpid()}",
    }
    # 与 src.signing 保持一致的客户端签名（仓库根加入 sys.path，兼容容器 /app）。
    from src.signing import sign_request

    sig = sign_request(
        KEYS[key_id], "POST", "/v1/settlement",
        payload["key_id"], payload["timestamp"], payload["nonce"],
        payload["idempotency_key"], payload,
    )
    return payload, {"X-Signature": sig, "Content-Type": "application/json"}


def phase_fire(state_path: str) -> None:
    wait_healthy()
    print("[fire] launching 16 concurrent competing requests (quota=100, ask=160)")

    def one(i):
        payload, headers = _signed_request_payload(i)
        status, body = _request("/v1/settlement", method="POST", body=payload, headers=headers)
        return i, payload, status, body

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(one, range(16)))

    approved = [r for r in results if r[2] == 201]
    rejected = [r for r in results if r[2] == 429]
    print(f"[fire] approved={len(approved)} quota_rejected={len(rejected)}")
    assert len(approved) == 10, f"expected 10 approvals, got {len(approved)}"
    assert len(rejected) == 6, f"expected 6 quota rejections, got {len(rejected)}"
    assert sum(r[3]["units"] for r in approved) == 100
    # 每个获准响应自报剩余额不得为负。
    assert all(r[3]["remaining"] >= 0 for r in approved)

    # 读取审计首页并冻结游标，供重启后继续。
    status, page = _request("/v1/audit?limit=5",
                            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"})
    assert status == 200
    state = {
        "burst_keys": [r[1]["idempotency_key"] for r in results],
        "first_page_ids": [e["id"] for e in page["entries"]],
        "cursor": page["next_cursor"],
        "approved_event_ids": sorted(r[3]["consumption_event_id"] for r in approved),
    }
    assert len(state["first_page_ids"]) == 5
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f)
    print(f"[fire] cursor frozen at {state['cursor']}; state -> {state_path}")


def _drain_audit(from_cursor, page_size=5):
    entries, cursor = [], from_cursor
    while True:
        status, page = _request(
            f"/v1/audit?cursor={cursor}&limit={page_size}",
            headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"})
        assert status == 200, page
        entries.extend(page["entries"])
        cursor = page["next_cursor"]
        if not page["has_more"]:
            return entries, cursor


def phase_verify(state_path: str) -> None:
    wait_healthy()
    assert os.path.exists(state_path), f"state file missing after restart: {state_path}"
    with open(state_path, encoding="utf-8") as f:
        state = json.load(f)
    print(f"[verify] resumed from cursor {state['cursor']} after PostgreSQL restart")

    # 1) 从冻结游标继续（小页强制翻页）：跨重启 id 严格连续、无缝无重。
    entries, final_cursor = _drain_audit(state["cursor"], page_size=5)
    assert entries, "expected audit entries after the frozen cursor"
    ids = [e["id"] for e in entries]
    assert ids == sorted(ids), "ids not monotonically increasing"
    assert len(ids) == len(set(ids)), "duplicate ids across pages"
    assert all(i > state["cursor"] for i in ids), "entries at/before resumed cursor"
    seam = state["first_page_ids"][-1]
    assert ids[0] == seam + 1, f"seam gap/overlap across restart: {ids[0]} after {seam}"

    # 2) 从 0 重新全量翻页：持久卷 + bigserial 保持同一序列，
    #    首页 id 必须与重启前冻结的一致，且 16 条竞争决策全部可审计。
    all_entries, _ = _drain_audit(0, page_size=5)
    all_ids = [e["id"] for e in all_entries]
    assert all_ids == sorted(all_ids) and len(all_ids) == len(set(all_ids))
    assert [e["id"] for e in all_entries[:5]] == state["first_page_ids"], \
        "audit sequence changed across restart"
    burst = {e["idempotency_key"]: e for e in all_entries
             if e["idempotency_key"] in set(state["burst_keys"])}
    missing = set(state["burst_keys"]) - set(burst)
    assert not missing, f"burst decisions missing from audit: {sorted(missing)[:3]}"
    approved_audit = [e for e in burst.values() if e["decision"] == "approved"]
    rejected_audit = [e for e in burst.values() if e["decision"] == "rejected"]
    assert len(approved_audit) == 10 and len(rejected_audit) == 6
    assert sum(e["units"] for e in approved_audit) == 100

    # 机构视角额度：恰好用尽，不超扣。
    status, quota = _request("/v1/orgs/org-alpha/quota",
                             headers={"X-Key-Id": "demo-key-a"})
    assert status == 200
    assert quota["consumed"] == 100 and quota["remaining"] == 0, quota

    # 机构视角审计裁剪仍然成立。
    status, org_page = _request("/v1/orgs/org-alpha/audit?limit=50",
                                headers={"X-Key-Id": "demo-key-a"})
    assert status == 200
    assert all(e["organization_id"] == "org-alpha" for e in org_page["entries"])
    assert all("debug_info" not in e and "signature_valid" not in e
               for e in org_page["entries"])

    # 账面逐笔核对：流水合计 == 用量；每笔均对应获准范围。
    status, rec = _request("/v1/orgs/org-alpha/reconciliation",
                           headers={"X-Key-Id": "demo-key-a"})
    assert status == 200, rec
    assert rec["balanced"] is True, rec
    assert rec["every_event_scope_granted"] is True, rec
    assert rec["events_sum_units"] == 100 == rec["ledger_consumed"], rec
    assert rec["event_count"] == 10, rec
    granted_scopes = {"correction/basic", "correction/rtk", "ephemeris/nav"}
    assert all(e["resource_scope"] in granted_scopes and e["scope_granted"]
               and e["units"] == 10 for e in rec["events"])
    assert sorted(e["event_id"] for e in rec["events"]) == state["approved_event_ids"]

    print("[verify] OK: cursor continuous across restart; consumed=100/100; "
          "10 events each mapped to a granted scope; no navigation data source touched.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["fire", "verify"])
    parser.add_argument("--state", default=STATE_PATH_DEFAULT)
    args = parser.parse_args()
    if args.phase == "fire":
        phase_fire(args.state)
    else:
        phase_verify(args.state)


if __name__ == "__main__":
    main()
