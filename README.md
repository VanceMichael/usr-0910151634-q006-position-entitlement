# 定位数据授权用量结算（纯后端）

Python 3.12 + PostgreSQL 16 构建的授权取数结算服务。**全程不连接任何真实导航
数据源**：服务只读写本项目的 PostgreSQL（DATABASE_URL），不存在任何对外部
定位/导航服务的调用。

一次取数必须同时满足三个条件，且在**同一个数据库事务**内完成：

1. 签名有效（HMAC-SHA256，规范化签名覆盖全部请求字段）；
2. 资源范围获准（`scope_grants` 且未吊销）；
3. 当 UTC 账期额度充足（账期行加行锁后扣减，`CHECK(consumed <= quota)` 兜底）。

此外提供：

- nonce 防重放 + `idempotency_key` 幂等；重试返回**初次结果**且不二次扣费；
- 密钥轮换只追加，不删除旧 `key_id`；台账逐笔保存 `key_id` 不可变快照；
- 只追加审计（触发器禁止 UPDATE/DELETE/TRUNCATE），记录每次批准/拒绝/重放，
  运营方可凭审计中的签名、请求摘要、nonce、幂等键证明“是哪次请求消耗了额度”；
- 机构查询按调用方机构与字段白名单裁剪；
- 按 UTC 账期给出剩余额度、拒绝原因汇总、连续审计游标（可跨 PostgreSQL 重启续读）。

## 目录

```
contracts/request.schema.json   请求契约（key_id/时间戳/nonce/范围/数量/幂等键）
migrations/001_initial.sql      可重复执行的建表迁移（含只追加触发器）
src/signing.py                  规范化签名 / 请求摘要
src/validators.py               契约校验
src/db.py                       连接、迁移、种子数据
src/settlement.py               结算事务（防重放→权限→额度→审计）
src/queries.py                  机构只读查询（裁剪/额度/拒绝汇总/游标/对账）
src/httpapi.py                  标准库 HTTP 服务
src/client.py                   调试客户端与签名辅助
scripts/entrypoint.sh           容器入口（serve/migrate/test）
scripts/compose-test.sh         竞争 → 重启 PG → 游标续读的容器编排
tests/                          单元 + 真实 PG 集成 + 并发 + 两阶段重启测试
```

## 请求签名

规范化签名串（`v1`，换行分隔，字段顺序固定）：

```
v1
<key_id>
<timestamp>          RFC3339，必须带时区
<nonce>
<resource_scope>
<units>
<idempotency_key>
```

`X-Signature = HMAC_SHA256(secret, 规范化串)` 的十六进制。任一字段改动签名即失配。
允许的时钟偏差（过去/未来对称）按机构从 `contracts.clock_skew_seconds` 读取。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/v1/settle` | 取数结算，头 `X-Key-Id`/`X-Signature` |
| GET | `/v1/quota?date=YYYY-MM-DD` | UTC 账期剩余额度 |
| GET | `/v1/rejections?date=…` | UTC 账期拒绝原因汇总 |
| GET | `/v1/audit?cursor=<id>&limit=&date=` | 连续审计游标（严格 id 升序） |
| GET | `/v1/reconciliation?date=…` | 账面逐笔对账（事件与账期 consumed 必须一致） |
| GET | `/healthz` | 健康检查（探活数据库） |

机构查询用 `X-Key-Id` + `X-Signature` 鉴权，签名串为
`GET\n<path>\n<按 key 排序的 canonical query>`。游标返回 `next_cursor`，
下次以 `?cursor=<next_cursor>` 续读，不重不漏。

拒绝原因码：`unknown_key` / `bad_signature` / `key_inactive` / `stale_timestamp`
/ `future_timestamp` / `units_exceeded` / `scope_denied` / `nonce_replayed`
/ `idempotency_conflict` / `idempotency_in_flight` / `quota_exceeded`。

## Docker Compose

`compose.yaml` 负责迁移、健康检查与持久卷：

- `postgres`：`postgres:16-alpine`，带 `pg_isready` 健康检查，数据在命名卷
  `entitlement-data`；
- `migrate`：数据库健康后执行迁移与种子，成功才放行 app；
- `app`：依赖迁移完成，自带 `/healthz` 健康检查；
- `tests`（test profile）：容器集成测试。

```bash
docker compose up -d --build
curl -s http://localhost:8000/healthz
```

种子演示数据（密钥仅用于本地）：机构 `org-a`（`demo-key-a`，额度 1000，
时钟偏差 300s，可见全部审计字段）与 `org-b`（`demo-key-b`，额度 100，
时钟偏差 120s，受限字段白名单）。

容器端到端测试（一组竞争请求 → 重启 PostgreSQL → 从同一游标续读）：

```bash
scripts/compose-test.sh
```

## 本地运行（无 Docker 时）

```bash
pip install -r requirements.txt
# 任意可达的 PostgreSQL 16
export DATABASE_URL=postgresql://ledger:ledger@127.0.0.1:5432/entitlements
python -m src           # 自动迁移+种子后启动 :8000

python -m src.client settle --key demo-key-a --secret demo-secret-a \
    --scope correction/basic --units 5
python -m src.client quota --key demo-key-a --secret demo-secret-a
python -m src.client audit --key demo-key-a --secret demo-secret-a --cursor 0
```

## 测试

```bash
# 纯单元（签名、契约校验）无需数据库；集成测试在 PG 不可达时自动跳过
python -m unittest discover -s tests -v
DATABASE_URL=... python -m unittest discover -s tests -v
```

关键集成保证（均对真实 PostgreSQL 16 验证）：

- `test_concurrency.py`：40 个线程各取 6（额度 100），恰好 16 笔获批共 96，
  24 笔 429，账期 `consumed` 与逐笔事件严格一致、绝不超扣；
- `test_concurrent_same_idempotency_key_single_charge`：同一幂等请求并发只有
  一笔消费；
- `test_restart.py`：write 阶段从竞争请求开始并读第一页游标 → **真正重启
  PostgreSQL**（持久卷保留）→ read 阶段从同一游标翻页到末尾，验证连续、
  不重不漏，且账面消费**逐笔对应获准范围** `correction/basic`、`key_id` 保留；
- 密钥轮换后历史事件仍记录旧 `key_id`，旧密钥不能新开消费、但可取回历史初次
  结果；吊销密钥则彻底不可用；
- `audit_log` 的 UPDATE/DELETE/TRUNCATE 均被触发器拒绝。
