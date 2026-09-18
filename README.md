# 定位数据授权用量结算（Position Entitlement Ledger）

纯后端结算服务，技术栈 **Python 3.12 + PostgreSQL 16**，对外定位数据授权后的每一次取数做
鉴权结算。服务本身**不连接任何真实导航数据源**，只产出获准/拒绝判定、消费账底与审计。

## 一次取数必须同时满足的条件

`POST /v1/settlement` 在**同一个数据库事务**内依次完成（任一失败即拒绝，不扣额度）：

1. **签名有效** — HMAC-SHA256，签名串绑定方法、路径、`key_id`、`timestamp`、`nonce`、
   `idempotency_key` 与规范化 JSON 报文体的 SHA-256；
2. **时间戳在合约时钟偏差内** — 允许的偏差从 `contracts.allowed_clock_skew_seconds` 读取，
   不硬编码在应用中（机构间可不同）；
3. **防重放** — `(key_id, nonce)` 唯一约束，重复 nonce 拒绝；
4. **资源范围获准** — 请求的 `resource_scope` 必须在该 key 的 `key_scopes` 授权集合内；
5. **当日额度充足** — 按 **UTC 账期**（`DATE`）在 `daily_quota_usage` 同一行上做
   谓词更新 `WHERE consumed + :units <= daily_quota`，行锁串行化，并发触及边界**绝不超扣**。

全部满足才追加消费流水、审计、幂等初次结果并返回 201。

## 关键不变量

- **幂等重试返回初次结果**：同机构 + 同 `idempotency_key` + 同请求指纹，返回首次的响应体与
  HTTP 状态（`X-Idempotent-Replay: true`），不二次扣减；同幂等键搭配不同请求体返回
  `409 IDEMPOTENCY_KEY_REUSE`。幂等判定以事务级咨询锁串行，杜绝并发窗口。
- **可证明是哪次请求消耗了额度**：每笔 `consumption_events` 与 `audit_log` 记录
  `key_id / resource_scope / units / nonce / request_timestamp / idempotency_key /
  signature_valid`，审计与流水以 `consumption_event_id` 互相指向。
- **只追加**：`consumption_events`、`idempotency_records`、`audit_log` 由触发器禁止
  `UPDATE/DELETE`。
- **密钥轮换不抹去旧 key_id**：轮换只把旧 key 置为 `rotated` 并 `superseded_by` 指向新
  key，授权范围平移到新 key；所有表对 `api_keys` 为 `ON DELETE RESTRICT`，历史记录里的
  旧 `key_id` 永久保留。
- **机构查询按调用方范围裁剪**：机构端点以 `X-Key-Id` 鉴权，只能读自己机构
  （行裁剪），且审计只返回白名单列（`debug_info`、`signature_valid` 等排障字段裁剪）。
  运营方以 `Bearer $OPERATOR_TOKEN` 访问 `/v1/audit`，可见全量字段与全部机构。
- **连续审计游标**：`audit_log.id`（BIGSERIAL）即游标，`?cursor=<id>` 严格递增翻页，
  `next_cursor` 持久化在调用方即可；**PostgreSQL 重启后从同一游标继续，无缝无重**。
- **账实相符**：`GET /v1/orgs/{org}/reconciliation` 逐笔核对——流水单位合计必须等于
  `daily_quota_usage.consumed`，且每笔流水的范围都在该 key 的获准范围内。

## 请求与签名

请求体（`contracts/request.schema.json`）：

```json
{"key_id":"demo-key-a","timestamp":"2026-09-18T00:00:00Z","nonce":"nonce-001",
 "resource_scope":"correction/basic","units":5,"idempotency_key":"idem-1"}
```

签名串（`\n` 分隔），报文体哈希使用键排序、无空白的确定性 JSON：

```
POST
/v1/settlement
<key_id>
<timestamp>
<nonce>
<idempotency_key>
sha256(<canonical JSON body>)
```

放入请求头 `X-Signature: <hex HMAC-SHA256>`。客户端示例见
`tests/container_scenario.py::_signed_request_payload`。

## HTTP 端点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康检查（含数据库连通） |
| POST | `/v1/settlement` | 取数结算（`X-Signature`） |
| GET | `/v1/orgs/{org}/quota?day=YYYY-MM-DD` | UTC 账期剩余额度 |
| GET | `/v1/orgs/{org}/rejections?day=...` | 当日拒绝原因汇总 |
| GET | `/v1/orgs/{org}/audit?cursor=&limit=` | 连续审计游标（机构视角，裁剪） |
| GET | `/v1/orgs/{org}/reconciliation?day=...` | 账面逐笔核对 |
| GET | `/v1/audit?cursor=&limit=&organization=` | 运营方全量审计（Bearer） |
| POST | `/v1/admin/rotate` | 密钥轮换（Bearer） |

拒绝原因码：`SIGNATURE_INVALID(401)`、`KEY_UNKNOWN(401)`、`KEY_INACTIVE(401)`、
`CLOCK_SKEW_EXCEEDED(401)`、`TIMESTAMP_MALFORMED(400)`、`NONCE_REPLAY(409)`、
`SCOPE_DENIED(403)`、`QUOTA_EXCEEDED(429)`、`IDEMPOTENCY_KEY_REUSE(409)`。

## 本地运行（无 Docker 时）

需要可连的 PostgreSQL 16 与 Python 3.12：

```bash
pip install -r requirements.txt
export DATABASE_URL="postgresql://ledger:ledger@127.0.0.1:5432/entitlements"
python -m src.migrate         # 顺序执行 migrations/*.sql
python -m src.app             # 启动 HTTP 服务（启动时也会幂等迁移）
python -m unittest discover -s tests -v
```

种子数据（`migrations/002_seed.sql`）：`org-alpha`（额度 100，偏差 300s，
key `demo-key-a` / `demo-key-a-c`）、`org-beta`（额度 20，偏差 120s，key `demo-key-b`）。
示例密钥仅用于本地契约说明，不可用于其他环境。

## Compose（迁移 / 健康检查 / 持久卷 / 容器测试）

```bash
docker compose config          # 校验编排
docker compose up -d postgres
docker compose run --rm migrate          # 一次性迁移服务
docker compose up -d app                 # 应用带 HEALTHCHECK
```

- `postgres`：`postgres:16-alpine` + `pg_isready` 健康检查 + 持久卷 `entitlement-data`；
- `migrate`：健康检查通过后顺序执行迁移，成功才放行 `app`；
- `app`：容器级 `HEALTHCHECK` 轮询 `/healthz`（要求 `database=up`）。

**容器端到端测试**（从一组竞争请求开始，并在 PostgreSQL 重启后续读同一游标）：

```bash
./scripts/container_test.sh
```

流程：① 16 笔并发请求（两把密钥、各 10 单位，需求 160 / 额度 100）→ 断言恰好 10 笔获准、
6 笔 `QUOTA_EXCEEDED`、账面 100/100；② 冻结审计首页 `next_cursor` 到 `test-state` 卷；
③ `docker compose restart postgres`（持久卷保留）；④ 从同一游标继续翻页，断言 id 跨重启
严格连续无缝、16 条决策齐全、额度用尽不超扣、机构裁剪仍成立、账面逐笔对应获准范围。

## 目录

```
contracts/request.schema.json   请求契约
migrations/001_initial.sql      表、只追加触发器、nonce 清理函数
migrations/002_seed.sql         演示机构/合约/密钥/授权范围
src/signing.py                  HMAC 签名与请求指纹
src/db.py                       连接、顺序迁移
src/settlement.py               单事务结算 + 额度/拒绝/审计/轮换/核对
src/app.py                      HTTP 服务
src/migrate.py                  迁移入口
tests/                          单元/并发/HTTP 测试 + 容器两阶段场景脚本
scripts/container_test.sh       Compose 端到端编排
```

## 生产化提醒

种子中的共享密钥为演示明文；生产环境应替换为 KMS/信封加密、为应用使用最小权限数据库角色
（收回只追加表的 `TRUNCATE`）、并为运营 token 使用真实密钥管理。
