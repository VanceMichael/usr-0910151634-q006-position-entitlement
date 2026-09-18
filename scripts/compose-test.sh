#!/usr/bin/env bash
# 容器内端到端测试编排：
#   1. 启动 PostgreSQL 16（持久卷）+ 迁移
#   2. write 阶段：一组竞争请求触及额度边界，读取第一页审计游标并落盘
#   3. 真正重启 PostgreSQL（数据保留在 entitlement-data 卷）
#   4. read 阶段：从同一游标继续翻页，校验连续/不重不漏/账面逐笔对应获准范围
#   5. 运行全量单元 + 集成测试（两阶段重启用例此时跳过）
#
# 用法：scripts/compose-test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

compose() { docker compose "$@"; }

echo ">> 启动 PostgreSQL 并执行迁移"
compose up -d postgres
compose run --rm migrate

echo ">> [write] 竞争请求 + 读取第一页游标"
compose run --rm \
  -e RESTART_PHASE=write \
  -e STATE_DIR=/state \
  -e TEST_ARGS=tests.test_restart \
  tests

echo ">> 重启 PostgreSQL（持久卷保留数据）"
compose restart postgres
for _ in $(seq 1 30); do
  status="$(compose ps --format '{{.Health}}' postgres 2>/dev/null || true)"
  if [ "$status" = "healthy" ]; then break; fi
  sleep 1
done

echo ">> [read] 重启后从同一游标续读"
compose run --rm \
  -e RESTART_PHASE=read \
  -e STATE_DIR=/state \
  -e TEST_ARGS=tests.test_restart \
  tests

echo ">> 全量测试套件"
compose run --rm tests

echo ">> 全部通过"
