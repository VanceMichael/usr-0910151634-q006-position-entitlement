#!/usr/bin/env bash
# 容器端到端测试编排（需要 Docker + docker compose）：
#   1. 启动 PostgreSQL 16（持久卷 entitlement-data + 健康检查）；
#      migrate 一次性服务先跑迁移，app 健康检查通过后才继续；
#   2. fire 阶段：16 笔并发竞争请求打向额度边界（需求 160 / 额度 100），
#      冻结审计游标到 test-state 卷中的 state.json；
#   3. 重启 PostgreSQL（容器重建、持久卷保留）；
#   4. verify 阶段：从同一游标继续读取，逐笔核对账面与获准范围。
set -euo pipefail

cd "$(dirname "$0")/.."

STATE=/state/state.json

wait_app() {
  echo "==> waiting for app health"
  for _ in $(seq 1 60); do
    if docker compose exec -T app python -c "
import json, urllib.request
r = urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)
assert json.load(r)['database'] == 'up'" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "app did not become healthy" >&2
  docker compose logs app | tail -30 >&2
  return 1
}

echo "==> up postgres + migrate + app"
docker compose up -d postgres
docker compose run --rm migrate
docker compose up -d app
wait_app

echo "==> phase 1: competing burst"
docker compose run --rm test python tests/container_scenario.py fire --state "$STATE"

echo "==> restarting PostgreSQL (persistent volume survives)"
docker compose restart postgres
wait_app

echo "==> phase 2: resume same cursor after restart"
docker compose run --rm test python tests/container_scenario.py verify --state "$STATE"

echo "==> container scenario passed"
