#!/bin/sh
# 容器入口：
#   serve     执行迁移与种子，然后启动 HTTP 服务（默认）
#   migrate   只执行迁移与种子后退出
#   test      运行测试（TEST_ARGS 默认 discover -s tests -v）
set -eu

case "${1:-serve}" in
  serve)
    exec python -m src
    ;;
  migrate)
    SEED_DATA="${SEED_DATA:-1}" python - <<'PY'
from os import environ
from src.db import prepare
prepare(environ["DATABASE_URL"],
        with_seed=environ.get("SEED_DATA", "1") not in ("0", "false", "False"))
print("migrations applied")
PY
    ;;
  test)
    exec python -m unittest ${TEST_ARGS:-discover -s tests -v}
    ;;
  *)
    exec "$@"
    ;;
esac
