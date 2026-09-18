"""容器/本地入口：执行迁移与（可选）种子后启动 HTTP 服务。

环境变量：
  DATABASE_URL   必填（compose 注入）
  SEED_DATA      "1"（默认）写入演示机构/密钥/合同/授权
  HOST/PORT      监听地址，默认 0.0.0.0:8000
"""

from __future__ import annotations

import os
import sys

from .db import prepare
from .httpapi import serve


def main() -> int:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is required", file=sys.stderr)
        return 2
    with_seed = os.environ.get("SEED_DATA", "1") not in ("0", "false", "False")
    print("applying migrations...", flush=True)
    prepare(database_url, with_seed=with_seed)
    print("migrations applied; starting HTTP server", flush=True)
    serve(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "8000")),
        verbose=os.environ.get("HTTP_VERBOSE", "0") == "1",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
