"""迁移入口：python -m src.migrate

供 compose 的 migrate 一次性服务调用；应用启动时也会幂等执行一次。
"""

import os

from .db import connect, run_migrations, wait_for_database


def main() -> None:
    url = os.environ.get("DATABASE_URL")
    wait_for_database(url)
    with connect(url) as conn:
        applied = run_migrations(conn)
    print("migrations up to date" if not applied else f"applied: {', '.join(applied)}", flush=True)


if __name__ == "__main__":
    main()
