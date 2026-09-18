"""PostgreSQL 连接与顺序迁移。

迁移文件位于 ``migrations/``，按文件名排序，每个文件在独立事务中执行一次，
执行记录保存在 ``schema_migrations``。连接统一使用 UTC 账期。
"""

import os
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import psycopg
from psycopg.rows import dict_row

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def _normalize_url(url: str) -> str:
    """补全 connect_timeout / options，统一 UTC；unix socket 直连也支持。"""
    parts = urlsplit(url)
    options = []
    if parts.query:
        # 保留已有参数（如 application_name），仅补 -c timezone。
        options.append(parts.query)
        if "timezone" not in parts.query:
            options.append("options=-c%20timezone%3DUTC")
    else:
        options.append("options=-c%20timezone%3DUTC")
    if "connect_timeout" not in (parts.query or ""):
        options.append("connect_timeout=5")
    return urlunsplit(parts._replace(query="&".join(options)))


def connect(database_url: str | None = None) -> psycopg.Connection:
    url = database_url or os.environ.get(
        "DATABASE_URL", "postgresql://ledger:ledger@127.0.0.1:5432/entitlements"
    )
    conn = psycopg.connect(_normalize_url(url), row_factory=dict_row, autocommit=False)
    return conn


def wait_for_database(url: str | None = None, attempts: int = 30, delay: float = 1.0) -> None:
    """等待数据库可连（compose 健康检查之后的二次保险）。"""
    import time

    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            with connect(url) as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
            return
        except psycopg.OperationalError as exc:
            last_error = exc
            time.sleep(delay)
    raise RuntimeError(f"database not reachable: {last_error}")


def applied_migrations(cur: psycopg.Cursor) -> set[str]:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    cur.execute("SELECT version FROM schema_migrations")
    return {row["version"] for row in cur.fetchall()}


def _split_statements(sql: str) -> Iterator[str]:
    """极简语句切分：按行忽略以 -- 开头的注释，按裸分号切分。

    迁移文件中的函数体使用 ``$$ ... $$`` 美元引用，内部分号不应被切分。
    """
    cleaned_lines = []
    for line in sql.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("--"):
            continue
        cleaned_lines.append(line)
    text = "\n".join(cleaned_lines)

    statements: list[str] = []
    buf: list[str] = []
    i = 0
    in_dollar = False
    dollar_tag = ""
    while i < len(text):
        if not in_dollar:
            # 匹配 $tag$ 形式（含空 tag 的 $$）。
            if text[i] == "$":
                end = text.find("$", i + 1)
                if end != -1:
                    tag = text[i : end + 1]
                    inner = tag[1:-1]
                    if inner == "" or inner.replace("_", "").isalnum():
                        in_dollar = True
                        dollar_tag = tag
                        buf.append(tag)
                        i = end + 1
                        continue
            ch = text[i]
            if ch == ";":
                stmt = "".join(buf).strip()
                if stmt:
                    statements.append(stmt)
                buf = []
            else:
                buf.append(ch)
            i += 1
        else:
            if text.startswith(dollar_tag, i):
                buf.append(dollar_tag)
                i += len(dollar_tag)
                in_dollar = False
                dollar_tag = ""
            else:
                buf.append(text[i])
                i += 1
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return iter(statements)


def run_migrations(conn: psycopg.Connection, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """在调用方事务/连接内顺序执行未应用的迁移。返回本次应用的版本列表。"""
    newly_applied: list[str] = []
    with conn.cursor() as cur:
        done = applied_migrations(cur)
        for path in sorted(migrations_dir.glob("*.sql")):
            version = path.name
            if version in done:
                continue
            sql = path.read_text(encoding="utf-8")
            for statement in _split_statements(sql):
                cur.execute(statement)
            cur.execute(
                "INSERT INTO schema_migrations (version) VALUES (%s)", (version,)
            )
            newly_applied.append(version)
    conn.commit()
    return newly_applied
