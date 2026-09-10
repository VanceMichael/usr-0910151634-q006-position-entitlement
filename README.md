# 定位数据授权用量结算

项目使用 Python 3.12 与 PostgreSQL 16 保存授权范围、用量和审计记录。示例密钥仅用于本地契约说明，不可用于其他环境。

```bash
python -m unittest discover -s tests -v
docker compose config
docker compose build
```

数据库结构从 `migrations` 顺序执行，连接信息通过 `DATABASE_URL` 注入。
