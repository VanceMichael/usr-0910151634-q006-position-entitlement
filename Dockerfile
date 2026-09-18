FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x scripts/entrypoint.sh scripts/compose-test.sh

EXPOSE 8000

# 入口负责：迁移（+可选种子）后启动服务；也支持 migrate / test 子命令
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["serve"]
