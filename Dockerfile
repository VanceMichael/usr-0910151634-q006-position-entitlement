FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# 容器内不额外安装 curl：用标准库做健康检查。
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=20 \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2); sys.exit(0 if r.status==200 and json.load(r)['database']=='up' else 1)"

CMD ["python", "-m", "src.app"]
