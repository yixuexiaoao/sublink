FROM python:3.12-slim-bookworm
WORKDIR /app
ENV TZ=Asia/Shanghai \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    WORKERS=2 \
    THREADS=8
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*
# 默认使用清华源,GitHub Actions 构建时传入 PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt -i ${PIP_INDEX_URL}
COPY run.py init_user_pw.py init_login_log.py docker-compose.yml ./
COPY migrations migrations
COPY app app
EXPOSE 5000
# --preload: 只在主进程初始化一次数据库; gthread: 拉取远程订阅等待网络时不阻塞其它请求
CMD ["sh", "-c", "exec gunicorn --preload -k gthread -w ${WORKERS} --threads ${THREADS} --timeout 120 -b 0.0.0.0:${PORT} run:app"]
