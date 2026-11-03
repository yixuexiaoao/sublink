FROM python:3.8.20-slim-bookworm
WORKDIR /app
COPY run.py .
COPY app app
COPY migrations migrations
COPY requirements.txt .
COPY init_user_pw.py .
COPY init_login_log.py .
#COPY uwsgi.ini .
COPY docker-compose.yml .
#RUN apt-get update && apt-get install -y build-essential
RUN apt-get update && apt-get install -y tzdata
RUN apt-get install -y gcc
ENV TZ=Asia/Shanghai
RUN pip3 install --upgrade pip
# 默认使用清华源,GitHub Actions 构建时传入 PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
RUN pip3 install --no-cache-dir -r requirements.txt -i ${PIP_INDEX_URL}
#RUN pip3 install setuptools wheel
#RUN pip3 install uwsgi
ENV PORT=5000
CMD gunicorn -w 4 -b 0.0.0.0:${PORT} run:app
#CMD uwsgi --ini uwsgi.ini --http-socket=0.0.0.0:${PORT}
EXPOSE ${PORT}

