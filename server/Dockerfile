FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r /app/server/requirements.txt

COPY server /app/server
COPY backend /app/backend

ENV TFK_SERVER_DB_PATH=/data/server.db \
    TFK_SERVER_HOST=0.0.0.0 \
    TFK_SERVER_PORT=8080

EXPOSE 8080

CMD ["uvicorn", "server.app.api.http_server:app", "--host", "0.0.0.0", "--port", "8080"]
