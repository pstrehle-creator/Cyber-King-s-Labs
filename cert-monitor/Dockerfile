FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CERT_MONITOR_DB=/data/cert_monitor.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cert_monitor.py ct.py dashboard.py storage.py ./
COPY templates/ templates/
COPY static/ static/
COPY docker/scheduler.sh /usr/local/bin/cert-monitor-scheduler

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin certmon \
    && mkdir -p /data \
    && chown certmon /data \
    && chmod 0755 /usr/local/bin/cert-monitor-scheduler

USER certmon
VOLUME /data
EXPOSE 8080

CMD ["python", "cert_monitor.py", "--help"]
