# ── Stage 1: build upstream sysmon-modular CLI (Go) ─────────────────────────
FROM golang:1.22-alpine AS cli
WORKDIR /src
COPY vendor/sysmon-modular/tooling/ ./tooling/
RUN cd tooling && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sysmon-modular ./cmd/sysmon-modular

# ── Stage 2: Python web app ──────────────────────────────────────────────────
FROM python:3.12-slim AS app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UPSTREAM_DIR=/opt/sysmon-modular DATA_DIR=/data CLI_BIN=/usr/local/bin/sysmon-modular
WORKDIR /srv

COPY --from=cli /out/sysmon-modular /usr/local/bin/sysmon-modular

# Upstream module tree (read-only inside the container; .git and tooling excluded)
COPY vendor/sysmon-modular/ /opt/sysmon-modular/
RUN rm -rf /opt/sysmon-modular/tooling /opt/sysmon-modular/.git

COPY pyproject.toml ./
COPY app/ ./app/
COPY tests/ ./tests/
RUN pip install --no-cache-dir -e '.[dev]'

RUN useradd -r -u 10001 sysmon && mkdir -p /data && chown sysmon:sysmon /data
USER sysmon
VOLUME ["/data"]
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
