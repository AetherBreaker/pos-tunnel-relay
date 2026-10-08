# syntax=docker/dockerfile:1
# aeth_ext's test log server at the version uv.lock pins, standing in for the central log server.
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-default-groups --group logserver
ENV ALERTS_EMAIL_PWD=unused
ENTRYPOINT ["/app/.venv/bin/test-log-server", "run", "--host", "0.0.0.0", "--port", "9020", "--log-dir", "/logs"]
