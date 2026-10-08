# syntax=docker/dockerfile:1
# The relay image built from the working tree, for the integration tests. Mirrors devkit-container's
# template (final stage, nonroot 999, env) plus docker/Dockerfile's `final` window, but syncs the
# checkout instead of cloning a tag; openssh-client and procps are for the tests' client container.
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim
RUN groupadd --system --gid 999 nonroot && useradd --system --gid 999 --uid 999 --create-home nonroot
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client cron procps \
  && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_*
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONOPTIMIZE=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable && rm -rf src
ENV PATH="/app/.venv/bin:$PATH"
ENTRYPOINT ["/app/.venv/bin/devkit-container", "run"]
