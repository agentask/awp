# Build context must be the repo root (pyproject.toml depends on
# ../../sdk/python via a local editable path dependency), e.g.:
#   docker build -f agents/python/Dockerfile -t concierge ..
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
# Docker's log capture isn't a tty, so Python defaults to fully buffering
# stdout instead of line-buffering it — every print() in this demo would
# sit unflushed instead of reaching `docker compose logs`.
ENV PYTHONUNBUFFERED=1
WORKDIR /src
COPY . .
WORKDIR /src/agents/python
RUN uv sync --frozen --no-dev
EXPOSE 8002
# --no-dev must match the --no-dev used at build time, or `uv run` decides
# the venv doesn't match the (implicit, dev-including) default group and
# re-syncs over the network on every container start, adding several
# seconds of startup latency before the inbox is actually listening.
ENTRYPOINT ["uv", "run", "--no-dev", "python", "-m", "concierge.main"]
