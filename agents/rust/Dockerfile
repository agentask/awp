# Build context must be the repo root (Cargo.toml depends on ../../sdk/rust
# via a local path dependency), e.g.:
#   docker build -f agents/rust/Dockerfile -t activities-agent ..
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --manifest-path agents/rust/Cargo.toml

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/agents/rust/target/release/activities-agent /usr/local/bin/activities-agent
EXPOSE 8003
ENTRYPOINT ["/usr/local/bin/activities-agent"]
