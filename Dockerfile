# syntax=docker/dockerfile:1.7
#
# Multi-stage build for paddock-server.
#
# Stage 1 — cargo-chef pre-cache of the dependency graph. Building deps
# separately from sources lets Docker reuse the layer across iterations
# even when only paddock-* code changes.
#
# Stage 2 — full workspace build with the cached deps.
#
# Stage 3 — minimal debian-slim runtime that just holds the binary, a
# data directory, and the CA bundle (for future KMS-fetch use cases).
#
# Target: paddock-server, listening on $PORT (default 8080), persisting
# under $DATA_DIR (default /data). Railway's persistent volume should be
# mounted there.

# -- Stage 1: chef --
FROM rust:1.95-slim AS chef
RUN cargo install cargo-chef --locked --version 0.1.71
WORKDIR /work

# -- Stage 2: planner --
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# -- Stage 3: builder --
FROM chef AS builder
COPY --from=planner /work/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json -p paddock-server
COPY . .
RUN cargo build --release -p paddock-server

# -- Stage 4: runtime --
FROM debian:bookworm-slim AS runtime
# `gosu` lets the entrypoint chown the mounted volume as root, then drop
# to the unprivileged `paddock` user before exec'ing the server. CA bundle
# is kept for future KMS / remote-key fetch use cases.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin paddock \
    && mkdir -p /data \
    && chown paddock:paddock /data
COPY --from=builder /work/target/release/paddock-server /usr/local/bin/paddock-server
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENV DATA_DIR=/data \
    RUST_LOG=info,paddock_server=debug,tower_http=info
EXPOSE 8080
# Railway / Fly / Render run their own health probes via HTTP against
# `/health`, so we don't bake a HEALTHCHECK directive — those platforms
# call straight into the route.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/paddock-server"]
