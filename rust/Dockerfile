# base image rust:1-bookworm pinned by digest; refresh deliberately (Dependabot or manual review)
FROM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libpq-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build --locked --release

# base image debian:bookworm-slim pinned by digest; refresh deliberately (Dependabot or manual review)
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libpq5 \
  && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 govai \
  && useradd --system --uid 1000 --gid govai --home-dir /nonexistent --shell /usr/sbin/nologin govai \
  && mkdir -p /var/lib/govai/ledger \
  && chown govai:govai /var/lib/govai/ledger

WORKDIR /app

COPY --from=builder /app/target/release/aigov_audit /app/aigov_audit

ENV GOVAI_LEDGER_DIR=/var/lib/govai/ledger \
    AIGOV_ENVIRONMENT=prod \
    HOME=/nonexistent

EXPOSE 8088

USER 1000:1000

# Same runtime contract as the root Dockerfile: non-root, read-only root filesystem, bundle mounted at /app/policies.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=6 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8088 && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && head -n 1 <&3 | grep -q ' 200 '"]

ENTRYPOINT ["/app/aigov_audit"]
