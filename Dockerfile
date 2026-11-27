# AIGov Core runtime image (aigov_audit ledger HTTP service).
#
# Clean build from the repository (no cached layers):
#   docker build --no-cache -t aigov-core:local .
#
# Runtime contract (see docs/operations/container-runtime.md):
#   - non-root user 1000:1000
#   - read-only root filesystem; writable paths are the ledger volume and /tmp (tmpfs)
#   - signed policy bundle and trust store are mounted read-only at /app/policies
#   - no source, tests, migrations directory, or unsigned policy files in this image
#   - migrations are compiled into the binary (sqlx::migrate!), so no source path is needed at runtime

# base image rust:1-bookworm pinned by digest; refresh deliberately (Dependabot or manual review)
FROM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libpq-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Only what the binary needs to compile: manifest, lock file, sources, and embedded migrations.
COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src ./src
COPY rust/migrations ./migrations

RUN cargo build --locked --release --bin aigov_audit \
  && strip target/release/aigov_audit \
  && cp target/release/aigov_audit /aigov_audit

# base image debian:bookworm-slim pinned by digest; refresh deliberately (Dependabot or manual review)
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libpq5 \
  && apt-get install -y --no-install-recommends --only-upgrade libpam0g libpam-modules libpam-modules-bin libpam-runtime \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --system --gid 1000 govai \
  && useradd --system --uid 1000 --gid govai --home-dir /nonexistent --shell /usr/sbin/nologin govai \
  && mkdir -p /app/policies /var/lib/govai/ledger \
  && chown root:root /app /app/policies \
  && chmod 0555 /app /app/policies \
  && chown govai:govai /var/lib/govai /var/lib/govai/ledger \
  && chmod 0700 /var/lib/govai /var/lib/govai/ledger

COPY --from=builder /aigov_audit /app/aigov_audit
RUN chown root:root /app/aigov_audit && chmod 0555 /app/aigov_audit

# Runtime configuration is supplied at deploy time, never baked into the image:
#   DATABASE_URL, GOVAI_API_KEYS, GOVAI_API_KEYS_JSON, AIGOV_POLICY_TRUST_ED25519_JSON, AIGOV_POLICY_BUNDLE_FILE
ENV AIGOV_BIND=0.0.0.0:8088 \
    AIGOV_POLICY_DIR=/app/policies \
    AIGOV_ENVIRONMENT=prod \
    GOVAI_LEDGER_DIR=/var/lib/govai/ledger \
    GOVAI_AUTO_MIGRATE=false \
    HOME=/nonexistent

WORKDIR /app

EXPOSE 8088

USER 1000:1000

# Health probe without curl: open a TCP connection to the service and read the status line.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=6 \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8088 && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && head -n 1 <&3 | grep -q ' 200 '"]

ENTRYPOINT ["/app/aigov_audit"]
