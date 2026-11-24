# AIGov Core — official runtime image (aigov_audit ledger HTTP service).
# Build: docker build -t aigov-core:local .
# Run:   docker run --rm -p 8088:8088 -v govai-ledger:/var/lib/govai/ledger ...

# base image rust:1-bookworm pinned by digest; refresh deliberately (Dependabot or manual review)
FROM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libpq-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY rust/Cargo.toml rust/Cargo.lock ./
COPY rust/src ./src
COPY rust/migrations ./migrations
COPY rust/policy.json rust/policy.dev.json rust/policy.staging.json rust/policy.prod.json ./

RUN cargo build --locked --release --bin aigov_audit

# base image debian:bookworm-slim pinned by digest; refresh deliberately (Dependabot or manual review)
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --system --gid 1000 govai \
  && useradd --system --uid 1000 --gid govai --home-dir /var/lib/govai --shell /usr/sbin/nologin govai \
  && mkdir -p /app/policies /var/lib/govai/ledger \
  && chown -R govai:govai /app /var/lib/govai

WORKDIR /app

COPY --from=builder --chown=govai:govai /build/target/release/aigov_audit /app/aigov_audit
COPY --from=builder --chown=govai:govai /build/policy.json /build/policy.dev.json /build/policy.staging.json /build/policy.prod.json /app/policies/
# Migrations are resolved at compile time from CARGO_MANIFEST_DIR (/build/migrations); provide the same path.
COPY --from=builder --chown=govai:govai /build/migrations /build/migrations

# Runtime configuration (set at deploy time): DATABASE_URL, GOVAI_API_KEYS, GOVAI_API_KEYS_JSON
ENV AIGOV_BIND=0.0.0.0:8088 \
    AIGOV_POLICY_DIR=/app/policies \
    AIGOV_ENVIRONMENT=prod \
    GOVAI_LEDGER_DIR=/var/lib/govai/ledger \
    GOVAI_AUTO_MIGRATE=false

EXPOSE 8088

USER govai

ENTRYPOINT ["/app/aigov_audit"]
