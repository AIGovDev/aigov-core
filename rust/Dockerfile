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
COPY policy.json policy.dev.json policy.staging.json policy.prod.json ./

RUN cargo build --locked --release

# base image debian:bookworm-slim pinned by digest; refresh deliberately (Dependabot or manual review)
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libpq5 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/aigov_audit /app/aigov_audit

EXPOSE 8088

CMD ["/app/aigov_audit"]
