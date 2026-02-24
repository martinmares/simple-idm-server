# ------------------------------------------------------------------------------
# Build stage: static Linux binaries (musl)
# ------------------------------------------------------------------------------
FROM rust:1.93-alpine3.22 AS builder

RUN apk add --no-cache musl-dev pkgconfig build-base cmake perl make

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY apps ./apps
COPY crates ./crates
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx

ENV SQLX_OFFLINE=true
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --workspace --bins --target x86_64-unknown-linux-musl

# ------------------------------------------------------------------------------
# Runtime stage: openSUSE Tumbleweed
# ------------------------------------------------------------------------------
FROM opensuse/tumbleweed:latest

RUN zypper -n ref && \
    zypper -n in --no-recommends ca-certificates curl shadow openssh && \
    zypper -n clean -a

# app:app (uid/gid 1001), home=/app
RUN groupadd -g 1001 app && \
    useradd -u 1001 -g 1001 -d /app -m -s /sbin/nologin app

WORKDIR /app

# Layout requested
RUN mkdir -p /app/bin /app/conf /app/migrations

# Copy all static binaries
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/simple-idm-server /app/bin/simple-idm-server
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/simple-idm-ctl /app/bin/simple-idm-ctl
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/simple-idm-oauth2-proxy /app/bin/simple-idm-oauth2-proxy
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/simple-idm-ssh-login /app/bin/simple-idm-ssh-login
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/simple-idm-ssh-signer /app/bin/simple-idm-ssh-signer

# Runtime files needed by server
COPY migrations /app/migrations

# Ownership + OpenShift-friendly write permissions.
# OpenShift may run with random UID; granting group 0 parity keeps /app writable.
RUN chown -R 1001:1001 /app && \
    chgrp -R 0 /app && \
    chmod -R g=u /app

ENV PATH="/app/bin:${PATH}"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost:8080/health || exit 1

USER 1001

CMD ["simple-idm-server"]
