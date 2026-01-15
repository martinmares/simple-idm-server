# Build stage
FROM rust:1.75-slim as builder

# Install dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code and sqlx metadata
COPY src ./src
COPY .sqlx ./.sqlx
COPY migrations ./migrations

# Build with sqlx offline mode (NO DATABASE REQUIRED!)
ENV SQLX_OFFLINE=true
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/simple-idm-server /usr/local/bin/simple-idm-server

# Copy migrations (needed for runtime)
COPY migrations ./migrations

# Create directory for keys
RUN mkdir -p /app/keys

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Run as non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

CMD ["simple-idm-server"]
