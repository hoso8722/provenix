# Multi-stage build for Provenix Server
FROM rust:1.75-slim as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY server/ ./server/

# Build the server
RUN cargo build --release --bin pxs

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 provenix

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/pxs ./pxs
COPY --from=builder /app/server/config/ ./config/

# Set permissions
RUN chown -R provenix:provenix /app
USER provenix

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["./pxs"]