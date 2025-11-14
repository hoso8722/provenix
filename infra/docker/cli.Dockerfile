# Multi-stage build for Provenix CLI tools
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

# Build CLI tools
RUN cargo build --release --bin px --bin pxb --bin pxa

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 provenix

WORKDIR /app

# Copy binaries from builder stage
COPY --from=builder /app/target/release/px ./px
COPY --from=builder /app/target/release/pxb ./pxb
COPY --from=builder /app/target/release/pxa ./pxa

# Create symlinks for easier access
RUN ln -s /app/px /usr/local/bin/px && \
    ln -s /app/pxb /usr/local/bin/pxb && \
    ln -s /app/pxa /usr/local/bin/pxa && \
    ln -s /app/px /usr/local/bin/provenix

# Set permissions
RUN chown -R provenix:provenix /app
USER provenix

CMD ["px", "--help"]