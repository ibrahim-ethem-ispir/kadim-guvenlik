# Stage 1: Build
FROM rust:1.91-bookworm as builder

WORKDIR /app

# Install feroxbuster dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install feroxbuster via cargo to ensure architecture compatibility
# Türkçe: Sürüm pin'lendi (2.13.1) + --locked → tekrarlanabilir build; eskiden "latest"
# çekildiği için iki build farklı feroxbuster davranışı üretebiliyordu.
RUN cargo install feroxbuster --version 2.13.1 --locked

# Copy Cargo files first for dependency caching
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Copy actual source
COPY src ./src

# Build release binary
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy feroxbuster from builder
COPY --from=builder /usr/local/cargo/bin/feroxbuster /usr/local/bin/feroxbuster

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/fuzz-service-rs /app/fuzz-service-rs

# Create logs directory
RUN mkdir -p /app/logs

# Environment defaults
ENV RUST_LOG=info
ENV PORT=8011
ENV WORDLIST_PATH=/app/files

EXPOSE 8011

CMD ["/app/fuzz-service-rs"]
