# =============================================================================
# Zero-Day Researcher Service - Multi-stage Dockerfile
# =============================================================================
# Kadim Güvenlik Platformu için Rust tabanlı güvenlik araştırma motoru
# Chromium dahil headless browser desteği ile

# Stage 1: Builder
FROM rust:1.91-bookworm AS builder

WORKDIR /app

# Cargo cache için önce dependency'leri kopyala
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Kaynak kodları kopyala ve build et
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Gerekli paketler (Chromium için)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Binary'yi kopyala
COPY --from=builder /app/target/release/researcher-service /app/researcher-service

# Chromium için environment
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMIUM_FLAGS="--headless --no-sandbox --disable-gpu --disable-software-rasterizer --disable-dev-shm-usage"

# Port
EXPOSE 8008

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8008/health || exit 1

# Çalıştır
CMD ["./researcher-service"]
