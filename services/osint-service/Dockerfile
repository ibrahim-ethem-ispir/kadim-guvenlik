# =============================================================================
# Kadim Güvenlik - OSINT Intelligence Service Dockerfile
# Türkçe: Maltego benzeri OSINT servisi için multi-stage build
# =============================================================================

# Stage 1: Build - Rust derlemesi
FROM rust:1.91-bookworm as builder

# Türkçe: Debian için gerekli build araçları
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Türkçe: Önce dependency'leri kopyala (cache için)
COPY Cargo.toml Cargo.lock* ./

# Türkçe: Boş main.rs ile dependency'leri derle (cache layer)
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Türkçe: Gerçek kaynak kodunu kopyala
COPY src ./src

# Türkçe: Timestamp güncelle ve derle
RUN touch src/main.rs && \
    cargo build --release

# Stage 2: Runtime - Minimal container (Debian-based to match builder)
FROM debian:bookworm-slim

# Türkçe: Runtime için gerekli paketler (SSL certificates)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    bind9-host \
    && rm -rf /var/lib/apt/lists/*

# Türkçe: Güvenlik için non-root kullanıcı
RUN groupadd -r osint && useradd -r -g osint osint

WORKDIR /app

# Türkçe: Binary'yi kopyala
COPY --from=builder /app/target/release/osint-service /app/osint-service

# Türkçe: Sahipliği ayarla
RUN chown -R osint:osint /app

USER osint

# Türkçe: Health check için port
EXPOSE 8010

# Türkçe: Environment variables
ENV RUST_LOG=info
ENV MONGODB_URI=mongodb://kadim:kadim_secure_2024@mongodb:27017
ENV REDIS_URL=redis://redis:6379
ENV ORCHESTRATOR_URL=http://orchestrator:8000

# Türkçe: Servisi başlat
CMD ["/app/osint-service"]
