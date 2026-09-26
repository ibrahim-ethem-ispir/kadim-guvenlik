# Build Stage
FROM rust:1.91-slim-bullseye as builder

WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Bağımlılıkları önbelleğe almak için önce sadece Cargo.toml'u kopyalayıp dummy build yapıyoruz
COPY Cargo.toml .
# src klasörünü oluşturup dummy main.rs ekliyoruz
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Şimdi gerçek kodları kopyalıyoruz
COPY src src
# Dummy build artifact'lerini temizleyip gerçek build'i yapıyoruz
# touch komutu dosya zaman damgasını günceller, böylece cargo yeniden derler
RUN touch src/main.rs
RUN cargo build --release

# Runtime Stage
FROM debian:bullseye-slim

WORKDIR /app

# Gerekli runtime kütüphaneleri (OpenSSL vb.)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Builder aşamasından binary'i kopyala
COPY --from=builder /app/target/release/recon_service /app/recon_service

# Log klasörü oluştur
RUN mkdir -p log


# Çalıştırma komutu
ENTRYPOINT ["/app/recon_service"]
