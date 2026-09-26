# Türkçe: Nmap'i kaynaktan derle (7.991) — Debian paket deposu eski sürümde kalıyor
# (bookworm ~7.93/7.94). -sV servis-imza veritabanı (nmap-service-probes) taze olmazsa
# modern servisler (kubernetes apiserver vb.) yanlış/eksik tanınır → pipeline'ın servis
# kategorizasyonu ve CVE korelasyonu bundan beslenir, tazelik kritik.
FROM python:3.10-slim AS nmap-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget bzip2 ca-certificates build-essential libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://nmap.org/dist/nmap-7.991.tar.bz2 \
    && echo "a5d507f29437bef3bedd4771ff9aaa8fc1c2a109ddba1f5b1cf12027456929be  nmap-7.991.tar.bz2" | sha256sum -c - \
    && tar xf nmap-7.991.tar.bz2 \
    && cd nmap-7.991 \
    && ./configure --without-zenmap --without-ndiff --without-ncat --without-nping --without-nmap-update \
    && make -j"$(nproc)" \
    && make install

FROM python:3.10-slim

# Türkçe: nmap runtime bağımlılığı (libstdc++ — nmap C++; libssl3 slim'de zaten var)
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nmap-builder /usr/local/bin/nmap /usr/local/bin/nmap
COPY --from=nmap-builder /usr/local/share/nmap /usr/local/share/nmap

WORKDIR /app

# Türkçe: Log dizini oluştur
RUN mkdir -p /app/logs

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Türkçe: Uzun süreli WebSocket bağlantıları için timeout ayarları
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--timeout-keep-alive", "7200", "--ws-ping-interval", "30", "--ws-ping-timeout", "300"]
