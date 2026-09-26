# Türkçe: Nmap'i kaynaktan derle (7.991) — rustscan açık portları nmap -sV'ye paslar;
# eski Debian nmap'inin servis-imza veritabanı modern servisleri (k8s apiserver vb.)
# eksik tanır. Base de 3.11'e yükseltildi (python:3.9 EOL).
FROM python:3.11-slim AS nmap-builder

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

FROM python:3.11-slim

# Install dependencies (libstdc++6: nmap C++ runtime)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nmap-builder /usr/local/bin/nmap /usr/local/bin/nmap
COPY --from=nmap-builder /usr/local/share/nmap /usr/local/share/nmap

# Install RustScan (2.4.1 — 2.0.1'den güncel; flag'ler -a/--ulimit/-b/-t/-- uyumlu)
# Not: zip içindeki .deb dpkg'nin bilmediği "nmap" bağımlılığı ister (nmap'i kaynaktan
# derliyoruz) — bu yüzden deb yerine zip'teki statik binary'yi (rustscan.tmp0-stripped)
# doğrudan /usr/local/bin'e kuruyoruz.
RUN wget -q https://github.com/RustScan/RustScan/releases/download/2.4.1/rustscan.deb.zip \
    && unzip rustscan.deb.zip \
    && install -m 0755 rustscan.tmp0-stripped /usr/local/bin/rustscan \
    && rm -f rustscan_*.deb rustscan.tmp0-stripped rustscan.deb.zip

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
