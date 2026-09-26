FROM python:3.11-slim

WORKDIR /app

# Türkçe: Go kurulumu ve subfinder binary indirme
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Türkçe: Subfinder binary'sini indirme (Go gerektirmeden direkt binary, sha256 doğrulamalı)
# Flag uyumluluğu v2.15.0 ile doğrulandı: -d/-json/-silent/-timeout/-rate-limit/-all/
# -recursive/-sources/-r/-ls/-version aynen geçerli (-json = -oJ alias).
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.15.0/subfinder_2.15.0_linux_amd64.zip \
    && echo "ce7372c58f25facbbb036c821a6336df2b4017891257f1455cd8d00d704d5862  subfinder_2.15.0_linux_amd64.zip" | sha256sum -c - \
    && apt-get update && apt-get install -y unzip \
    && unzip subfinder_2.15.0_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm -f subfinder_2.15.0_linux_amd64.zip \
    && apt-get purge -y unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Python bağımlılıkları
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8010

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
