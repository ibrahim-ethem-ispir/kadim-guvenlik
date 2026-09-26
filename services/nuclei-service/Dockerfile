FROM python:3.11-alpine

# Nuclei binary indir (sha256 doğrulamalı - supply-chain koruması)
RUN apk add --no-cache wget unzip ca-certificates && \
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip && \
    echo "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6  nuclei_3.11.1_linux_amd64.zip" | sha256sum -c - && \
    unzip nuclei_3.11.1_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei_3.11.1_linux_amd64.zip && \
    apk del wget unzip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Nuclei template'lerini güncelle
RUN nuclei -update-templates

EXPOSE 8003

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003"]
