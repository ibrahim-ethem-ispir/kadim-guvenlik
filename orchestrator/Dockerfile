FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Türkçe: Uzun süreli WebSocket bağlantıları için timeout ayarları
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "7200", "--ws-ping-interval", "30", "--ws-ping-timeout", "300"]
