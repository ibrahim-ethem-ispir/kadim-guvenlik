# Playwright resmi imajı Chromium + bağımlılıkları HAZIR getirir (browser indirme derdi yok).
FROM mcr.microsoft.com/playwright/python:v1.62.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Chromium imajda kurulu; yine de garanti için (idempotent):
RUN python -m playwright install chromium

COPY main.py .

EXPOSE 8012
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8012"]
