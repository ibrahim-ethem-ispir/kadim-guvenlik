# =============================================================================
# Crawler Service — headless (JS-render) keşif
# =============================================================================
# ÖNCE: mcr.microsoft.com/playwright/python:v1.62.0-jammy base'i geliyordu.
# O base FULL Chromium + Firefox + WebKit + tüm font/X setini taşıyor
# (2.22 GB tek katman) → imaj 3.73 GB. Oysa bu servis SADECE `p.chromium.launch()`
# çağırıyor ve daima headless çalışıyor.
#
# ŞİMDİ: python:3.11-slim + `playwright install --only-shell chromium`.
# --only-shell, tam Chromium yerine `chromium-headless-shell` indirir (headless
# launch'ın gerçekten kullandığı binary) + yalnız gereken sistem kütüphaneleri
# (--with-deps). ÖLÇÜM: 3.73 GB → 1.43 GB (headless-shell 340 MB + chromium sistem
# kütüphaneleri ~250 MB + python site-packages 197 MB).
# Daha aşağısı için headless-shell'i ayrı bir base imajdan COPY etmek gerekir.
#
# DİKKAT: headless=False (headed) bir launch eklenirse --only-shell YETMEZ;
# o zaman `--only-shell` kaldırılıp tam chromium kurulmalı.
# =============================================================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Tek katmanda: pip bağımlılıkları + headless-shell + sistem kütüphaneleri,
# ardından apt/pip artıkları silinir (imaj boyutu için kritik).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* /root/.cache/ms-playwright/.links

COPY main.py .

EXPOSE 8012
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8012"]
