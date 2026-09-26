# Kadim Güvenlik — demo hedefi imajı (kasıtlı zafiyetli; bkz. app.py uyarısı)
FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir "flask>=3,<4"

COPY app.py /app/app.py

# Baseline dosya: LFI doğrulayıcısı ÖNCE bu URL'yi çeker (baseline imza kontrolü).
# İÇERİK KRİTİK: passwd imzası ('root:...:0:0:'), win.ini başlıkları ([extensions]/
# [fonts]) veya base64-kaynak İÇERMEMELİ — yoksa baseline'da imza var sanılır ve
# gerçek LFI bulgusu baseline'a eşitlenip doğrulanmaz (detect_lfi_signature mantığı).
RUN echo "Bu zararsiz bir nottur. LFI baseline icin temiz icerik." > /app/notes.txt

EXPOSE 80
CMD ["python", "app.py"]
