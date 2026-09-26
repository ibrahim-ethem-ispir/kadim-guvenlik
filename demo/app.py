# Kadim Güvenlik — KASITLI ZAFİYETLİ demo hedefi (Faz A, PROOF_OF_VALUE_PLAN)
# =============================================================================
# ⚠️ UYARI: Bu uygulama BİLEREK zafiyetlidir. Yalnız SAHİBİ OLDUĞUNUZ ağda/sunucuda,
# Kadim Güvenlik otonom motorunu KANITLAMAK için çalıştırın. Asla internete açmayın,
# asla gerçek veri koymayın. İşi bitince `docker compose down` ile kaldırın.
#
# 4 sınıf — hepsi orchestrator/pipeline/verification.py'nin DETERMİNİSTİK imzasıyla
# confirmed olur (özel DB/auth/CSRF gerekmez):
#   LFI (CWE-22)          → detect_lfi_signature: /etc/passwd imzası
#   Reflected-XSS (CWE-79)→ marker'ın HAM (escape'siz) yansıması
#   SSTI (CWE-1336)       → aritmetik çarpımın HESAPLANMIŞ dönmesi
#   Open-Redirect (CWE-601)→ 302 Location'ın sentinel host'a çözülmesi
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)


# 1) LFI: dosya yolunu param'dan okur — yol doğrulaması YOK (kasıtlı).
@app.route("/download")
def download():
    page = request.args.get("file", "notes.txt")
    try:
        with open(page, "r", errors="replace") as f:
            return "<pre>" + f.read() + "</pre>"
    except Exception as e:
        return f"hata: {e}", 404


# 2) Reflected-XSS: param'ı escape'siz yansıtır (kasıtlı).
# NEDEN çalışır: Flask view'dan DÖNEN düz string autoescape'e uğramaz → marker ham yansır.
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Sonuçlar: {q}</h1>"


# 3) SSTI: kullanıcı girdisi şablon KAYNAĞINA gömülür (kasıtlı) → Jinja2 değerlendirir.
@app.route("/greet")
def greet():
    name = request.args.get("name", "misafir")
    return render_template_string(f"Merhaba {name}!")


# 4) Open-Redirect: hedef doğrulanmadan yönlendirir (kasıtlı).
@app.route("/go")
def go():
    url = request.args.get("next", "/")
    return redirect(url)


@app.route("/")
def home():
    # Crawler bu linkleri keşfeder → endpoint discovery → hipotez tohumu → verifier.
    # Link verilmeyen uçlar kaçabilir (bilinen genel sınır — bkz. plan §6).
    return """<html><body>
<h1>Kadim Demo Hedef (kasıtlı zafiyetli — yetkili test)</h1>
<ul>
  <li><a href="/download?file=notes.txt">/download?file=</a> (LFI)</li>
  <li><a href="/search?q=merhaba">/search?q=</a> (Reflected XSS)</li>
  <li><a href="/greet?name=dunya">/greet?name=</a> (SSTI)</li>
  <li><a href="/go?next=/">/go?next=</a> (Open Redirect)</li>
</ul>
</body></html>"""


if __name__ == "__main__":
    # PORT 80: orchestrator'ın target validator'ı host:port KABUL ETMİYOR (main.py
    # validate_target) → hedef çıplak hostname olmalı, uygulama standart portta dinlemeli.
    app.run(host="0.0.0.0", port=80)
