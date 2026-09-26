# Kadim Demo Hedefi — kasıtlı zafiyetli test uygulaması

> ⚠️ **Yalnız yetkili test.** Bu uygulama BİLEREK zafiyetlidir (LFI, Reflected-XSS,
> SSTI, Open-Redirect). Kendi ağınız/sunucunuz dışında ÇALIŞTIRMAYIN, internete
> AÇMAYIN. Port yayınları yalnız `127.0.0.1`'e bağlıdır. İş bitince kaldırın.

Amaç: Kadim Güvenlik otonom motorunun **kanıtlı (confirmed)** bulgu ürettiğini
uçtan uca göstermek. Ayrıntılı plan: kökteki `PROOF_OF_VALUE_PLAN_2026-09-05.md`.

## 1. Kurulum

```bash
# Ana stack ayakta olmalı (external ağı bu compose kullanıyor):
docker compose up -d            # repo kökünde

# Demo hedefi:
cd demo && docker compose up -d
docker logs kadim-demo          # "Running on http://0.0.0.0:80" beklenir
```

## 2. Elle doğrulama (motoru çalıştırmadan önce hedefi teyit et)

```bash
# LFI — /etc/passwd içeriği dönmeli (root:x:0:0:...):
curl 'http://127.0.0.1:5001/download?file=../../../../etc/passwd'

# XSS — girdi HAM yansımalı (escape yok):
curl 'http://127.0.0.1:5001/search?q=Kad1mTest<x>'

# SSTI — çarpım HESAPLANMIŞ dönmeli (49):
curl 'http://127.0.0.1:5001/greet?name={{7*7}}'

# Open-Redirect — 302 + Location sentinel:
curl -i 'http://127.0.0.1:5001/go?next=https://kadim-oob.invalid/t1' | head -5
```

Dördü de beklenen sonucu vermiyorsa motoru suçlama — önce hedefi düzelt.

## 3. Otonom tarama

`/api/v2/scan` **JWT ister** (AuthMiddleware). Önce token al:

```bash
TOKEN=$(curl -s -X POST http://localhost:5566/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"KULLANICI","password":"PAROLA"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Taramayı başlat (hedef ÇIPLAK hostname — port YASAK, bkz. plan §3.1):
curl -s -X POST http://localhost:5566/api/v2/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"vuln.demo.local","profile":"autonomous","level":"standard"}'

# Durum (session_id ilk yanıttan):
curl -s http://localhost:5566/api/v2/scan/<session_id> -H "Authorization: Bearer $TOKEN"
```

Hesabın yoksa: `POST /api/auth/register {"username","password"}` (username ≥3 karakter,
yalnız harf/rakam/_/-). Frontend'den (`http://localhost:5566`) de giriş yapabilirsin.

## 4. Sonuç

Frontend → **Auto-Scan** → oturum: 4 sınıfta **confirmed** bulgu beklenir
(LFI kanıtı `proof` alanında `etc_passwd` imzası; XSS marker yansıması; SSTI asal
çarpımı; redirect sentinel). Ham kanıt Mongo'da:

```bash
docker exec -it kadim-mongodb mongosh -u kadim -p kadim_secure_2024 \
  --authenticationDatabase admin kadim_security \
  --eval 'db.v2_scan_sessions.find({},{"ai_analysis":1}).sort({created_at:-1}).limit(1)'
```

LLM şart DEĞİL: `.env`'de `AUTONOMOUS_LLM_DISABLE=1` iken de bu 4 sınıf deterministik
doğrulanır (kanıt LLM'e bağlı değil — Kuşatma Doktrini).

## 5. Kaldırma

```bash
cd demo && docker compose down
docker rmi demo-kadim-demo 2>/dev/null || true
```
