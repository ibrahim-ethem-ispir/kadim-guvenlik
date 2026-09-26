"""Mass-exposure (kitlesel BOLA) SAF çekirdek testi — düz script (pytest yok).
Çalıştır: python -m orchestrator.pipeline.test_mass_exposure  (ya da doğrudan)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from orchestrator.pipeline.idor_probe import (
    detect_pii, has_strong_pii, sample_id_window, count_distinct,
    adjudicate_mass_exposure, extract_object_refs, Measured, ObjectRef,
    _MASS_PII_MIN, _MASS_DATA_MIN,
)

_p = 0; _f = 0
def ok(cond, msg):
    global _p, _f
    if cond: _p += 1
    else: _f += 1; print(f"  FAIL: {msg}")

def M(body, status=200, ct="application/json"):
    from orchestrator.pipeline.idor_probe import _classify
    return Measured(status=status, body=body, page_class=_classify(status, body),
                    length=len(body), content_type=ct)

# ---- detect_pii ----
c = detect_pii('{"email":"a@b.com","telefon":"05551112233","iban":"TR330006100519786457841326"}')
ok(c.get("email") == 1, f"email say: {c}")
ok(c.get("telefon") == 1, f"telefon say: {c}")
ok(c.get("iban") == 1, f"iban say: {c}")
ok(c.get("pii_alan", 0) >= 2, f"pii_alan: {c}")
ok(has_strong_pii(c), "email+iban güçlü PII")
ok(not has_strong_pii(detect_pii('{"title":"blog","body":"lorem 12345"}')), "public sayfa güçlü PII değil")
ok(not has_strong_pii(detect_pii('{"count": 1712345678901}')), "epoch-benzeri tek başına güçlü değil")

# ---- sample_id_window ----
r = ObjectRef(location="path", value="1000", kind="numeric", name="users", index=2, name_hint=True)
w = sample_id_window(r, 10)
ok(len(w) == 10, f"pencere boyu: {len(w)}")
ok("1000" not in w, "owner değeri pencerede yok")
ok(all(int(x) >= 0 for x in w), "negatif id yok")
ok(sample_id_window(ObjectRef("path","abc-uuid","uuid"), 10) == [], "uuid için pencere boş")

# ---- count_distinct ----
same = [M('{"id":1,"x":"aaaa"}'), M('{"id":1,"x":"aaaa"}'), M('{"id":1,"x":"aaaa"}')]
ok(count_distinct(same) == 1, f"birebir kopya tek küme: {count_distinct(same)}")
diff = [M('{"id":%d,"email":"u%d@x.com","ad":"Kisi%d Soyad%d bambaska icerik %d"}' % (i,i,i,i,i)) for i in range(6)]
ok(count_distinct(diff) == 6, f"6 farklı kayıt: {count_distinct(diff)}")

# ---- adjudicate: CONFIRMED (kitlesel PII, kimliksiz) ----
pii_samples = [M('{"id":%d,"email":"user%d@bank.com","telefon":"0555%07d","adres":"Sokak %d No %d Mah farkli %d"}' % (i,i,i,i,i,i)) for i in range(1000, 1000+_MASS_PII_MIN+2)]
v = adjudicate_mass_exposure(pii_samples, ref=r, unauth=True)
ok(v["is_idor"] and v["tier"] == "confirmed", f"kitlesel PII confirmed: {v}")
ok(v["distinct_pii"] >= _MASS_PII_MIN, f"distinct_pii: {v.get('distinct_pii')}")
ok("token yok" in v["reason"], "kimliksiz gerekçe")

# ---- adjudicate: PROBABLE (bol veri, PII yok) ----
data_only = [M('{"id":%d,"sku":"P%d","title":"urun %d benzersiz aciklama %d metni burada"}' % (i,i,i,i)) for i in range(_MASS_DATA_MIN+2)]
v2 = adjudicate_mass_exposure(data_only, ref=r, unauth=True)
ok(v2["is_idor"] and v2["tier"] == "probable", f"PII yok bol veri probable: {v2}")

# ---- adjudicate: eşik altı (az kayıt) → is_idor False ----
few = [M('{"id":1,"email":"a@b.com"}'), M('{"id":2,"email":"c@d.com"}')]
v3 = adjudicate_mass_exposure(few, ref=r, unauth=True)
ok(not v3["is_idor"], f"az kayıt confirmed değil: {v3}")

# ---- adjudicate: HTML/public sayfa veri sayılmaz ----
html = [M("<html><body>blog post %d</body></html>" % i, ct="text/html") for i in range(20)]
v4 = adjudicate_mass_exposure(html, ref=r, unauth=True)
ok(not v4["is_idor"], f"html sayfa kitlesel ifşa değil: {v4}")

# ---- kanıt ham PII sızdırmıyor mu (yalnız sayım/tür) ----
ok("@bank.com" not in v["reason"], "kanıtta ham email YOK")
ok("0555" not in v["reason"], "kanıtta ham telefon YOK")

# ---- extract_object_refs entegrasyon (API path) ----
refs = extract_object_refs("https://api.hedef.com/v1/users/1042")
ok(refs and refs[0].kind == "numeric" and refs[0].name_hint, f"api users/1042 ref: {refs}")

print(f"\n{'='*40}\nGeçti: {_p}  Kaldı: {_f}")
sys.exit(1 if _f else 0)
