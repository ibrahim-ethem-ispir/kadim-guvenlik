"""
Kadim Güvenlik — Kapsam Kapısı testleri (düz script, pytest yok)
================================================================
Çalıştır: `python3 test_scope_guard.py` (orchestrator/pipeline içinden).
scope_guard (entry yetki + SSRF/iç-ağ guard) ve attack_hypothesis host-kapsam süzgecini
izole doğrular — dış-kutudan yetkisiz/off-target istek engelinin regresyonunu yakalar.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scope_guard as sg
import attack_hypothesis as ah

_fail = []


def ok(cond, msg):
    print(("  [OK] " if cond else "  [FAIL] ") + msg)
    if not cond:
        _fail.append(msg)


def test_ssrf_guard_default():
    os.environ.pop("ALLOW_PRIVATE_TARGETS", None)
    ok(sg.ip_scope_reason("127.0.0.1"), "loopback reddedilir")
    ok(sg.ip_scope_reason("10.0.0.5"), "RFC1918 reddedilir")
    ok(sg.ip_scope_reason("192.168.1.1"), "192.168/16 reddedilir")
    ok(sg.ip_scope_reason("169.254.169.254"), "bulut-metadata reddedilir")
    ok(sg.ip_scope_reason("8.8.8.8") is None, "public IP serbest")
    ok(sg.ip_scope_reason("bank.com.tr") is None, "domain IP-guard'a takılmaz")


def test_internal_mode():
    os.environ["ALLOW_PRIVATE_TARGETS"] = "true"
    ok(sg.ip_scope_reason("10.0.0.5") is None, "iç-ağ modunda RFC1918 serbest")
    ok(sg.ip_scope_reason("169.254.169.254"), "iç-ağ modunda bile metadata yasak")
    os.environ.pop("ALLOW_PRIVATE_TARGETS", None)


def test_allowlist():
    os.environ["AUTHORIZED_TARGETS"] = "bank.com.tr, 203.0.113.0/24"
    ok(sg.authorized_hosts_configured(), "allowlist dolu algılanır")
    ok(sg.is_authorized("bank.com.tr"), "tam domain eşleşme")
    ok(sg.is_authorized("api.bank.com.tr"), "subdomain eşleşme")
    ok(not sg.is_authorized("evil.com"), "kapsam-dışı domain red")
    ok(not sg.is_authorized("notbank.com.tr"), "suffix-benzeri sahte domain red")
    ok(sg.is_authorized("203.0.113.9"), "CIDR içindeki IP kabul")
    ok(not sg.is_authorized("203.0.114.9"), "CIDR dışı IP red")
    raised = False
    try:
        sg.enforce_target_scope("evil.com")
    except ValueError:
        raised = True
    ok(raised, "enforce_target_scope kapsam-dışında ValueError")
    os.environ.pop("AUTHORIZED_TARGETS", None)
    ok(not sg.authorized_hosts_configured(), "allowlist boş algılanır")
    ok(sg.is_authorized("anything.com"), "allowlist boşsa herkes yetkili (geriye-uyum)")


def test_hypothesis_scope():
    allowed = frozenset({"bank.com.tr"})
    raw = [
        {"url": "https://api.bank.com.tr/x?id=1", "vuln_class": "sqli"},
        {"url": "http://169.254.169.254/latest/meta-data/", "vuln_class": "sqli"},
        {"url": "https://evil-attacker.com/x?id=1", "vuln_class": "sqli"},
        {"url": "https://bank.com.tr/p?file=x", "vuln_class": "lfi"},
    ]
    hyps = ah.parse_hypotheses(raw, allowed_hosts=allowed)
    hosts = sorted({ah._canon_host(h.url) for h in hyps})
    ok(hosts == ["api.bank.com.tr", "bank.com.tr"], f"yalnız in-scope kaldı: {hosts}")
    ok(len(ah.parse_hypotheses(raw)) == 4, "allowed_hosts=None → filtre yok (geriye-uyum)")
    # _canon_host: www + şema + port normalize
    ok(ah._canon_host("https://www.bank.com.tr:443/x") == "bank.com.tr", "www/şema/port normalize")


if __name__ == "__main__":
    for fn in (test_ssrf_guard_default, test_internal_mode, test_allowlist, test_hypothesis_scope):
        print(f"=== {fn.__name__} ===")
        fn()
    print()
    if _fail:
        print(f"{len(_fail)} test BAŞARISIZ")
        sys.exit(1)
    print("Tüm kapsam-kapısı testleri geçti.")
