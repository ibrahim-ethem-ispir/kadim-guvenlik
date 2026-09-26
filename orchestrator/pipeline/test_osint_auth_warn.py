"""
Kadim Güvenlik — OSINT API-anahtarı sessiz-hata görünürlüğü testleri.

_maybe_warn_osint_auth: OSINT 'completed' görünüp lookup'lar 401/403 (eksik/geçersiz key)
ile boş dönüyorsa operatöre WARNING yayınlamalı; gerçek veri geldiğinde SUSMALI. Düz script.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.scan_pipeline_v2 import ScanPipelineV2, StageResult  # noqa: E402


class _Stage:
    def __init__(self, tool):
        self.tool = tool


def _run(tool, status, data):
    pipe = ScanPipelineV2(None)
    events = []

    async def narrate(etype, msg, data=None, **k):
        events.append((getattr(etype, "value", str(etype)), msg))

    res = StageResult(stage_name="osint_x", tool=tool, status=status, data=data)
    asyncio.run(pipe._maybe_warn_osint_auth(_Stage(tool), res, narrate))
    return events


def test_warns_on_auth_errors():
    ev = _run("osint", "completed", {
        "shodan": {"error": "HTTP 401 Unauthorized"},
        "virustotal": {"error": "invalid api key"},
        "internetdb": {"ports": [80, 443]},  # keysiz başarılı — sayılmamalı
    })
    assert any("OSINT" in m and "API-anahtarı" in m for _, m in ev), ev
    # 2 auth-fail (shodan, virustotal) mesajda geçmeli
    msg = ev[0][1]
    assert "shodan" in msg and "virustotal" in msg
    assert "2/3" in msg, msg
    print("[OK] test_warns_on_auth_errors")


def test_silent_when_all_ok():
    ev = _run("osint", "completed", {
        "internetdb": {"ports": [80]},
        "dns": {"records": ["A 1.2.3.4"]},
    })
    assert ev == [], ev
    print("[OK] test_silent_when_all_ok")


def test_silent_on_non_auth_error():
    """Ağ/erişim hatası (401/403 DEĞİL) API-key uyarısı üretmemeli — yanlış yönlendirme olmasın."""
    ev = _run("osint", "completed", {"shodan": {"error": "connection timeout"}})
    assert ev == [], ev
    print("[OK] test_silent_on_non_auth_error")


def test_ignores_non_osint_tool():
    ev = _run("nuclei", "completed", {"x": {"error": "401 unauthorized"}})
    assert ev == [], ev
    print("[OK] test_ignores_non_osint_tool")


if __name__ == "__main__":
    test_warns_on_auth_errors()
    test_silent_when_all_ok()
    test_silent_on_non_auth_error()
    test_ignores_non_osint_tool()
    print("\nTüm testler geçti.")
