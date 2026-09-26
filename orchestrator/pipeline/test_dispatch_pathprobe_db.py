"""Türkçe: REGRESYON — _dispatch_pathprobe, ToolDispatcher'da 'db' attribute'una erişip
tüm stage'i çökertmemeli.

Kök neden: K3 kablolaması yanlışlıkla `self.db` kullandı; ama `_dispatch_pathprobe`
ToolDispatcher'dadır ve o sınıfın `db`'si YOKTUR ("Mongo'yu pipeline yönetir"). Attribute
erişimi flag kontrolünden ÖNCE, KOŞULSUZ çalışıp AttributeError atıyordu → pathprobe hep
'failed' (bilerek açık bırakılan .env bile bulunamıyordu). Bu test: flag KAPALIyken (varsayılan)
dispatch DB'ye HİÇ dokunmadan 'completed' döner.
"""
import asyncio
import os
import sys
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline import path_probe as pp_mod  # noqa: E402
from pipeline import scan_pipeline_v2 as sp  # noqa: E402
from pipeline.scan_pipeline_v2 import ToolDispatcher  # noqa: E402


class _Stage:
    def __init__(self):
        self.options = {}
        self.name = "pathprobe"


async def _fake_probe(*args, **kwargs):
    return {
        "findings": [], "severity_counts": {}, "probed": 10, "base_url": "http://example.com",
        "target": "example.com", "note": None, "elapsed_seconds": 0.1,
        "detected_technologies": [], "partial": False,
    }


def _run_dispatch():
    d = ToolDispatcher("scanid1234567890", "example.com")
    with patch.object(pp_mod, "probe_sensitive_paths", _fake_probe), \
         patch.object(sp.ScanEventBus, "publish", new=AsyncMock()):
        return asyncio.run(d._dispatch_pathprobe(_Stage()))


def test_tooldispatcher_db_attribute_yok():
    """Sözleşme: ToolDispatcher Mongo'yu doğrudan tutmaz (self.db yok)."""
    d = ToolDispatcher("x", "example.com")
    assert not hasattr(d, "db")


def test_dispatch_flags_kapali_completed_doner():
    os.environ.pop("PATHPROBE_MEMORY", None)
    os.environ.pop("PATHPROBE_LLM_INTEL", None)
    res = _run_dispatch()
    assert res.status == "completed", \
        f"beklenen 'completed', gelen '{res.status}' — hata: {getattr(res, 'error', None)}"
    assert res.tool == "pathprobe"


def main():
    tests = [test_tooldispatcher_db_attribute_yok, test_dispatch_flags_kapali_completed_doner]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"[OK] {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {t.__name__}: {type(e).__name__}: {e}")
    if failed:
        print(f"\n{failed} test BAŞARISIZ.")
        sys.exit(1)
    print("\nRegresyon testleri geçti.")


if __name__ == "__main__":
    main()
