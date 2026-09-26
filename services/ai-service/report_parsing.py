"""
Kadim Güvenlik — Sağlam AI rapor ayrıştırma (§2.3)
==================================================
Türkçe: LLM analiz metninden yapılandırılmış veri (risk_score / öneriler / kritik
bulgular / ...) çıkarır. ÖNCE makine-okunur JSON aranır (model bir ```json bloğu ya da
düz JSON döndürdüyse); yoksa SAĞLAM regex fallback'e düşülür.

NEDEN (kök-neden düzeltmesi)
----------------------------
Eski satır-satır regex `int(numbers[0])` ile "risk score reflects 2026 ... 85/100"
cümlesinde YILI (2026) skor sanabiliyor ya da clamp'e takılıp GERÇEK skoru (85)
kaybediyordu; numaralı listeleri (1. 2. 3.) ve JSON çıktıyı öneri/bulgu diye HİÇ
toplamıyordu. Bu modül JSON-önce + bağlam-farkında regex ile bunu onarır.

SAF ve BAĞIMSIZ: yalnız stdlib (json, re). İzole test edilebilir.
"""

import json
import re
from typing import Any, Dict, List, Optional

# Tüketicilerin (scan_analyzer, brain_router, main) beklediği anahtarların BİRLEŞİMİ.
_KEYS = ("risk_score", "executive_summary", "critical_findings",
         "attack_chain", "recommendations", "technical_details", "next_steps")


def _empty_result() -> Dict[str, Any]:
    return {
        "risk_score": None,
        "executive_summary": "",
        "critical_findings": [],
        "attack_chain": [],
        "recommendations": [],
        "technical_details": [],
        "next_steps": [],
    }


def _clamp_score(value: Any) -> Optional[int]:
    """0-100 arası bir tamsayıya indir; dışındaysa/parse edilemezse None."""
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return None
    return score if 0 <= score <= 100 else None


def _coerce_str_list(value: Any) -> List[str]:
    """JSON'dan gelen değeri temiz string listesine çevir (str/dict/None toleranslı)."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, dict):
                # {"title": "...", "description": "..."} gibi objeleri düzleştir
                text = item.get("title") or item.get("name") or item.get("description") or ""
                text = str(text).strip()
                if text:
                    out.append(text)
        return out
    return []


# ---- JSON yolu ----------------------------------------------------------------

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    """Metinde risk_score içeren bir JSON objesi varsa ondan yapılandırılmış veri çıkar."""
    candidates: List[str] = []
    candidates.extend(_JSON_FENCE_RE.findall(text))
    # Fenced yoksa: ilk '{' ile son '}' arasını dene (model ham JSON döndürmüş olabilir).
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        candidates.append(text[first:last + 1])

    for blob in candidates:
        try:
            data = json.loads(blob)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        # risk_score veya bilinen alanlardan biri yoksa bu blok analiz JSON'u değildir.
        if not any(k in data for k in ("risk_score", "recommendations", "critical_findings")):
            continue
        result = _empty_result()
        result["risk_score"] = _clamp_score(data.get("risk_score"))
        result["executive_summary"] = str(data.get("executive_summary") or "").strip()
        result["critical_findings"] = _coerce_str_list(data.get("critical_findings"))
        result["attack_chain"] = _coerce_str_list(data.get("attack_chain"))
        result["recommendations"] = _coerce_str_list(data.get("recommendations"))
        result["technical_details"] = _coerce_str_list(data.get("technical_details"))
        result["next_steps"] = _coerce_str_list(data.get("next_steps"))
        return result
    return None


# ---- Regex fallback -----------------------------------------------------------

# "85/100" -> 85 (skorun /100 komşuluğunda olması yıl karışmasını önler)
_SCORE_OVER_100_RE = re.compile(r"(\d{1,3})\s*/\s*100")
# "risk score: 85" / "risk skoru 85" (score/skoru'ya BİTİŞİK sayı — yıl değil)
_SCORE_LABELED_RE = re.compile(
    r"risk[_\s]*sko?r[eu]?\s*[:\-=]?\s*(\d{1,3})", re.IGNORECASE
)
# Liste elemanı: "1. ...", "- ...", "* ...", "• ..."
_LIST_ITEM_RE = re.compile(r"^\s*(?:\d+[.)]|[-*•])\s+(.*\S)")


def _extract_risk_score(text: str) -> Optional[int]:
    m = _SCORE_OVER_100_RE.search(text)
    if m:
        return _clamp_score(m.group(1))
    m = _SCORE_LABELED_RE.search(text)
    if m:
        return _clamp_score(m.group(1))
    return None


def _regex_parse(text: str) -> Dict[str, Any]:
    result = _empty_result()
    result["risk_score"] = _extract_risk_score(text)

    section = None
    for raw in text.split("\n"):
        line = raw.strip()
        low = line.lower()

        # Bölüm başlıkları (TR + EN) — sırayla kontrol, en spesifik önce
        if "kritik bulgu" in low or "critical finding" in low or "🔴" in line:
            section = "critical_findings"
            continue
        if "sonraki adım" in low or "next step" in low or "hemen yapıl" in low or "⏭️" in line:
            section = "next_steps"
            continue
        if "öneri" in low or "recommendation" in low or "💡" in line:
            section = "recommendations"
            continue
        if "teknik" in low or "technical" in low or "delil" in low or "🔬" in line:
            section = "technical_details"
            continue
        if "attack chain" in low or "saldırı zinciri" in low:
            section = "attack_chain"
            continue

        item = _LIST_ITEM_RE.match(raw)
        if item and section:
            cleaned = item.group(1).strip()
            if len(cleaned) > 3:
                result[section].append(cleaned)

    return result


def parse_ai_analysis(text: str) -> Dict[str, Any]:
    """
    LLM analiz metnini yapılandırılmış dict'e çevir (JSON-önce, sağlam regex fallback).

    Döner: _KEYS anahtarlarının hepsini içeren dict (tüketici sözleşmesi).
    """
    if not text or not text.strip():
        return _empty_result()

    from_json = _try_parse_json(text)
    if from_json is not None:
        # JSON risk_score verdi ama liste alanları boşsa, regex ile ZENGİNLEŞTİR
        # (model JSON'u kısmi doldurmuş olabilir — bilgi kaybetme).
        if not from_json["recommendations"] and not from_json["critical_findings"]:
            regex = _regex_parse(text)
            for key in ("critical_findings", "recommendations", "technical_details",
                        "next_steps", "attack_chain"):
                if not from_json[key]:
                    from_json[key] = regex[key]
            if from_json["risk_score"] is None:
                from_json["risk_score"] = regex["risk_score"]
        return from_json

    return _regex_parse(text)
