# -*- coding: utf-8 -*-
"""KİMLİK DÜZLEMİ (Credential Plane) çıkarıcısı — SAF çekirdek (ağ/DB YOK).

Operatör sezgisi (20 yıllık red team): her sızıntı bulgusu bir KİMLİK HAMMADDESİDİR.
Tarayıcı mantığı sızıntıyı "medium bulgu" olarak listeler; operatör mantığı onu
kimliğe çevirir ve kimliği bir sonraki surda SİLAH olarak kullanır (T1078 Valid
Accounts). Bu modül, bulgu nesnelerinin kanıt metinlerinden (proof/extracted)
yeniden-kullanılabilir kimlik malzemesi devşirir; karar/ucra-yazma işi pipeline'da.

Çıktı şeması (dict):
    {"kind": basic|db_conn|aws_key|username,   # silah türü
     "host": kanonik-host, "user": str, "secret": str (HAM, yalnız bellekte!),
     "material": str (anahtar/DSN gibi tek-parçalı malzeme),
     "source": "bulgu başlığı/araç", "url": kaynak URL}

GÜVENLİK: secret ASLA ham kanıta/olaya yazılmaz — Graph.register_credential onu yalnız
node.meta'da tutar (compact_state/rapor meta yayınlamaz); olay/bulguda maskelenir
(exploit_chain._mask_cred). Bu modül I/O yapmaz → izole test edilebilir.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from .exploit_chain import parse_config_credentials

# --- DSN: kullanıcı:parola gömülü bağlantı dizeleri (config sızıntılarının bel kemiği) ---
_DSN_RE = re.compile(
    r"(?P<scheme>mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqp|mssql|"
    r"jdbc:[a-z0-9]+)://(?P<user>[^:/@\s]{1,64}):(?P<pass>[^@/\s]{3,128})@",
    re.IGNORECASE,
)
# --- Tek-parçalı malzemeler: bulgu listesinde dursa da operatör için saldırı yüzeyi ---
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT_BEARER_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

# Bu araçların kanıtı ZATEN silahlandırılmış (chain/replay) veya maskeli → geri devşirilmez
# (maskeli 'p***' çiftleri regex'e takılıp sahte kimlik üretmesin).
_SKIP_TOOLS = {"exploit_chain", "cred_replay", "jwt_verify"}

MAX_SPECS_PER_SCAN = 12


def _canon_host(name: str) -> str:
    """Bağımsız küçük kanonikleştirme (attack_graph'a bağımlılık kurmadan SAF kal)."""
    h = (name or "").strip().lower()
    h = re.sub(r"^\w+://", "", h)
    h = h.split("/")[0].split("?")[0].split("@")[-1].split(":")[0].strip(".")
    return h[4:] if h.startswith("www.") else h


def _ev_get(ev: Any, field: str, default: Any = None) -> Any:
    """Evidence dataclass'i de düz dict'i de aynı oku (testlerde dict kullanılır)."""
    if isinstance(ev, dict):
        return ev.get(field, default)
    return getattr(ev, field, default)


def _tier(ev: Any) -> str:
    fn = _ev_get(ev, "effective_confidence_tier")
    if callable(fn):
        try:
            return str(fn())
        except Exception:
            pass
    return str(_ev_get(ev, "confidence_tier", "") or "")


def harvest_from_evidence(evidences: Iterable[Any]) -> List[Dict[str, Any]]:
    """Bulgulardan kimlik-spec'leri çıkar (SAF, deterministik, sıralı, dedup'lı).

    Yalnız confirmed/probable kademedeki bulgular taranır — 'unconfirmed' kanıt metni
    FP çöplüğüdür, oradan kimlik çıkarmak yanlış-kimlik POST'u riski (hesap kilitleme).
    exploit_chain.parse_config_credentials kullanıcı+parola ÇİFTİ ister; tek-parçalı
    malzemeler (AWS anahtarı, DSN, taşıyıcı JWT) ayrı desenlerle yakalanır."""
    specs: List[Dict[str, Any]] = []
    seen = set()

    def _push(spec: Dict[str, Any]) -> None:
        key = (spec["kind"], spec.get("user", ""), spec.get("secret", ""),
               spec.get("material", ""), spec["host"])
        if key in seen:
            return
        seen.add(key)
        specs.append(spec)
        if len(specs) >= MAX_SPECS_PER_SCAN:
            return

    for ev in evidences or []:
        if len(specs) >= MAX_SPECS_PER_SCAN:
            break
        tool = str(_ev_get(ev, "tool", "") or "")
        if tool in _SKIP_TOOLS:
            continue
        if _tier(ev) not in ("confirmed", "probable"):
            continue
        proof = str(_ev_get(ev, "proof", "") or "")
        extracted = _ev_get(ev, "extracted") or []
        if not isinstance(extracted, list):
            extracted = [str(extracted)]
        blob = "\n".join([proof] + [str(x) for x in extracted[:20]])
        host = _canon_host(str(_ev_get(ev, "target", "") or ""))
        source = (str(_ev_get(ev, "title", "") or tool))[:80]
        url = str(_ev_get(ev, "target", "") or "")

        # 1) DSN — gömülü çift; en yüksek değer (DB/kuyruk kimliği = sonraki sur)
        for m in _DSN_RE.finditer(blob):
            _push({"kind": "db_conn", "host": host, "user": m.group("user"),
                   "secret": m.group("pass"), "material": m.group(0)[:160],
                   "source": source, "url": url})

        # 2) config çiftleri (WP define, user/pass satırları) — çift şart
        for c in parse_config_credentials(blob, mask=False):
            _push({"kind": "basic", "host": host, "user": c["username"],
                   "secret": c["password"], "material": "",
                   "source": f"{source} [{c.get('source', 'pair')}]", "url": url})

        # 3) Tek-parçalı malzemeler: silah-kenar ÜRETMEZ (spray/brute doktrin kapalı),
        #    CREDENTIAL node olarak grafa yazılır → killchain/rapor/path-proposer yakıtı.
        for m in _AWS_KEY_RE.finditer(blob):
            _push({"kind": "aws_key", "host": host, "user": "", "secret": "",
                   "material": m.group(0), "source": source, "url": url})
        if "bearer" in blob.lower() or tool in ("js_secrets", "pathprobe"):
            for m in _JWT_BEARER_RE.finditer(blob):
                _push({"kind": "username", "host": host, "user": "jwt-carrier",
                       "secret": "", "material": m.group(0)[:120],
                       "source": source, "url": url})

        # 4) WP kullanıcı enum'u → username varlığı (pass-spray YASAK; hedefli-replay
        #    ancak basic çiftle mümkün) — yalnız isim listesi, değer = saldırı yüzeyi.
        tl = (str(_ev_get(ev, "title", "") or "") + proof).lower()
        if ("wp/v2/users" in tl or "?author=1" in tl or "user enumer" in tl) \
                and tool == "wp_probe":
            for item in extracted[:10]:
                u = re.sub(r"^[^A-Za-z0-9._-]+|[^A-Za-z0-9._-]+$", "", str(item))
                if 3 <= len(u) <= 40 and not _AWS_KEY_RE.fullmatch(u):
                    _push({"kind": "username", "host": host, "user": u, "secret": "",
                           "material": "", "source": source, "url": url})

    return specs


def harvest_fingerprint(spec: Dict[str, Any]) -> str:
    """Tekrar-devşirme dedup parmak izi (pipeline root.meta['cred_seen'] kümesinde tutar)."""
    import hashlib
    seed = "|".join([spec.get("kind", ""), spec.get("host", ""), spec.get("user", ""),
                     str(spec.get("secret", "") or spec.get("material", ""))[:24]])
    return hashlib.sha1(seed.encode("utf-8", "replace")).hexdigest()[:16]
