"""
Red Team Proxy Router — Orchestrator
====================================
Türkçe: UI'daki domain chip'lerinden ("bu domain'i derinlemesine incele") tetiklenen
hedefli red-team aksiyonları. İki uç:

1. POST /redteam/path-probe  → deterministik hassas-yol taraması (pipeline.path_probe).
   "domain/.env" sınıfı basit ama ölümcül açıkların ANINDA doğrulaması.
2. POST /redteam/analyze     → hızlı yüzey snapshot'ı (DNS + HTTP parmak izi + hassas
   yol taraması + crt.sh subdomainler) toplayıp ai-service'e RED TEAM personasıyla
   gönderir. LLM saldırgan gibi "5 adım önde" düşünür: bulgulardan saldırı zinciri
   kurar, insan analistin bakması gereken sıradaki noktaları önceliklendirir.

Motor felsefesiyle uyum: LLM burada da KRİTİK YOL DEĞİL — path-probe tek başına
deterministik sonuç üretir; analyze'da LLM erişilemezse snapshot yine döner.
"""

import logging
import os
import re
import socket
import uuid
from datetime import datetime

from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# nginx /api/ prefix'ini strip ediyor → /redteam olarak mount edilir (frontend: /api/redteam/*)
router = APIRouter(prefix="/redteam", tags=["redteam"])

logger = logging.getLogger("redteam-proxy")

AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://ai-service:8009")

# Kalıcı kayıt: manuel red-team taramaları (path-probe / analyze) Mongo'ya yazılır ki
# geriye dönük görülebilsin. db bağlanamazsa None — kayıt sessizce atlanır (tarama yine döner).
try:
    from core.db import db as _mongo_db
except Exception as _db_e:  # import döngüsü/erişim sorununda tarama yine çalışsın
    logger.warning(f"core.db import edilemedi — red-team kayıtları kalıcı olmayacak: {_db_e}")
    _mongo_db = None


def _redteam_collection():
    """Manuel red-team tarama kayıtları koleksiyonu; db yoksa None."""
    if _mongo_db is not None:
        return _mongo_db["redteam_scans"]
    return None


def _persist_redteam_scan(doc: dict) -> None:
    """Bir red-team taramasını kalıcı yaz. Hata tarama sonucunu ETKİLEMEZ (best-effort).
    Ham sırlar zaten path_probe tarafında maskelendiği için burada ek maskeleme gerekmez."""
    col = _redteam_collection()
    if col is None:
        return
    try:
        col.insert_one(doc)
    except Exception as e:
        logger.warning(f"Red-team kaydı yazılamadı ({doc.get('target')}): {e}")

# Hedef doğrulama: domain veya IPv4. SSRF yüzeyini sınırlamak için şema/porta izin verme;
# iç-ağ hedefleri bu platformun zaten doğal kullanım alanıdır (yetkili kullanıcı aracı).
_DOMAIN_RE = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _normalize_target(raw: str) -> str:
    """Kullanıcı girdisini temiz host'a indirger; geçersizse 422 fırlatır."""
    host = re.sub(r"^https?://", "", (raw or "").strip()).split("/")[0].split("?")[0].strip()
    host = host.split(":")[0]  # port ekini at — prober 80/443 dener
    if not host or len(host) > 253:
        raise HTTPException(status_code=422, detail="Geçersiz hedef")
    if not (_DOMAIN_RE.match(host) or _IPV4_RE.match(host)):
        raise HTTPException(status_code=422, detail=f"Geçersiz hedef formatı: {host}")
    return host


class PathProbeRequest(BaseModel):
    target: str = Field(..., description="Domain veya IP (örn. example.com)")
    # reveal=True → yanıttaki snippet'ler MASKESİZ döner (kanıtlama için). DB'ye YİNE maskeli
    # yazılır (kalıcı depo güvenliği). Yetkili operatör "açığı kanıtlamam lazım" derse kullanır.
    reveal: bool = False


class RedTeamAnalyzeRequest(BaseModel):
    target: str
    include_probe: bool = True   # hassas yol taramasını snapshot'a dahil et
    include_subdomains: bool = True  # crt.sh pasif subdomain listesi


class LearnPathRequest(BaseModel):
    """Manuel ekip raporu: 'başkası buldu, biz bulamadık' → kalıcı hafıza. Bir kez girilen yol
    sonraki HER taramada problanır (K3 öğrenme döngüsü)."""
    path: str = Field(..., description="Web-kök göreli yol (örn. /symfony/config/databases.yml)")
    category: str = "credential_exposure"
    severity: str = "high"
    # signature: deterministik doğrulama imzası (must_contain_any/all, must_not_contain, min_length).
    # Verilmezse validator alanı ya da 'generic' kullanılır (operatör kanıtı var kabul).
    signature: Optional[Dict[str, Any]] = None
    validator: Optional[str] = None
    tech: Optional[List[str]] = None  # None → global (her hedefte aranır)


async def _http_fingerprint(client: httpx.AsyncClient, host: str) -> dict:
    """Kök sayfadan hızlı parmak izi: server/X-Powered-By/başlık/güvenlik başlıkları."""
    for scheme in ("https", "http"):
        base = f"{scheme}://{host}"
        try:
            resp = await client.get(base + "/", timeout=8.0)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            title = ""
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:8192], re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
            sec_headers = {}
            for h in ("strict-transport-security", "content-security-policy",
                      "x-frame-options", "x-content-type-options",
                      "referrer-policy", "permissions-policy"):
                sec_headers[h] = headers.get(h)
            return {
                "base_url": base,
                "status": resp.status_code,
                "server": headers.get("server"),
                "x_powered_by": headers.get("x-powered-by"),
                "title": title,
                "missing_security_headers": [h for h, v in sec_headers.items() if not v],
                "content_length": len(resp.content),
            }
        except Exception:
            continue
    return {"base_url": None, "error": "HTTP erişimi yok (80/443 kapalı veya filtrelendi)"}


async def _crtsh_subdomains(client: httpx.AsyncClient, host: str) -> list:
    """Pasif subdomain keşfi (crt.sh) — kısa timeout, hata sessiz."""
    # Yalnız registrable kök domain sorgulanır (sub.example.com → example.com)
    parts = host.split(".")
    if len(parts) > 2 and not _IPV4_RE.match(host):
        root = ".".join(parts[-2:])
    else:
        root = host
    try:
        resp = await client.get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=10.0)
        if resp.status_code != 200:
            return []
        names = set()
        for entry in (resp.json() or [])[:200]:
            for n in str(entry.get("name_value", "")).split("\n"):
                n = n.strip().lstrip("*.")
                if n and n.endswith(root) and n != root:
                    names.add(n)
        return sorted(names)[:15]
    except Exception:
        return []


async def _detect_tech_hints(client: httpx.AsyncClient, host: str) -> list:
    """Kök sayfadan hızlı teknoloji tahmini (Server/X-Powered-By/başlık/gövde imzaları) →
    pathprobe'un framework-özel yol setini açar (Laravel/Next.js/WordPress...). Böylece
    manuel tarama da otonom motor kadar 'hedefin teknolojisine göre büyüyen katalog' kullanır.
    Tespit başarısızsa boş liste (yalnız statik katalog problanır — regresyon yok)."""
    fp = await _http_fingerprint(client, host)
    hints: list = []
    blob = " ".join(str(fp.get(k, "")) for k in ("server", "x_powered_by", "title")).lower()
    # Gövdeden de birkaç imza (cookie/asset yolu) yakala.
    try:
        base = fp.get("base_url")
        if base:
            r = await client.get(base + "/", timeout=6.0)
            blob += " " + r.text[:4096].lower()
            cookies = " ".join(r.headers.get_list("set-cookie")).lower() if hasattr(r.headers, "get_list") else str(r.headers.get("set-cookie", "")).lower()
            blob += " " + cookies
    except Exception:
        pass
    # İmza → teknoloji etiketi (pathprobe _paths_for_tech ile eşleşen anahtarlar).
    _SIGNS = {
        "laravel": ["laravel", "laravel_session"],
        "wordpress": ["wp-content", "wp-json", "wordpress"],
        "next": ["_next/", "__next", "next.js"],
        "symfony": ["symfony", "sf_redirect"],
        "django": ["csrftoken", "django"],
        "node": ["express", "x-powered-by: express"],
        "spring": ["spring", "jsessionid"],
        "tomcat": ["tomcat", "apache-coyote"],
    }
    for tech, needles in _SIGNS.items():
        if any(n in blob for n in needles):
            hints.append(tech)
    return hints


@router.post("/path-probe")
async def run_path_probe(request: PathProbeRequest):
    """
    Tek bir host'ta hassas yol taraması çalıştır (senkron, hızlı — genel bütçe kalkanlı).
    UI'daki domain chip aksiyonu buraya gelir; sonuçlar doğrudan döner VE Mongo'ya
    (redteam_scans) kalıcı yazılır ki geriye dönük görülebilsin.
    """
    from pipeline.path_probe import probe_sensitive_paths

    host = _normalize_target(request.target)
    logger.info(f"🧭 RedTeam path-probe tetiklendi: {host}")
    try:
        # Teknoloji tahmini → framework-özel yollar (Laravel .env.backup/laravel.log vb.).
        tech_hints: list = []
        try:
            async with httpx.AsyncClient(
                verify=False, follow_redirects=True, timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0 (compatible; KadimGuvenlik/1.0; +security-audit)"},
            ) as c:
                tech_hints = await _detect_tech_hints(c, host)
        except Exception:
            pass  # teknoloji tespiti opsiyonel — statik katalog yine problanır

        # K2/K3 — EKLEMELİ zekâ (flag arkasında; kapalıyken canlı probe bugünküyle aynı).
        extra_paths: list = []
        mem_col = _memory_collection()
        if os.getenv("PATHPROBE_MEMORY", "0") == "1" and mem_col is not None:
            try:
                from pipeline.path_memory import load_learned_paths
                extra_paths += load_learned_paths(mem_col, tech_hints)
            except Exception as e:
                logger.warning(f"RedTeam path-probe hafıza yüklenemedi: {e}")
        if os.getenv("PATHPROBE_LLM_INTEL", "0") == "1":
            try:
                from pipeline.path_intel import suggest_paths_llm
                extra_paths += await suggest_paths_llm({"target": host, "tech_hints": tech_hints or []})
            except Exception as e:
                logger.warning(f"RedTeam path-probe LLM önerisi alınamadı: {e}")

        # reveal=True → HAM (maskesiz) snippet döndür (kanıtlama). DB'ye yine maskeli yazılır.
        result = await probe_sensitive_paths(host, timeout=5.0, concurrency=12,
                                             redact=not request.reveal,
                                             tech_hints=tech_hints or None,
                                             extra_paths=extra_paths or None)
    except Exception as e:
        logger.error(f"PathProbe hatası ({host}): {e}")
        raise HTTPException(status_code=500, detail=f"Tarama hatası: {e}")

    # --- KALICI KAYIT: geriye dönük görülebilsin (redteam_scans) ---
    # ÖNEMLİ: yanıt maskesiz (reveal) olsa bile DB'ye MASKELİ yazılır — kalıcı depoda ham
    # parola tutmak istemeyiz. reveal modunda findings ham snippet taşır; DB için maskele.
    findings = result.get("findings") or []
    db_findings = findings
    if request.reveal:
        from pipeline.path_probe import _redact_snippet
        db_findings = []
        for f in findings:
            g = dict(f)
            g["snippet"] = _redact_snippet(g.get("path", ""), g.get("snippet", "") or "")
            g["redacted"] = True
            db_findings.append(g)
    _persist_redteam_scan({
        "_id": str(uuid.uuid4()),
        "kind": "path_probe",
        "target": host,
        "created_at": datetime.utcnow(),
        "base_url": result.get("base_url"),
        "probed": result.get("probed"),
        "partial": result.get("partial", False),
        "tech_hints": tech_hints,
        "revealed_in_ui": bool(request.reveal),  # denetim izi: bu tarama maskesiz mi görüntülendi
        "severity_counts": result.get("severity_counts") or {},
        "finding_count": len(db_findings),
        "findings": db_findings,   # DAİMA maskeli (kalıcı depo güvenliği)
        "source": "manual_redteam_ui",
    })

    # K3 — ÖĞRENME: UI taraması da doğrulanan yolları kalıcı hafızaya beslesin (best-effort).
    if os.getenv("PATHPROBE_MEMORY", "0") == "1" and mem_col is not None and findings:
        try:
            from pipeline.path_memory import record_findings
            record_findings(mem_col, findings, host, techs=tech_hints)
        except Exception as e:
            logger.warning(f"RedTeam path-probe hafızaya yazılamadı: {e}")
    return result


@router.post("/learn-path")
async def learn_path(request: LearnPathRequest):
    """Manuel bir hassas yolu KALICI hafızaya ekle (K3). 'Başkası buldu, biz bulamadık'
    boşluğunu sistematik kapatır: bu andan sonra her tarama bu yolu proplar. scan_memories
    koleksiyonuna yazılır; db yoksa 503. Ham sır gövdesi TUTULMAZ — yalnız yol + imza."""
    col = _memory_collection()
    if col is None:
        raise HTTPException(status_code=503, detail="Kalıcı depo devre dışı (db yok)")
    path = (request.path or "").strip()
    if not path.startswith("/") or "://" in path or " " in path or len(path) > 256:
        raise HTTPException(status_code=422, detail="Geçersiz yol (/ ile başlamalı, host içermemeli)")
    try:
        from pipeline.path_memory import learn_path_manual
        doc = learn_path_manual(
            col, path, request.category, request.severity,
            signature=request.signature, validator=request.validator, tech=request.tech,
        )
    except Exception as e:
        logger.error(f"learn-path yazılamadı ({path}): {e}")
        raise HTTPException(status_code=500, detail=f"Kayıt hatası: {e}")
    logger.info(f"🧠 Manuel öğrenilmiş yol eklendi: {path} (tech={request.tech or 'global'})")
    return {"status": "learned", "path": path,
            "scope": "global" if not request.tech else request.tech,
            "id": doc.get("_id")}


def _memory_collection():
    """Öğrenilmiş yol hafızası koleksiyonu (scan_memories); db yoksa None."""
    if _mongo_db is not None:
        return _mongo_db["scan_memories"]
    return None


@router.get("/scans")
async def list_redteam_scans(target: str = "", limit: int = 50):
    """
    Kayıtlı red-team taramalarını (path-probe / analyze) geriye dönük listele.
    Opsiyonel `target` ile tek host'a filtrele. En yeni önce.
    """
    col = _redteam_collection()
    if col is None:
        return {"scans": [], "count": 0, "note": "kalıcı depo devre dışı (db yok)"}
    query = {}
    if target:
        query["target"] = _normalize_target(target)
    try:
        # Liste görünümü hafif olsun: findings gövdesini değil, özeti döndür.
        cursor = col.find(query, {"findings": 0}).sort("created_at", -1).limit(min(limit, 200))
        scans = []
        for d in cursor:
            d["id"] = str(d.pop("_id", ""))
            if isinstance(d.get("created_at"), datetime):
                d["created_at"] = d["created_at"].isoformat()
            scans.append(d)
        return {"scans": scans, "count": len(scans)}
    except Exception as e:
        logger.error(f"Red-team kayıt listesi hatası: {e}")
        raise HTTPException(status_code=500, detail=f"Liste hatası: {e}")


@router.get("/scans/{scan_id}")
async def get_redteam_scan(scan_id: str):
    """Tek bir red-team tarama kaydının tam detayını (findings dahil) döndür."""
    col = _redteam_collection()
    if col is None:
        raise HTTPException(status_code=404, detail="Kalıcı depo devre dışı")
    try:
        d = col.find_one({"_id": scan_id})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kayıt okuma hatası: {e}")
    if not d:
        raise HTTPException(status_code=404, detail="Kayıt bulunamadı")
    d["id"] = str(d.pop("_id", ""))
    if isinstance(d.get("created_at"), datetime):
        d["created_at"] = d["created_at"].isoformat()
    return d


@router.post("/analyze")
async def redteam_analyze(request: RedTeamAnalyzeRequest):
    """
    Hedef için hızlı yüzey snapshot'ı toplar ve AI red-team analizi üretir.

    Akış: DNS → HTTP parmak izi → hassas yol probu → crt.sh subdomain.
    Snapshot her durumda döner; LLM analizi erişilemezse `ai_error` alanı
    dolar ama deterministik bulgular kaybolmaz (motor felsefesi).
    """
    host = _normalize_target(request.target)
    logger.info(f"🤖 RedTeam analizi tetiklendi: {host}")

    snapshot: dict = {"target": host, "kind": "redteam_surface_snapshot"}

    # DNS çözümleme (blocking socket'i thread'e at)
    try:
        import asyncio
        snapshot["resolved_ip"] = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.gethostbyname(host)
        )
    except Exception:
        snapshot["resolved_ip"] = None

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10.0,
        headers={"User-Agent": "Mozilla/5.0 (compatible; KadimGuvenlik/1.0; +security-audit)"},
    ) as client:
        snapshot["http"] = await _http_fingerprint(client, host)

        if request.include_probe:
            from pipeline.path_probe import probe_sensitive_paths
            probe = await probe_sensitive_paths(host)
            snapshot["sensitive_path_scan"] = {
                "probed": probe.get("probed"),
                "severity_counts": probe.get("severity_counts"),
                "findings": probe.get("findings"),
                "note": probe.get("note"),
            }
        if request.include_subdomains:
            snapshot["known_subdomains"] = await _crtsh_subdomains(client, host)

    # --- AI red-team analizi (opsiyonel sezgi katmanı — kritik yol değil) ---
    ai_result = None
    ai_error = None
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(
                f"{AI_SERVICE_URL}/analyze",
                json={
                    "scan_data": snapshot,
                    "provider": "ollama",   # use_default=True ile DB/.env varsayılanı çözer
                    "model": "",
                    "analysis_type": "redteam",
                    "use_default": True,
                },
            )
            if resp.status_code == 200:
                ai_result = resp.json()
            else:
                ai_error = f"AI service HTTP {resp.status_code}"
    except Exception as e:
        ai_error = str(e)
        logger.warning(f"RedTeam AI analizi erişilemez ({host}): {e}")

    # --- KALICI KAYIT: analyze sonucu da geriye dönük görülebilsin ---
    sps = snapshot.get("sensitive_path_scan") or {}
    _persist_redteam_scan({
        "_id": str(uuid.uuid4()),
        "kind": "analyze",
        "target": host,
        "created_at": datetime.utcnow(),
        "resolved_ip": snapshot.get("resolved_ip"),
        "http": snapshot.get("http"),
        "severity_counts": sps.get("severity_counts") or {},
        "finding_count": len(sps.get("findings") or []),
        "findings": sps.get("findings") or [],   # snippet'ler maskeli
        "known_subdomains": snapshot.get("known_subdomains") or [],
        "ai_risk": (ai_result or {}).get("risk_score") if isinstance(ai_result, dict) else None,
        "ai_error": ai_error,
        "source": "manual_redteam_ui",
    })

    return {
        "target": host,
        "snapshot": snapshot,
        "ai": ai_result,
        "ai_error": ai_error,
    }
