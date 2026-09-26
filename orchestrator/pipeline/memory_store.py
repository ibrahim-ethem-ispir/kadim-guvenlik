"""Vektör hafıza (Qdrant) — SAF çekirdek.

Amaç: `scan_memories` derslerini, `Evidence` bulgularını ve payload-ailelerini
embedding olarak saklayıp SEMANTİK benzerlikle geri getirmek. Motor bunu yalnız
skor SİNYALİ olarak kullanır (curiosity/novelty girdisi) — karar yine graf+kuralda.

Doktrin uyumu:
- Best-effort: Qdrant kapalı / embedding modeli tanımsız / flag kapalı → her çağrı
  sessiz no-op, tarama ETKİLENMEZ (diğer prob'larla aynı sözleşme).
- Ağ çağrısı import anında YOK; ilk kullanımda tembel bağlantı.
- Varsayılan KAPALI (VECTOR_MEMORY_ENABLED=0): embedding dış API maliyeti üretir.

Payload şeması (tek koleksiyon `kadim_vektor`, filtre HNSW içinde çalışır):
  {kind, target, tech, severity, title, text, session_id, ts}
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vektor_hafiza")

COLLECTION = os.getenv("VECTOR_COLLECTION", "kadim_vektor")
# Tekrar deneme spamini önle: bağlantı bir kez başarısız olursa bu süre boyunca devre dışı.
_RETRY_COOLDOWN_SANIYE = 60


def _flag_acik() -> bool:
    return os.getenv("VECTOR_MEMORY_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on", "evet")


def _embed_base_url() -> Optional[str]:
    """OpenAI-uyumlu /embeddings kökü. Sıralama: açık config > deepseek > ollama."""
    base = os.getenv("VECTOR_EMBED_BASE_URL", "").strip()
    if not base:
        ds = os.getenv("DEEPSEEK_BASE_URL", "").strip()
        if ds and os.getenv("DEEPSEEK_API_KEY", "").strip():
            base = ds.rstrip("/") + "/v1"
    if not base:
        oll = os.getenv("OLLAMA_URL", "").strip()
        if oll:
            base = oll.rstrip("/") + "/v1"  # Ollama OpenAI-uyumlu uç sunar
    return base or None


def _deterministik_id(text: str, kind: str) -> str:
    # Aynı ders iki kez yazılmasın (upsert idempotent olsun) diye içerik-hash'i.
    return hashlib.sha256(f"{kind}::{text}".encode("utf-8", "ignore")).hexdigest()


class VektorHafiza:
    """Qdrant istemci sarmalayıcı — tüm metotlar hata yutar, asla fırlatmaz."""

    def __init__(self) -> None:
        self._client: Any = None
        self._http: Any = None
        self._boyut: Optional[int] = None
        self._devre_disi_neden: Optional[str] = None
        self._sonraki_deneme: float = 0.0

    # --- yaşam döngüsü -------------------------------------------------
    @property
    def aktif(self) -> bool:
        return _flag_acik() and bool(os.getenv("VECTOR_EMBED_MODEL", "").strip())

    def _istemci(self) -> Any:
        if not self.aktif:
            self._devre_disi_neden = "flag kapalı veya VECTOR_EMBED_MODEL tanımsız"
            return None
        if time.time() < self._sonraki_deneme:
            return None
        if self._client is not None:
            return self._client
        try:
            from qdrant_client import QdrantClient  # tembel import: bağımlılık yoksa modül yine yüklenir

            url = os.getenv("QDRANT_URL", "http://qdrant:6333")
            self._client = QdrantClient(url=url, timeout=5)
            self._client.get_collections()  # hızlı sağlık yoklaması
            self._devre_disi_neden = None
            logger.info("vektör hafıza bağlandı: %s", url)
        except Exception as exc:  # Qdrant yok/ağır → cooldown, motor sürer
            self._client = None
            self._sonraki_deneme = time.time() + _RETRY_COOLDOWN_SANIYE
            self._devre_disi_neden = f"qdrant erişilemedi: {exc}"
            logger.warning("vektör hafıza devre dışı (%s) — tarama etkilenmez", self._devre_disi_neden)
        return self._client

    def _embed(self, texts: List[str]) -> Optional[List[List[float]]]:
        """OpenAI-uyumlu /embeddings. Hata → None (çağıran no-op'a düşer)."""
        try:
            import httpx

            base = _embed_base_url()
            model = os.getenv("VECTOR_EMBED_MODEL", "").strip()
            if not base or not model:
                return None
            headers = {"Content-Type": "application/json"}
            key = os.getenv("DEEPSEEK_API_KEY", "").strip() or os.getenv("EMBED_API_KEY", "").strip()
            if key:
                headers["Authorization"] = f"Bearer {key}"
            resp = httpx.post(
                f"{base}/embeddings",
                json={"model": model, "input": texts},
                headers=headers,
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data") or []
            vectors = [d.get("embedding") for d in data]
            if not vectors or any(v is None for v in vectors):
                return None
            return vectors
        except Exception as exc:
            logger.warning("embedding üretilemedi: %s", exc)
            return None

    def _koleksiyon_hazirla(self, boyut: int) -> bool:
        try:
            client = self._istemci()
            if client is None:
                return False
            adlar = {c.name for c in client.get_collections().collections}
            if COLLECTION not in adlar:
                from qdrant_client.models import Distance, VectorParams

                client.create_collection(
                    collection_name=COLLECTION,
                    vectors_config=VectorParams(size=boyut, distance=Distance.COSINE),
                )
                logger.info("koleksiyon oluşturuldu: %s (dim=%d)", COLLECTION, boyut)
            self._boyut = boyut
            return True
        except Exception as exc:
            logger.warning("koleksiyon hazırlanamadı: %s", exc)
            return False

    # --- yazma ---------------------------------------------------------
    def kaydet(self, kind: str, text: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """Tek anı/bulgu kaydet. kind: memory|evidence|payload. Idempotent."""
        if not self.aktif or not text.strip():
            return False
        vectors = self._embed([text])
        if not vectors:
            return False
        vec = vectors[0]
        if self._boyut is None and not self._koleksiyon_hazirla(len(vec)):
            return False
        if self._boyut and len(vec) != self._boyut:
            # Model değişmiş → eski vektörlerle karşılaştırma anlamsız; atla.
            logger.warning("embedding boyutu değişti (%d != %s) — kayıt atlandı", len(vec), self._boyut)
            return False
        try:
            from qdrant_client.models import PointStruct

            body: Dict[str, Any] = {"kind": kind, "text": text[:2000], "ts": int(time.time())}
            if payload:
                body.update({k: v for k, v in payload.items() if k not in ("kind", "text")})
            self._istemci().upsert(
                collection_name=COLLECTION,
                points=[PointStruct(id=_deterministik_id(text, kind), vector=vec, payload=body)],
            )
            return True
        except Exception as exc:
            logger.warning("vektör kaydı başarısız: %s", exc)
            return False

    def toplu_kaydet(self, kind: str, items: List[Dict[str, Any]]) -> int:
        """items: [{text, ...payload}] — tek embedding çağrısında batch."""
        items = [i for i in items if str(i.get("text", "")).strip()]
        if not self.aktif or not items:
            return 0
        vectors = self._embed([str(i["text"])[:2000] for i in items])
        if not vectors or len(vectors) != len(items):
            return 0
        if self._boyut is None and not self._koleksiyon_hazirla(len(vectors[0])):
            return 0
        try:
            from qdrant_client.models import PointStruct

            points = []
            for item, vec in zip(items, vectors):
                body: Dict[str, Any] = {"kind": kind, "ts": int(time.time())}
                body.update({k: v for k, v in item.items()})
                body["text"] = str(body.get("text", ""))[:2000]
                points.append(
                    PointStruct(id=_deterministik_id(str(item["text"]), kind), vector=vec, payload=body)
                )
            self._istemci().upsert(collection_name=COLLECTION, points=points)
            return len(points)
        except Exception as exc:
            logger.warning("toplu vektör kaydı başarısız: %s", exc)
            return 0

    # --- okuma ---------------------------------------------------------
    def benzer_ara(
        self,
        text: str,
        kind: Optional[str] = None,
        filtre: Optional[Dict[str, Any]] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Semantik benzerlik + payload filtresi (Qdrant filtrelemeyi HNSW içinde yapar).

        Dönüş: [{score, ...payload}] — boş liste = 'bulunamadı' (asla exception yok).
        """
        if not self.aktif or not text.strip():
            return []
        vectors = self._embed([text])
        if not vectors:
            return []
        try:
            client = self._istemci()
            if client is None:
                return []
            must = []
            if kind:
                from qdrant_client.models import FieldCondition, MatchValue

                must.append(FieldCondition(key="kind", match=MatchValue(value=kind)))
            for key, value in (filtre or {}).items():
                from qdrant_client.models import FieldCondition, MatchValue

                must.append(FieldCondition(key=key, match=MatchValue(value=value)))
            query_filter = None
            if must:
                from qdrant_client.models import Filter

                query_filter = Filter(must=must)
            hits = client.query_points(
                collection_name=COLLECTION,
                query=vectors[0],
                query_filter=query_filter,
                limit=limit,
                with_payload=True,
            ).points
            out = []
            for h in hits:
                row = dict(h.payload or {})
                row["score"] = float(h.score)
                out.append(row)
            return out
        except Exception as exc:
            # Koleksiyon henüz yok vb. → sessiz boş sonuç, motor sürer.
            logger.debug("benzer_ara başarısız (yutuldu): %s", exc)
            return []


# Süreç başına tek örnek (Mongo singleton konvansiyonuyla aynı ruh).
_hafiza: Optional[VektorHafiza] = None


def vektor_hafiza() -> VektorHafiza:
    global _hafiza
    if _hafiza is None:
        _hafiza = VektorHafiza()
    return _hafiza


# --- Motor/pipeline için üst-seviye yardımcılar -------------------------------
# Bunlar SAF kalır: flag kapalı/servis yoksa boş sonuç — çağıran taraf try/except
# yazmak zorunda kalmaz (yine de best-effort sarmal önerilir).

# Geçmiş benzerlik eşiği: altındaki eşleşmeler "ders" sayılmaz (gürültü koruması).
MIN_SKOR = float(os.getenv("VECTOR_RECALL_MIN_SCORE", "0.55"))


def gecmis_dersleri_hatirla(target: str, techs: Optional[List[str]] = None,
                            limit: int = 5) -> List[str]:
    """Hedef+teknoloji profilinden SEMANTİK geçmiş ders üret (engine.memory_lessons'a girer).

    Field-journal (exploit_memory) aynı hedefin/kayıtlı desenlerin DÜZ METİN eşleşmesini
    yükler; bu fonksiyon onu TAMAMLAR: farklı hedefte bile benzer teknoloji/zafiyet
    sınıfında doğrulanmış bulguları getirir ('wordpress+wpbakery sqli başka hedefte
    çıkmıştı' → bu hedefte de aynı kenar erken öncelenir).
    """
    h = vektor_hafiza()
    if not h.aktif or not target:
        return []
    sorgu = " ".join([target] + list(techs or []))
    hits = h.benzer_ara(sorgu, limit=max(1, limit))
    dersler: List[str] = []
    for hit in hits:
        skor = float(hit.get("score") or 0.0)
        if skor < MIN_SKOR:
            continue
        metin = str(hit.get("text") or "")[:300]
        if not metin:
            continue
        kaynak = hit.get("target") or "?"
        dersler.append(f"[vektör-hafıza {skor:.2f}] geçmiş hedef {kaynak}: {metin}")
    return dersler


def bulgulari_hafizaya_yaz(scan_id: str, target: str, evidence_dicts: List[Dict[str, Any]]) -> int:
    """Tarama sonu: kanıtlanmış bulguları vektör koleksiyonuna bas (gelecek recall için).

    evidence_dicts: Evidence.to_dict() çıktıları. Başarısızlık 0 döner, exception YOK.
    """
    h = vektor_hafiza()
    if not h.aktif or not evidence_dicts:
        return 0
    items: List[Dict[str, Any]] = []
    for d in evidence_dicts:
        baslik = str(d.get("title") or "").strip()
        if not baslik:
            continue
        kanit = str(d.get("proof") or "")[:300]
        items.append({
            "text": f"{baslik} | {d.get('target') or target} | {d.get('severity') or ''} | {kanit}",
            "target": target,
            "severity": d.get("severity") or "info",
            "cve": d.get("cve") or "",
            "tool": d.get("tool") or "",
            "scan_id": scan_id,
            "verified": bool(d.get("verified")),
        })
    if not items:
        return 0
    return h.toplu_kaydet("evidence", items)
