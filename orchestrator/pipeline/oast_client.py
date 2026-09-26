"""
Kadim Güvenlik — OAST (Out-of-Band Application Security Testing) Client
========================================================================
Türkçe: Bankacılık ve kurumsal sistemlerdeki asenkron çalışan arka plan servislerindeki
(Kafka, RabbitMQ, IBM MQ, batch worker'lar) KÖR (blind) zafiyetleri (Kör SSRF, Kör XXE,
Kör RCE / Log4j, DNS exfiltration) tespit edebilmek için callback dinleyicisi istemcisi.

Tasarım Prensipleri:
1. SAF ve DEGRADE-SAFE: Harici ağ bağlantısı yoksa, izole/offline test ortamındaysa
   veya OAST sunucusu kapalıysa ASLA motoru düşürmez (mock/fallback moduna geçer).
2. STANDART & UYUMLU: ProjectDiscovery Interactsh (veya özel self-hosted OAST sunucusu)
   protokolü ile uyumlu korelasyon token'ı üretir.
3. KORELASYON: Her tarama oturumu ve zafiyet adayı için benzersiz bir alt alan adı (subdomain)
   üretir: `{marker}-{token}.{oast_domain}`. Böylece gelen DNS/HTTP isteğinin hangi URL,
   hangi parametre ve hangi adımdan tetiklendiği kesinleşir.
"""

import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("oast-client")

# Çevresel değişkenler
OAST_ENABLED = os.getenv("OAST_ENABLED", "1") == "1"
# Varsayılan public interactsh sunucusu veya kurumsal self-hosted sunucu (örn: oast.kadim.local)
OAST_SERVER_URL = os.getenv("OAST_SERVER_URL", "https://oast.me")
OAST_DOMAIN = os.getenv("OAST_DOMAIN", "oast.me")
OAST_AUTH_TOKEN = os.getenv("OAST_AUTH_TOKEN", "")
OAST_POLL_INTERVAL_S = float(os.getenv("OAST_POLL_INTERVAL_S", "2.0"))


@dataclass
class OastInteraction:
    """OAST sunucusundan dönen geri arama (callback) kaydı."""
    protocol: str              # "dns" | "http" | "ldap" | "smtp"
    full_id: str               # "cwe918-a1b2c3d4"
    remote_address: str        # İsteği atan sunucunun IP adresi (gerçek backend IP'si!)
    timestamp: str
    raw_request: Optional[str] = None
    query_type: Optional[str] = None   # DNS için: A, AAAA, TXT
    marker: Optional[str] = None       # Hangi testten geldi: "ssrf", "xxe", "rce"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "full_id": self.full_id,
            "remote_address": self.remote_address,
            "timestamp": self.timestamp,
            "raw_request": self.raw_request,
            "query_type": self.query_type,
            "marker": self.marker,
        }


class OastClient:
    """
    OAST etkileşimlerini yöneten istemci sınıfı.
    """

    def __init__(
        self,
        session_id: str,
        server_url: str = OAST_SERVER_URL,
        oast_domain: str = OAST_DOMAIN,
        auth_token: str = OAST_AUTH_TOKEN,
        mock_mode: bool = False,
    ):
        self.session_id = session_id
        self.server_url = server_url.rstrip("/")
        self.oast_domain = oast_domain.lstrip(".")
        self.auth_token = auth_token
        self.mock_mode = mock_mode or not OAST_ENABLED
        self.registered_tokens: Dict[str, Dict[str, Any]] = {}
        # Yakalanan onaylı etkileşimler
        self.interactions: List[OastInteraction] = []
        # DEDUP: interactsh /poll cursor'suz olduğundan aynı etkileşimi ard arda dönebilir;
        # imza kümesiyle tekrarları eleriz (yoksa interactions_count + UI rozeti şişerdi).
        self._seen_sigs: set = set()
        # Mock modda test için simüle edilmiş geri aramalar
        self._mock_interactions: List[Dict[str, Any]] = []

    def generate_payload(self, marker: str = "oast", context: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
        """
        Benzersiz bir test token'ı ve tam OAST alan adı üretir.

        Returns:
            (token, fqdn): örn. ("ssrf-9f8e7d6c", "ssrf-9f8e7d6c.oast.me")
        """
        short_id = uuid.uuid4().hex[:10]
        token = f"{marker}-{short_id}".lower()
        fqdn = f"{token}.{self.oast_domain}"

        self.registered_tokens[token] = {
            "token": token,
            "fqdn": fqdn,
            "marker": marker,
            "context": context or {},
            "created_at": time.time(),
        }
        return token, fqdn

    def add_mock_interaction(
        self,
        token: str,
        protocol: str = "dns",
        remote_addr: str = "10.0.0.42",
        raw_req: Optional[str] = None,
    ):
        """İzole testler ve CI/CD için mock etkileşim ekler."""
        self._mock_interactions.append({
            "token": token,
            "protocol": protocol,
            "remote_address": remote_addr,
            "raw_request": raw_req,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    async def poll_interactions(self) -> List[OastInteraction]:
        """
        OAST sunucusunu sorgular ve kaydedilmiş token'larımıza gelen
        yeni DNS/HTTP etkileşimlerini toplar.
        """
        new_hits: List[OastInteraction] = []

        # 1. Mock mod kontrolü
        if self.mock_mode or not self.server_url:
            while self._mock_interactions:
                item = self._mock_interactions.pop(0)
                tok = item["token"]
                reg = self.registered_tokens.get(tok, {})
                interaction = OastInteraction(
                    protocol=item.get("protocol", "dns"),
                    full_id=tok,
                    remote_address=item.get("remote_address", "127.0.0.1"),
                    timestamp=item.get("timestamp", ""),
                    raw_request=item.get("raw_request"),
                    marker=reg.get("marker", "unknown"),
                )
                self.interactions.append(interaction)
                new_hits.append(interaction)
            return new_hits

        # 2. Gerçek Interactsh / OAST sunucusuna HTTP GET yoklaması
        # Standart interactsh-server HTTP API'si: GET /poll?id=...
        try:
            headers = {"User-Agent": "Kadim-OAST-Client/2.0"}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(
                    f"{self.server_url}/poll",
                    headers=headers,
                    params={"session": self.session_id},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    raw_list = data if isinstance(data, list) else data.get("data", [])
                    for item in raw_list:
                        full_id = item.get("full-id") or item.get("unique_id") or ""
                        # Token'larımızdan biriyle eşleşiyor mu?
                        matched_tok = next((t for t in self.registered_tokens if t in full_id), None)
                        if matched_tok:
                            # DEDUP: sunucu aynı etkileşimi tekrar dönebilir → imzayla ele.
                            # full-id (etkileşim başına benzersiz) + zaman + protokol + kaynak IP.
                            sig = (full_id, item.get("timestamp", ""),
                                   item.get("protocol", "dns"),
                                   item.get("remote-address", item.get("remote_ip", "")))
                            if sig in self._seen_sigs:
                                continue
                            self._seen_sigs.add(sig)
                            reg = self.registered_tokens[matched_tok]
                            interaction = OastInteraction(
                                protocol=item.get("protocol", "dns"),
                                full_id=matched_tok,
                                remote_address=item.get("remote-address", item.get("remote_ip", "")),
                                timestamp=item.get("timestamp", ""),
                                raw_request=item.get("raw-request"),
                                query_type=item.get("q-type"),
                                marker=reg.get("marker", "unknown"),
                            )
                            self.interactions.append(interaction)
                            new_hits.append(interaction)
        except Exception as e:
            logger.debug(f"OAST poll hatası (sessiz fallback): {e}")

        return new_hits

    def has_interaction_for(self, token: str) -> Optional[OastInteraction]:
        """Belirtilen token için yakalanmış bir etkileşim var mı?
        Önce poll edilmiş `interactions`'a, sonra henüz poll edilmemiş MOCK etkileşimlerine
        bakar — izole testlerde senkron callback tespiti için (üretimde gerçek callback
        asenkrondur; tur-sonu poll kanıtı yayınlar)."""
        for hit in self.interactions:
            if hit.full_id == token:
                return hit
        for item in self._mock_interactions:
            if item.get("token") == token:
                reg = self.registered_tokens.get(token, {})
                return OastInteraction(
                    protocol=item.get("protocol", "dns"),
                    full_id=token,
                    remote_address=item.get("remote_address", "127.0.0.1"),
                    timestamp=item.get("timestamp", ""),
                    raw_request=item.get("raw_request"),
                    marker=reg.get("marker", "unknown"),
                )
        return None

    def summary(self) -> Dict[str, Any]:
        """Tarama özeti için OAST metrikleri."""
        return {
            "enabled": not self.mock_mode and OAST_ENABLED,
            "mock_mode": self.mock_mode,
            "domain": self.oast_domain,
            "tokens_generated": len(self.registered_tokens),
            "interactions_count": len(self.interactions),
            "interactions": [i.to_dict() for i in self.interactions[-10:]],
        }
