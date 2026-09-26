"""
Türkçe: Plugin Registry - Tarama servislerinin (plugin) tek kayıt noktası.

Amaç: Yeni bir tarama servisi eklemek için orchestrator'ı 5 ayrı yerden
düzenlemek yerine, sadece bu dosyadaki PLUGINS listesine tek bir satır eklemek
yeterli olsun. Her plugin'in URL'i eskisi gibi ortam değişkeninden (env)
okunur; sadece tanım tek noktaya toplandı.

Davranış NOTU: Bu registry mevcut davranışı DEĞİŞTİRMEZ. Her plugin için
`env` ve `default` değerleri, önceden main.py içindeki
`os.getenv("X_SERVICE_URL", "http://...")` satırlarıyla birebir aynıdır.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class PluginSpec:
    """Türkçe: Bir tarama plugin'inin (servisin) tanımı."""

    name: str                       # Benzersiz plugin adı (ör. "nmap")
    env: str                        # URL'i taşıyan ortam değişkeni (ör. "NMAP_SERVICE_URL")
    default_url: str                # env yoksa kullanılacak varsayılan URL
    category: str = "scanner"       # Gruplama: scanner / recon / intel / ai / util
    standard_contract: bool = False # Standart /scan, /status, /logs, /ws sözleşmesine uyuyor mu?
    capabilities: List[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        """Türkçe: Çalışma zamanındaki HTTP taban URL'i (env > default)."""
        return os.getenv(self.env, self.default_url)

    @property
    def ws_url(self) -> str:
        """Türkçe: WebSocket taban URL'i (http -> ws)."""
        return self.url.replace("http://", "ws://").replace("https://", "wss://")


# =============================================================================
# PLUGIN KAYITLARI
# Yeni servis eklemek için: buraya tek bir PluginSpec satırı ekle. Hepsi bu kadar.
# default_url değerleri eski main.py satırlarıyla BİREBİR aynı tutulmuştur.
# =============================================================================
_PLUGIN_LIST: List[PluginSpec] = [
    PluginSpec("nmap", "NMAP_SERVICE_URL", "http://nmap-service:8001",
               category="scanner", standard_contract=True,
               capabilities=["scan", "logs", "config", "validate", "preview"]),
    PluginSpec("subfinder", "SUBFINDER_SERVICE_URL", "http://subfinder-service:8010",
               category="recon", standard_contract=True,
               capabilities=["scan", "logs", "active-scans"]),
    PluginSpec("rustscan", "RUSTSCAN_SERVICE_URL", "http://rustscan-service:8002",
               category="scanner", standard_contract=True,
               capabilities=["scan", "logs", "active-scans"]),
    PluginSpec("nuclei", "NUCLEI_SERVICE_URL", "http://nuclei-service:8003",
               category="scanner", standard_contract=True,
               capabilities=["scan", "logs", "templates", "active-scans"]),
    PluginSpec("osint", "OSINT_SERVICE_URL", "http://osint-service:8005",
               category="intel", standard_contract=False,
               capabilities=["graph", "history"]),
    PluginSpec("hash_cracker", "HASH_CRACKER_SERVICE_URL", "http://hash-cracker:8006",
               category="util", standard_contract=False,
               capabilities=["crack"]),
    PluginSpec("recon", "RECON_SERVICE_URL", "http://recon-service:8004",
               category="recon", standard_contract=False,
               capabilities=["recon"]),
    PluginSpec("ai", "AI_SERVICE_URL", "http://ai-service:8009",
               category="ai", standard_contract=False,
               capabilities=["analyze", "chat", "report"]),
    PluginSpec("fuzz", "FUZZ_SERVICE_URL", "http://fuzz-service:8011",
               category="scanner", standard_contract=False,
               capabilities=["fuzz"]),
]

# Türkçe: İsim -> PluginSpec hızlı erişim tablosu
PLUGINS: Dict[str, PluginSpec] = {p.name: p for p in _PLUGIN_LIST}


def get(name: str) -> Optional[PluginSpec]:
    """Türkçe: İsimle plugin getirir (yoksa None)."""
    return PLUGINS.get(name)


def url(name: str) -> str:
    """Türkçe: İsimle plugin URL'i getirir. Bilinmeyen plugin hata verir."""
    spec = PLUGINS.get(name)
    if spec is None:
        raise KeyError(f"Bilinmeyen plugin: {name}")
    return spec.url


def standard_plugins() -> List[PluginSpec]:
    """Türkçe: Standart sözleşmeye uyan plugin'ler (generic proxy için — Faz 2)."""
    return [p for p in _PLUGIN_LIST if p.standard_contract]


def health_targets() -> List[tuple[str, str]]:
    """Türkçe: (isim, url) çiftleri - toplu health-check için."""
    return [(p.name, p.url) for p in _PLUGIN_LIST]
