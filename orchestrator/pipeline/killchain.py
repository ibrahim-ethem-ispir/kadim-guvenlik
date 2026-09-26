"""
Kadim Güvenlik — APT Kill-Chain Kompozisyonu (Faz 2)
=====================================================
Türkçe: İzole bulguları (servis, sürüm-CVE, ifşa, sır, erişim boşluğu) MITRE ATT&CK
taktiklerine eşleyip HEDEFE YÖNELEN bir saldırı zincirine dizer. Çıktı "alert listesi"
değil, gerçek bir APT aktörünün izleyeceği yol: Keşif → İlk Erişim → Yürütme →
Kimlik Erişimi → Yetki Yükseltme → Yanal Hareket → Etki.

Bu, "sektörün önüne geçme" katmanıdır: Stanford ARTEMIS dersi (en iyi AI ajanı bulguları
buldu ama zinciri kuramadı → kritik RCE'yi ıskaladı) tam da bu boşluğu işaret eder.

Tasarım: SAF çekirdek (I/O YOK) — normalize gözlem listesi girer, KillChain çıkar.
İzole test edilebilir (test_killchain.py). Karar motorunu BOZMAZ; graph.summary() bunu
raporlama/akıl-yürütme katmanı olarak çağırır. LLM yalnız anlatı zenginleştirir (opsiyonel).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ============================================================
# MITRE ATT&CK taktik zinciri (kill-chain sırası + etki ağırlığı)
# ============================================================
# Ağırlık zincirin SONUNA doğru artar: bir kimlik-erişimi/yanal-hareket kanıtı, bir
# keşif gözleminden çok daha "ilerlemiş" bir tehdittir. Zincir skoru bu ağırlıkla üretilir.
PHASE_ORDER: List[Tuple[str, str, float]] = [
    ("reconnaissance",       "TA0043", 1.0),
    ("initial-access",       "TA0001", 3.0),
    ("execution",            "TA0002", 3.5),
    ("credential-access",    "TA0006", 4.0),
    ("privilege-escalation", "TA0004", 4.5),
    ("lateral-movement",     "TA0008", 5.0),
    ("collection",           "TA0009", 4.0),
    ("impact",               "TA0040", 6.0),
]
_PHASE_WEIGHT = {name: w for name, _, w in PHASE_ORDER}
_PHASE_INDEX = {name: i for i, (name, _, _) in enumerate(PHASE_ORDER)}
_PHASE_TR = {
    "reconnaissance": "Keşif", "initial-access": "İlk Erişim", "execution": "Yürütme",
    "credential-access": "Kimlik Erişimi", "privilege-escalation": "Yetki Yükseltme",
    "lateral-movement": "Yanal Hareket", "collection": "Toplama", "impact": "Etki",
}

# Kanıt güç kademesi → zincir katkı çarpanı. Kanıtlanmış bir halka, doğrulanmamış bir
# halkadan çok daha gerçekçidir (APT gerçek yolu izler, tahmini değil).
_TIER_FACTOR = {"confirmed": 1.0, "probable": 0.7, "unconfirmed": 0.4}


@dataclass
class TTP:
    """Bir gözlemin ATT&CK eşlemesi."""
    tactic: str            # kill-chain fazı (PHASE_ORDER adı)
    technique_id: str      # "T1190"
    technique_name: str    # "Exploit Public-Facing Application"


@dataclass
class ChainLink:
    """Kill-chain'in tek bir halkası: bir faz + onu dolduran en güçlü gözlem."""
    phase: str
    technique_id: str
    technique_name: str
    title: str
    target: str
    confidence_tier: str
    contribution: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase, "phase_tr": _PHASE_TR.get(self.phase, self.phase),
            "technique_id": self.technique_id, "technique_name": self.technique_name,
            "title": self.title, "target": self.target,
            "confidence_tier": self.confidence_tier,
            "contribution": round(self.contribution, 2),
        }


@dataclass
class KillChain:
    """Kompoze edilmiş saldırı zinciri — raporun 'saldırı anlatısı' çekirdeği."""
    links: List[ChainLink] = field(default_factory=list)
    score: float = 0.0
    objective: str = ""          # ulaşılan en ileri faz (insan-okunur)
    reachable_impact: float = 0.0  # zincirin dokunduğu en yüksek varlık değeri
    narrative: str = ""
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "links": [l.to_dict() for l in self.links],
            "score": round(self.score, 2),
            "objective": self.objective,
            "reachable_impact": round(self.reachable_impact, 1),
            "narrative": self.narrative,
            "techniques": self.techniques,
            "depth": len(self.links),
        }


# ============================================================
# Gözlem → ATT&CK eşleme (SAF, kural tabanlı)
# ============================================================
# Gözlem normalize dict: {kind, tool, category, service, cwe(list/str), title, severity,
# confidence_tier, value, breach_prob, target, cve}. Kural sırası ÖNEMLİ (özelden genele).

def _cwe_nums(obs: Dict[str, Any]) -> set:
    cwe = obs.get("cwe") or []
    if not isinstance(cwe, list):
        cwe = [cwe]
    out = set()
    for c in cwe:
        digits = "".join(ch for ch in str(c) if ch.isdigit())
        if digits:
            out.add(digits)
    return out


def classify_ttp(obs: Dict[str, Any]) -> TTP:
    """Bir gözlemi ATT&CK (taktik, teknik) çiftine eşle. Eşleşmezse keşif (en zayıf faz)."""
    tool = str(obs.get("tool") or "").lower()
    cat = str(obs.get("category") or "").lower()
    svc = str(obs.get("service") or "").lower()
    title = str(obs.get("title") or "").lower()
    cves = _cwe_nums(obs)

    # 1) Zafiyet sınıfı (CWE en güvenilir)
    if "89" in cves:  # SQLi
        return TTP("execution", "T1190", "Exploit Public-Facing Application (SQLi)")
    if cves & {"94", "1336", "78", "77"}:  # RCE/SSTI/cmdi
        return TTP("execution", "T1059", "Command and Scripting Interpreter")
    if cves & {"98", "22"}:  # LFI / path traversal → dosya/sır okuma
        return TTP("credential-access", "T1552", "Unsecured Credentials (LFI)")
    if "79" in cves:  # XSS → istemci ele geçirme / oltalama
        return TTP("initial-access", "T1189", "Drive-by Compromise (XSS)")
    if "601" in cves:  # açık yönlendirme → oltalama
        return TTP("initial-access", "T1566", "Phishing (Open Redirect)")
    if "285" in cves or "access" in title:  # erişim kontrolü boşluğu
        return TTP("privilege-escalation", "T1548", "Abuse Elevation Control (Access Gap)")
    # --- T2/T3 sınıfları: IDOR/JWT/CORS/SSRF/XXE/GraphQL + forge-zinciri + K8s ---
    if tool == "k8s_probe" or "kubernetes" in title:
        # K8s kontrol-düzlemi ifşası → cluster sırları/kimlik (secret/kubelet/etcd).
        return TTP("credential-access", "T1552.007", "Container API Unsecured Credentials (K8s)")
    if tool == "exploit_chain" or "forged jwt" in title or "privilege escalation" in title:
        # Kırılan sır → forge → korumalı erişim: kill-chain'in DORUK escalation halkası.
        return TTP("privilege-escalation", "T1548", "Abuse Elevation Control (Forged Token Chain)")
    if cves & {"639", "284", "862", "863"} or tool == "idor_probe" or "object-level" in title:
        return TTP("privilege-escalation", "T1548", "Abuse Elevation Control (IDOR/BOLA)")
    if cves & {"347", "345"} or tool == "jwt_verify":  # zayıf/forge-edilebilir JWT
        return TTP("credential-access", "T1528", "Steal Application Access Token (JWT)")
    if "942" in cves or tool == "cors_verify":  # CORS → cross-origin oturum/veri hırsızlığı
        return TTP("credential-access", "T1539", "Steal Web Session Cookie (CORS)")
    if "918" in cves:  # SSRF → bulut metadata kimlik-bilgisi hırsızlığı
        return TTP("credential-access", "T1552.005", "Cloud Instance Metadata API (SSRF)")
    if "611" in cves:  # XXE → yerel dosya/sır okuma
        return TTP("credential-access", "T1552", "Unsecured Credentials (XXE File Read)")
    if tool == "graphql_intel" or "introspection" in title:  # şema ifşası = keşif
        return TTP("reconnaissance", "T1590", "Gather Victim Info (GraphQL Schema)")

    # 1.5) LLM red-teaming (MITRE ATLAS — adversarial ML). Prompt injection = model saldırgan
    # talimatını YÜRÜTÜR (execution); system-prompt sızıntısı = gizli talimat/sır (cred-access).
    if tool == "llm_redteam" or "prompt injection" in title or "atlas" in str(obs.get("atlas") or "").lower():
        if "system-prompt" in title or "system prompt" in title or "sızınt" in title:
            return TTP("credential-access", "AML.T0056", "LLM Meta Prompt Extraction")
        if "prompt injection" in title or "talimat ezme" in title:
            return TTP("execution", "AML.T0051", "LLM Prompt Injection")
        return TTP("reconnaissance", "AML.T0040", "LLM Feature Discovery")

    # 2) Kaynağa göre (tool)
    if tool in ("cve_intel",) or obs.get("cve"):
        return TTP("initial-access", "T1190", "Exploit Public-Facing Application (CVE)")
    if tool == "js_secret_scan" or "secret" in title or "api key" in title:
        return TTP("credential-access", "T1552.001", "Credentials In Files")
    if tool == "method_matrix":
        return TTP("privilege-escalation", "T1548", "Abuse Elevation Control (Method-Swap)")
    if tool == "pathprobe" or cat in ("exposure", "vcs_exposure"):
        if cat == "vcs_exposure" or ".git" in title or "secret" in title or ".env" in title:
            return TTP("credential-access", "T1552.001", "Credentials In Files (Exposure)")
        return TTP("initial-access", "T1190", "Exploit Public-Facing Application (Exposure)")

    # 3) Servis türüne göre (SERVICE gözlemleri)
    if cat == "database" or svc in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch"):
        return TTP("collection", "T1213", "Data from Information Repositories")
    if cat == "remote-mgmt" or svc in ("ssh", "rdp", "telnet", "smb", "openssh"):
        return TTP("lateral-movement", "T1021", "Remote Services")
    if cat == "mail-service" or svc in ("smtp", "imap", "pop3", "dovecot", "exim", "postfix"):
        return TTP("collection", "T1114", "Email Collection")
    if cat in ("admin-panel", "auth-endpoint") or "panel" in title or "login" in title:
        return TTP("credential-access", "T1110", "Brute Force (Auth Surface)")
    if cat == "dns-service" or svc in ("dns", "domain", "powerdns", "bind"):
        return TTP("reconnaissance", "T1590", "Gather Victim Network Information (DNS)")
    if cat in ("web-app", "network-service") or svc in ("apache", "nginx", "iis"):
        return TTP("initial-access", "T1190", "Exploit Public-Facing Application")
    if cat == "default-creds" or "default" in title and "cred" in title:
        return TTP("initial-access", "T1078", "Valid Accounts (Default Creds)")

    return TTP("reconnaissance", "T1595", "Active Scanning")


# ============================================================
# Kill-chain kompozisyonu (SAF)
# ============================================================

def _obs_weight(obs: Dict[str, Any]) -> float:
    """Bir gözlemin ham çekiciliği: değer × ihlal olasılığı (yoksa severity'den türet)."""
    val = obs.get("value")
    if not isinstance(val, (int, float)):
        val = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 8}.get(
            str(obs.get("severity") or "info").lower(), 8)
    bp = obs.get("breach_prob")
    if not isinstance(bp, (int, float)):
        bp = 0.5
    return float(val) * (0.4 + 0.6 * float(bp))  # olasılık 0 olsa bile değer tamamen sıfırlanmasın


def compose_killchain(observations: List[Dict[str, Any]]) -> KillChain:
    """Normalize gözlem listesinden EN GÜÇLÜ kill-chain'i kompoze et (SAF).

    Her ATT&CK fazı için en güçlü gözlemi seç (değer×olasılık×kademe-çarpanı), fazları
    kill-chain sırasına diz. Skor = Σ(faz_ağırlığı × halka_katkısı). Zincir ne kadar uzağa
    (yüksek faza) ulaşırsa ve halkalar ne kadar KANITLI ise skor o kadar yüksek."""
    if not observations:
        return KillChain(narrative="Kompoze edilecek gözlem yok.")

    best_per_phase: Dict[str, Tuple[float, ChainLink]] = {}
    max_impact = 0.0
    for obs in observations:
        ttp = classify_ttp(obs)
        tier = str(obs.get("confidence_tier") or "unconfirmed").lower()
        factor = _TIER_FACTOR.get(tier, 0.4)
        raw = _obs_weight(obs)
        contribution = raw * factor
        max_impact = max(max_impact, raw)
        link = ChainLink(
            phase=ttp.tactic, technique_id=ttp.technique_id,
            technique_name=ttp.technique_name,
            title=str(obs.get("title") or obs.get("service") or "gözlem"),
            target=str(obs.get("target") or ""),
            confidence_tier=tier, contribution=contribution,
        )
        cur = best_per_phase.get(ttp.tactic)
        if cur is None or contribution > cur[0]:
            best_per_phase[ttp.tactic] = (contribution, link)

    # Fazları kill-chain sırasına diz
    links = [best_per_phase[name][1]
             for name, _, _ in PHASE_ORDER if name in best_per_phase]
    score = sum(_PHASE_WEIGHT[l.phase] * l.contribution for l in links)
    # 0-100 ölçeğine kabaca normalize (yüksek uçları sıkıştır)
    score_norm = min(100.0, score / 10.0)

    # Ulaşılan en ileri faz = hedef
    objective_phase = max((l.phase for l in links), key=lambda p: _PHASE_INDEX[p]) if links else ""
    objective = _PHASE_TR.get(objective_phase, objective_phase)

    techniques = []
    for l in links:
        if l.technique_id not in techniques:
            techniques.append(l.technique_id)

    narrative = _build_narrative(links, objective, score_norm)

    return KillChain(links=links, score=score_norm, objective=objective,
                     reachable_impact=max_impact, narrative=narrative,
                     techniques=techniques)


def _build_narrative(links: List[ChainLink], objective: str, score: float) -> str:
    """İnsan-okunur APT saldırı anlatısı üret (rapor/UI için)."""
    if not links:
        return "Saldırı zinciri kurulamadı — kompoze edilecek kanıt yok."
    parts = []
    for i, l in enumerate(links, 1):
        tier_tr = {"confirmed": "kanıtlı", "probable": "olası",
                   "unconfirmed": "doğrulanmamış"}.get(l.confidence_tier, l.confidence_tier)
        parts.append(f"{i}. [{_PHASE_TR.get(l.phase, l.phase)} · {l.technique_id}] "
                     f"{l.title} ({tier_tr})")
    chain_txt = " → ".join(_PHASE_TR.get(l.phase, l.phase) for l in links)
    header = (f"Saldırı zinciri (skor {score:.0f}/100, hedef: {objective}): {chain_txt}. "
              f"Aşamalar:\n")
    return header + "\n".join(parts)
