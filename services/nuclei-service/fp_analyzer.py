"""
Nuclei False Positive Analyzer - Akıllı FP Tespit Motoru
Türkçe: Nuclei bulgularını analiz ederek false positive olasılığını hesaplar

Özellikler:
- Response pattern analizi (404, login page vs gerçek zafiyet)
- Template güvenilirlik skorlaması
- MongoDB'den geçmiş FP istatistikleri
"""

import os
import re
import logging
from typing import Dict, Optional, List, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

# Türkçe: MongoDB bağlantısı için pymongo
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False

logger = logging.getLogger("nuclei-fp-analyzer")


class FPRiskLevel(Enum):
    """Türkçe: False Positive risk seviyeleri"""
    LOW = "low"           # Güvenilir bulgu
    MEDIUM = "medium"     # Dikkatli incelenmeli
    HIGH = "high"         # Muhtemelen FP
    VERY_HIGH = "very_high"  # Büyük ihtimalle FP


@dataclass
class FPAnalysisResult:
    """Türkçe: FP analiz sonucu"""
    fp_score: float           # 0.0 - 1.0 arası, yüksek = FP olasılığı yüksek
    risk_level: FPRiskLevel
    reasons: List[str]        # Neden FP olabileceğinin açıklamaları
    is_potential_fp: bool     # fp_score > 0.7 ise True
    template_reliability: float  # Template güvenilirlik skoru
    historical_fp_rate: Optional[float]  # Geçmiş FP oranı


class FPAnalyzer:
    """
    Türkçe: False Positive Analyzer
    
    Her Nuclei bulgusu için FP olasılığını hesaplar.
    MongoDB'den geçmiş istatistikleri kullanır.
    """
    
    # Türkçe: Bilinen FP üreten pattern'ler
    HIGH_FP_PATTERNS = [
        # Generic error pages
        (r"404|not found|page not found", 0.3, "404 sayfası tespit edildi"),
        (r"403|forbidden|access denied", 0.25, "403 erişim engeli sayfası"),
        (r"500|internal server error", 0.2, "500 hata sayfası"),
        
        # Login/Auth pages (sık FP kaynağı)
        (r"login|signin|sign in|authenticate", 0.15, "Login sayfası tespit edildi"),
        (r"password|şifre|parola", 0.1, "Şifre alanı içeren sayfa"),
        
        # Generic teknoloji tespitleri
        (r"powered by|running on|version", 0.1, "Generic versiyon bilgisi"),
        
        # WAF/CDN tespitleri
        (r"cloudflare|akamai|fastly|incapsula", 0.4, "CDN/WAF tespit edildi"),
        
        # Default pages
        (r"welcome to nginx|apache.*default|iis.*default", 0.35, "Default kurulum sayfası"),
        (r"it works|test page|under construction", 0.3, "Test/yapım sayfası"),
    ]
    
    # Türkçe: Güvenilir template kaynakları
    TRUSTED_TEMPLATE_SOURCES = [
        "projectdiscovery",
        "pdteam", 
        "nuclei-templates/cves",
        "nuclei-templates/vulnerabilities"
    ]
    
    # Türkçe: Düşük güvenilirlik gösteren template özellikleri
    LOW_RELIABILITY_INDICATORS = [
        "miscellaneous",
        "technologies",
        "panels",
        "exposed-panels",
        "fingerprint",
        "detect"
    ]
    
    # Türkçe: Yüksek güvenilirlik gösteren özellikler
    HIGH_RELIABILITY_INDICATORS = [
        "cve-",
        "rce",
        "sqli",
        "xss",
        "lfi",
        "rfi",
        "ssrf",
        "auth-bypass"
    ]
    
    def __init__(self, mongodb_uri: Optional[str] = None, database_name: str = "kadim_security"):
        """
        Türkçe: FP Analyzer başlatıcı
        
        Args:
            mongodb_uri: MongoDB bağlantı URI'si
            database_name: Veritabanı adı
        """
        self.db = None
        self.fp_stats_collection = None
        
        if mongodb_uri and MONGO_AVAILABLE:
            try:
                self.client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
                self.client.admin.command('ping')
                self.db = self.client[database_name]
                self.fp_stats_collection = self.db["fp_stats"]
                logger.info("✅ FP Analyzer MongoDB bağlantısı başarılı")
            except Exception as e:
                logger.warning(f"⚠️ MongoDB bağlantısı kurulamadı, offline mod: {e}")
    
    async def analyze_finding(self, finding: Dict[str, Any]) -> FPAnalysisResult:
        """
        Türkçe: Bir Nuclei bulgusunu analiz eder
        
        Args:
            finding: Nuclei JSON bulgusu (raw data)
            
        Returns:
            FPAnalysisResult: FP analiz sonucu
        """
        reasons = []
        fp_score = 0.0
        
        # 1. Template bilgilerini çıkar
        template_id = finding.get("template-id", "unknown")
        template_path = finding.get("template", "")
        info = finding.get("info", {})
        severity = info.get("severity", "info")
        matcher_name = finding.get("matcher-name", "")
        matched_at = finding.get("matched-at", "")
        response = finding.get("response", "")
        
        # 2. Template Güvenilirlik Skoru
        template_reliability = self._calculate_template_reliability(
            template_id, template_path, info
        )
        
        # 3. Response Pattern Analizi
        pattern_fp_score, pattern_reasons = self._analyze_response_patterns(
            response, matched_at
        )
        fp_score += pattern_fp_score
        reasons.extend(pattern_reasons)
        
        # 4. Severity Bazlı Düzeltme
        severity_modifier = self._get_severity_modifier(severity)
        fp_score += severity_modifier
        if severity_modifier > 0:
            reasons.append(f"Düşük severity ({severity}) - FP riski artırıldı")
        
        # 5. Matcher Analizi
        matcher_fp = self._analyze_matcher(matcher_name, info)
        fp_score += matcher_fp
        if matcher_fp > 0:
            reasons.append("Zayıf matcher pattern tespit edildi")
        
        # 6. Template Güvenilirlik Etkisi
        # Düşük güvenilirlik = yüksek FP riski
        reliability_impact = (1.0 - template_reliability) * 0.2
        fp_score += reliability_impact
        
        # 7. Geçmiş FP İstatistikleri (MongoDB'den)
        historical_fp_rate = await self._get_historical_fp_rate(template_id)
        if historical_fp_rate is not None:
            # Geçmişte FP oranı yüksekse, bu bulgu da muhtemelen FP
            fp_score += historical_fp_rate * 0.3
            if historical_fp_rate > 0.5:
                reasons.append(f"Bu template geçmişte %{int(historical_fp_rate*100)} FP üretmiş")
        
        # 8. Skoru normalize et (0.0 - 1.0 arası)
        fp_score = min(max(fp_score, 0.0), 1.0)
        
        # 9. Risk seviyesi belirle
        risk_level = self._determine_risk_level(fp_score)
        
        # 10. Potansiyel FP mi?
        is_potential_fp = fp_score > 0.7
        
        return FPAnalysisResult(
            fp_score=round(fp_score, 3),
            risk_level=risk_level,
            reasons=reasons,
            is_potential_fp=is_potential_fp,
            template_reliability=round(template_reliability, 3),
            historical_fp_rate=historical_fp_rate
        )
    
    def _calculate_template_reliability(
        self, 
        template_id: str, 
        template_path: str, 
        info: Dict
    ) -> float:
        """Türkçe: Template güvenilirlik skorunu hesapla (0.0 - 1.0)"""
        reliability = 0.5  # Başlangıç değeri
        
        template_lower = template_id.lower()
        path_lower = template_path.lower()
        
        # Güvenilir kaynak kontrolü
        for source in self.TRUSTED_TEMPLATE_SOURCES:
            if source in path_lower:
                reliability += 0.2
                break
        
        # Yüksek güvenilirlik göstergeleri
        for indicator in self.HIGH_RELIABILITY_INDICATORS:
            if indicator in template_lower:
                reliability += 0.15
                break
        
        # Düşük güvenilirlik göstergeleri
        for indicator in self.LOW_RELIABILITY_INDICATORS:
            if indicator in template_lower or indicator in path_lower:
                reliability -= 0.15
                break
        
        # CVE ID varsa güvenilirlik artır
        cve_refs = info.get("classification", {}).get("cve-id", [])
        if cve_refs:
            reliability += 0.2
        
        # Author kontrolü
        author = info.get("author", "")
        if isinstance(author, list):
            author = " ".join(author)
        if "projectdiscovery" in author.lower() or "pdteam" in author.lower():
            reliability += 0.1
        
        return min(max(reliability, 0.0), 1.0)
    
    def _analyze_response_patterns(
        self, 
        response: str, 
        matched_at: str
    ) -> tuple[float, List[str]]:
        """Türkçe: Response içeriğini FP pattern'leri için analiz et"""
        fp_score = 0.0
        reasons = []
        
        # Response + matched URL birleştir
        combined = f"{response} {matched_at}".lower()
        
        for pattern, score, reason in self.HIGH_FP_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                fp_score += score
                reasons.append(reason)
        
        return fp_score, reasons
    
    def _get_severity_modifier(self, severity: str) -> float:
        """Türkçe: Severity'ye göre FP risk modifiyeri"""
        modifiers = {
            "info": 0.2,      # Info bulgular genelde FP
            "low": 0.1,
            "medium": 0.0,
            "high": -0.1,     # High bulgular genelde güvenilir
            "critical": -0.15  # Critical bulgular çok güvenilir
        }
        return modifiers.get(severity.lower(), 0.0)
    
    def _analyze_matcher(self, matcher_name: str, info: Dict) -> float:
        """Türkçe: Matcher kalitesini analiz et"""
        fp_score = 0.0
        
        # Sadece status code matcher = yüksek FP riski
        if matcher_name and "status" in matcher_name.lower():
            fp_score += 0.15
        
        # Word + regex kombinasyonu = düşük FP riski
        # (Bu bilgi genelde template içinde, burada basit kontrol)
        
        return fp_score
    
    def _determine_risk_level(self, fp_score: float) -> FPRiskLevel:
        """Türkçe: FP skoruna göre risk seviyesi belirle"""
        if fp_score < 0.3:
            return FPRiskLevel.LOW
        elif fp_score < 0.5:
            return FPRiskLevel.MEDIUM
        elif fp_score < 0.7:
            return FPRiskLevel.HIGH
        else:
            return FPRiskLevel.VERY_HIGH
    
    async def _get_historical_fp_rate(self, template_id: str) -> Optional[float]:
        """Türkçe: MongoDB'den template'in geçmiş FP oranını getir"""
        if not self.fp_stats_collection:
            return None
        
        try:
            stats = self.fp_stats_collection.find_one({"template_id": template_id})
            if stats:
                total = stats.get("fp_count", 0) + stats.get("tp_count", 0)
                if total > 0:
                    return stats.get("fp_count", 0) / total
            return None
        except Exception as e:
            logger.error(f"FP stats sorgu hatası: {e}")
            return None
    
    async def mark_as_false_positive(self, template_id: str) -> bool:
        """
        Türkçe: Bir bulguyu false positive olarak işaretle
        MongoDB'de template istatistiklerini güncelle
        """
        if not self.fp_stats_collection:
            logger.warning("MongoDB bağlantısı yok, FP işaretleme atlandı")
            return False
        
        try:
            result = self.fp_stats_collection.update_one(
                {"template_id": template_id},
                {
                    "$inc": {"fp_count": 1},
                    "$set": {"last_updated": datetime.utcnow()}
                },
                upsert=True
            )
            logger.info(f"✅ Template FP olarak işaretlendi: {template_id}")
            return True
        except Exception as e:
            logger.error(f"FP işaretleme hatası: {e}")
            return False
    
    async def mark_as_true_positive(self, template_id: str) -> bool:
        """
        Türkçe: Bir bulguyu true positive (gerçek zafiyet) olarak işaretle
        """
        if not self.fp_stats_collection:
            return False
        
        try:
            result = self.fp_stats_collection.update_one(
                {"template_id": template_id},
                {
                    "$inc": {"tp_count": 1},
                    "$set": {"last_updated": datetime.utcnow()}
                },
                upsert=True
            )
            logger.info(f"✅ Template TP olarak işaretlendi: {template_id}")
            return True
        except Exception as e:
            logger.error(f"TP işaretleme hatası: {e}")
            return False
    
    async def get_template_stats(self, template_id: str) -> Optional[Dict]:
        """Türkçe: Template istatistiklerini getir"""
        if not self.fp_stats_collection:
            return None
        
        try:
            stats = self.fp_stats_collection.find_one({"template_id": template_id})
            if stats:
                total = stats.get("fp_count", 0) + stats.get("tp_count", 0)
                return {
                    "template_id": template_id,
                    "fp_count": stats.get("fp_count", 0),
                    "tp_count": stats.get("tp_count", 0),
                    "total": total,
                    "fp_rate": stats.get("fp_count", 0) / total if total > 0 else 0,
                    "last_updated": stats.get("last_updated")
                }
            return None
        except Exception as e:
            logger.error(f"Template stats sorgu hatası: {e}")
            return None


# Türkçe: Global analyzer instance (lazy init)
_analyzer_instance: Optional[FPAnalyzer] = None


def get_fp_analyzer(mongodb_uri: Optional[str] = None) -> FPAnalyzer:
    """Türkçe: FP Analyzer singleton instance döndür"""
    global _analyzer_instance
    
    if _analyzer_instance is None:
        # Environment'tan MongoDB URI'yi al
        if mongodb_uri is None:
            mongodb_uri = os.environ.get("MONGODB_URI")
        
        _analyzer_instance = FPAnalyzer(
            mongodb_uri=mongodb_uri,
            database_name=os.environ.get("MONGODB_DATABASE", "kadim_security")
        )
    
    return _analyzer_instance


async def analyze_and_enrich_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Türkçe: Convenience fonksiyon - Finding'i analiz et ve FP bilgisiyle zenginleştir
    
    Bu fonksiyon websocket_monitor'dan çağrılacak.
    
    Args:
        finding: Orijinal finding dict
        
    Returns:
        Zenginleştirilmiş finding dict (fp_analysis eklendi)
    """
    analyzer = get_fp_analyzer()
    result = await analyzer.analyze_finding(finding)
    
    # Finding'e FP analiz sonuçlarını ekle
    finding["fp_analysis"] = {
        "fp_score": result.fp_score,
        "risk_level": result.risk_level.value,
        "is_potential_fp": result.is_potential_fp,
        "reasons": result.reasons,
        "template_reliability": result.template_reliability,
        "historical_fp_rate": result.historical_fp_rate
    }
    
    return finding
