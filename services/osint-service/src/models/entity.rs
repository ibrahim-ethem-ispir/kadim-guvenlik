//! # Entity Model
//! 
//! Türkçe: OSINT entity'leri için veri modeli.
//! Domain, IP, Email, Technology, Port, Vulnerability gibi entity tipleri.

use serde::{Deserialize, Serialize};
use mongodb::bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Türkçe: Entity tipleri - Maltego'daki node tiplerinin karşılığı
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    /// Domain adı (example.com)
    Domain,
    /// Subdomain (sub.example.com)
    Subdomain,
    /// IP adresi (IPv4 veya IPv6)
    Ip,
    /// Email adresi
    Email,
    /// Teknoloji/Framework (React, Nginx, PHP)
    Technology,
    /// Açık port
    Port,
    /// Güvenlik açığı
    Vulnerability,
    /// Kişi
    Person,
    /// Organizasyon/Şirket
    Organization,
    /// SSL Sertifikası
    Certificate,
    /// DNS Kaydı
    DnsRecord,
    /// ASN (Autonomous System Number)
    Asn,
    /// Network bloğu (CIDR)
    NetBlock,
    /// URL
    Url,
    /// Hash değeri
    Hash,
    /// Dosya
    File,
}

impl EntityType {
    /// Türkçe: String olarak entity tipi
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::Domain => "domain",
            EntityType::Subdomain => "subdomain",
            EntityType::Ip => "ip",
            EntityType::Email => "email",
            EntityType::Technology => "technology",
            EntityType::Port => "port",
            EntityType::Vulnerability => "vulnerability",
            EntityType::Person => "person",
            EntityType::Organization => "organization",
            EntityType::Certificate => "certificate",
            EntityType::DnsRecord => "dns_record",
            EntityType::Asn => "asn",
            EntityType::NetBlock => "netblock",
            EntityType::Url => "url",
            EntityType::Hash => "hash",
            EntityType::File => "file",
        }
    }
    
    /// Türkçe: String'den entity tipi oluştur
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "domain" => Some(EntityType::Domain),
            "subdomain" => Some(EntityType::Subdomain),
            "ip" => Some(EntityType::Ip),
            "email" => Some(EntityType::Email),
            "technology" => Some(EntityType::Technology),
            "port" => Some(EntityType::Port),
            "vulnerability" => Some(EntityType::Vulnerability),
            "person" => Some(EntityType::Person),
            "organization" => Some(EntityType::Organization),
            "certificate" => Some(EntityType::Certificate),
            "dns_record" => Some(EntityType::DnsRecord),
            "asn" => Some(EntityType::Asn),
            "netblock" => Some(EntityType::NetBlock),
            "url" => Some(EntityType::Url),
            "hash" => Some(EntityType::Hash),
            "file" => Some(EntityType::File),
            _ => None,
        }
    }
    
    /// Türkçe: Frontend için ikon adı
    pub fn icon(&self) -> &'static str {
        match self {
            EntityType::Domain => "globe",
            EntityType::Subdomain => "git-branch",
            EntityType::Ip => "server",
            EntityType::Email => "mail",
            EntityType::Technology => "code",
            EntityType::Port => "plug",
            EntityType::Vulnerability => "alert-triangle",
            EntityType::Person => "user",
            EntityType::Organization => "building",
            EntityType::Certificate => "shield",
            EntityType::DnsRecord => "database",
            EntityType::Asn => "network",
            EntityType::NetBlock => "layers",
            EntityType::Url => "link",
            EntityType::Hash => "hash",
            EntityType::File => "file",
        }
    }
    
    /// Türkçe: Frontend için renk kodu
    pub fn color(&self) -> &'static str {
        match self {
            EntityType::Domain => "#3b82f6",      // blue
            EntityType::Subdomain => "#6366f1",   // indigo
            EntityType::Ip => "#10b981",          // emerald
            EntityType::Email => "#f59e0b",       // amber
            EntityType::Technology => "#8b5cf6",  // violet
            EntityType::Port => "#14b8a6",        // teal
            EntityType::Vulnerability => "#ef4444", // red
            EntityType::Person => "#ec4899",      // pink
            EntityType::Organization => "#6b7280", // gray
            EntityType::Certificate => "#22c55e", // green
            EntityType::DnsRecord => "#06b6d4",   // cyan
            EntityType::Asn => "#a855f7",         // purple
            EntityType::NetBlock => "#f97316",    // orange
            EntityType::Url => "#0ea5e9",         // sky
            EntityType::Hash => "#64748b",        // slate
            EntityType::File => "#78716c",        // stone
        }
    }
}

/// Türkçe: OSINT Entity - Graf'taki node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// MongoDB ObjectId
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// Entity tipi (domain, ip, email, vb.)
    pub entity_type: EntityType,
    
    /// Entity değeri (example.com, 1.2.3.4, user@example.com)
    pub value: String,
    
    /// Entity'ye özgü özellikler (JSON olarak)
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
    
    /// İlk görülme zamanı
    #[serde(default = "Utc::now")]
    pub first_seen: DateTime<Utc>,
    
    /// Son görülme/güncelleme zamanı
    #[serde(default = "Utc::now")]
    pub last_seen: DateTime<Utc>,
    
    /// Kaynak (hangi OSINT modülünden geldi)
    #[serde(default)]
    pub source: String,
    
    /// Güven skoru (0.0 - 1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    
    /// Etiketler
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_confidence() -> f64 {
    1.0
}

impl Entity {
    /// Türkçe: Yeni entity oluştur
    pub fn new(entity_type: EntityType, value: String, source: &str) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            entity_type,
            value,
            properties: HashMap::new(),
            first_seen: now,
            last_seen: now,
            source: source.to_string(),
            confidence: 1.0,
            tags: Vec::new(),
        }
    }
    
    /// Türkçe: Özellik ekle
    pub fn with_property(mut self, key: &str, value: serde_json::Value) -> Self {
        self.properties.insert(key.to_string(), value);
        self
    }
    
    /// Türkçe: Etiket ekle
    pub fn with_tag(mut self, tag: &str) -> Self {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
        self
    }
    
    /// Türkçe: Güven skoru ayarla
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
    
    /// Türkçe: Frontend için JSON çıktısı (graph node)
    pub fn to_graph_node(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id.map(|id| id.to_hex()).unwrap_or_default(),
            "type": self.entity_type.as_str(),
            "label": &self.value,
            "icon": self.entity_type.icon(),
            "color": self.entity_type.color(),
            "properties": &self.properties,
            "confidence": self.confidence,
            "tags": &self.tags
        })
    }
}

// ==================== DOMAIN ENTITY ÖZELLİKLERİ ====================

/// Türkçe: Domain entity özellikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainProperties {
    /// Kayıtlı olduğu registrar
    pub registrar: Option<String>,
    /// Kayıt tarihi
    pub created_date: Option<String>,
    /// Son güncelleme tarihi
    pub updated_date: Option<String>,
    /// Bitiş tarihi
    pub expiry_date: Option<String>,
    /// Name server'lar
    pub nameservers: Vec<String>,
    /// DNSSEC aktif mi
    pub dnssec: Option<bool>,
    /// Cloudflare arkasında mı
    pub behind_cloudflare: Option<bool>,
    /// Alexa rank
    pub alexa_rank: Option<u64>,
}

// ==================== IP ENTITY ÖZELLİKLERİ ====================

/// Türkçe: IP entity özellikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpProperties {
    /// IP versiyonu (4 veya 6)
    pub version: u8,
    /// Ülke kodu
    pub country_code: Option<String>,
    /// Ülke adı
    pub country: Option<String>,
    /// Şehir
    pub city: Option<String>,
    /// ISP/Hosting provider
    pub isp: Option<String>,
    /// ASN numarası
    pub asn: Option<String>,
    /// ASN organizasyonu
    pub asn_org: Option<String>,
    /// Reverse DNS
    pub rdns: Option<String>,
    /// Blacklist durumu
    pub blacklisted: Option<bool>,
    /// Risk skoru (0-100)
    pub risk_score: Option<u8>,
}

// ==================== PORT ENTITY ÖZELLİKLERİ ====================

/// Türkçe: Port entity özellikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortProperties {
    /// Port numarası
    pub port: u16,
    /// Protokol (tcp/udp)
    pub protocol: String,
    /// Servis adı
    pub service: Option<String>,
    /// Servis versiyonu
    pub version: Option<String>,
    /// Banner
    pub banner: Option<String>,
    /// Port durumu (open/closed/filtered)
    pub state: String,
}

// ==================== VULNERABILITY ENTITY ÖZELLİKLERİ ====================

/// Türkçe: Vulnerability entity özellikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityProperties {
    /// CVE ID
    pub cve_id: Option<String>,
    /// Zafiyet adı
    pub name: String,
    /// Açıklama
    pub description: Option<String>,
    /// Severity (critical/high/medium/low/info)
    pub severity: String,
    /// CVSS skoru
    pub cvss_score: Option<f32>,
    /// Etkilenen servis
    pub affected_service: Option<String>,
    /// Referanslar
    pub references: Vec<String>,
    /// Kaynak (nuclei, nikto, vb.)
    pub source_scanner: String,
}

// ==================== CERTIFICATE ENTITY ÖZELLİKLERİ ====================

/// Türkçe: SSL Certificate entity özellikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProperties {
    /// Subject CN
    pub subject_cn: String,
    /// Issuer
    pub issuer: String,
    /// Geçerlilik başlangıcı
    pub not_before: String,
    /// Geçerlilik sonu
    pub not_after: String,
    /// Sertifika süresi dolmuş mu
    pub expired: bool,
    /// Kalan gün sayısı
    pub days_until_expiry: Option<i64>,
    /// SAN (Subject Alternative Names)
    pub san: Vec<String>,
    /// Sertifika fingerprint
    pub fingerprint: Option<String>,
    /// Sertifika zinciri geçerli mi
    pub chain_valid: Option<bool>,
}

// ==================== TECHNOLOGY ENTITY ÖZELLİKLERİ ====================

/// Türkçe: Technology entity özellikleri
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyProperties {
    /// Teknoloji adı
    pub name: String,
    /// Kategori (CMS, Framework, Server, vb.)
    pub category: String,
    /// Versiyon
    pub version: Option<String>,
    /// Güvenilirlik (how confident)
    pub confidence: f64,
    /// Tespit yöntemi
    pub detection_method: Option<String>,
    /// Website
    pub website: Option<String>,
}
