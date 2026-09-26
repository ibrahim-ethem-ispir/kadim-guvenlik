//! # Relationship Model
//! 
//! Türkçe: Entity'ler arası ilişkiler için veri modeli.
//! Graf'taki edge'leri temsil eder.

use serde::{Deserialize, Serialize};
use mongodb::bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Türkçe: İlişki tipleri - Graf'taki edge tipleri
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Domain -> IP (DNS çözümleme)
    ResolvesTo,
    /// Domain -> Subdomain
    HasSubdomain,
    /// IP/Domain -> Port
    HasPort,
    /// Host -> Technology
    UsesTechnology,
    /// Host/Port -> Vulnerability
    HasVulnerability,
    /// Domain -> Organization (WHOIS'ten)
    BelongsTo,
    /// Domain -> Certificate
    HasCertificate,
    /// Domain -> DNS Record
    HasDnsRecord,
    /// IP -> ASN
    InAsn,
    /// IP -> NetBlock
    InNetBlock,
    /// Domain -> MX Domain (mail için)
    HasMailServer,
    /// Domain -> Nameserver
    HasNameserver,
    /// Email -> Domain
    EmailDomain,
    /// Person -> Organization
    WorksAt,
    /// Person -> Email
    HasEmail,
    /// URL -> Domain
    HostedOn,
    /// Generic ilişki
    RelatedTo,
}

impl RelationshipType {
    /// Türkçe: String olarak ilişki tipi
    pub fn as_str(&self) -> &'static str {
        match self {
            RelationshipType::ResolvesTo => "resolves_to",
            RelationshipType::HasSubdomain => "has_subdomain",
            RelationshipType::HasPort => "has_port",
            RelationshipType::UsesTechnology => "uses_technology",
            RelationshipType::HasVulnerability => "has_vulnerability",
            RelationshipType::BelongsTo => "belongs_to",
            RelationshipType::HasCertificate => "has_certificate",
            RelationshipType::HasDnsRecord => "has_dns_record",
            RelationshipType::InAsn => "in_asn",
            RelationshipType::InNetBlock => "in_netblock",
            RelationshipType::HasMailServer => "has_mail_server",
            RelationshipType::HasNameserver => "has_nameserver",
            RelationshipType::EmailDomain => "email_domain",
            RelationshipType::WorksAt => "works_at",
            RelationshipType::HasEmail => "has_email",
            RelationshipType::HostedOn => "hosted_on",
            RelationshipType::RelatedTo => "related_to",
        }
    }
    
    /// Türkçe: String'den ilişki tipi oluştur
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "resolves_to" => Some(RelationshipType::ResolvesTo),
            "has_subdomain" => Some(RelationshipType::HasSubdomain),
            "has_port" => Some(RelationshipType::HasPort),
            "uses_technology" => Some(RelationshipType::UsesTechnology),
            "has_vulnerability" => Some(RelationshipType::HasVulnerability),
            "belongs_to" => Some(RelationshipType::BelongsTo),
            "has_certificate" => Some(RelationshipType::HasCertificate),
            "has_dns_record" => Some(RelationshipType::HasDnsRecord),
            "in_asn" => Some(RelationshipType::InAsn),
            "in_netblock" => Some(RelationshipType::InNetBlock),
            "has_mail_server" => Some(RelationshipType::HasMailServer),
            "has_nameserver" => Some(RelationshipType::HasNameserver),
            "email_domain" => Some(RelationshipType::EmailDomain),
            "works_at" => Some(RelationshipType::WorksAt),
            "has_email" => Some(RelationshipType::HasEmail),
            "hosted_on" => Some(RelationshipType::HostedOn),
            "related_to" => Some(RelationshipType::RelatedTo),
            _ => None,
        }
    }
    
    /// Türkçe: Frontend için okunabilir etiket
    pub fn label(&self) -> &'static str {
        match self {
            RelationshipType::ResolvesTo => "Resolves To",
            RelationshipType::HasSubdomain => "Has Subdomain",
            RelationshipType::HasPort => "Has Port",
            RelationshipType::UsesTechnology => "Uses",
            RelationshipType::HasVulnerability => "Vulnerable To",
            RelationshipType::BelongsTo => "Belongs To",
            RelationshipType::HasCertificate => "Has Certificate",
            RelationshipType::HasDnsRecord => "Has Record",
            RelationshipType::InAsn => "In ASN",
            RelationshipType::InNetBlock => "In Network",
            RelationshipType::HasMailServer => "Mail Server",
            RelationshipType::HasNameserver => "Nameserver",
            RelationshipType::EmailDomain => "Domain",
            RelationshipType::WorksAt => "Works At",
            RelationshipType::HasEmail => "Has Email",
            RelationshipType::HostedOn => "Hosted On",
            RelationshipType::RelatedTo => "Related To",
        }
    }
    
    /// Türkçe: İlişki rengi (edge color)
    pub fn color(&self) -> &'static str {
        match self {
            RelationshipType::ResolvesTo => "#3b82f6",
            RelationshipType::HasSubdomain => "#6366f1",
            RelationshipType::HasPort => "#10b981",
            RelationshipType::UsesTechnology => "#8b5cf6",
            RelationshipType::HasVulnerability => "#ef4444",
            RelationshipType::BelongsTo => "#6b7280",
            RelationshipType::HasCertificate => "#22c55e",
            RelationshipType::HasDnsRecord => "#06b6d4",
            RelationshipType::InAsn => "#a855f7",
            RelationshipType::InNetBlock => "#f97316",
            RelationshipType::HasMailServer => "#f59e0b",
            RelationshipType::HasNameserver => "#14b8a6",
            RelationshipType::EmailDomain => "#f59e0b",
            RelationshipType::WorksAt => "#ec4899",
            RelationshipType::HasEmail => "#ec4899",
            RelationshipType::HostedOn => "#0ea5e9",
            RelationshipType::RelatedTo => "#9ca3af",
        }
    }
}

/// Türkçe: Entity ilişkisi - Graf'taki edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    /// MongoDB ObjectId
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    
    /// Kaynak entity ID
    pub source_entity_id: ObjectId,
    
    /// Hedef entity ID
    pub target_entity_id: ObjectId,
    
    /// İlişki tipi
    pub relationship_type: RelationshipType,
    
    /// İlişkiye özgü özellikler
    #[serde(default)]
    pub properties: HashMap<String, serde_json::Value>,
    
    /// Keşfedilme zamanı
    #[serde(default = "Utc::now")]
    pub discovered_at: DateTime<Utc>,
    
    /// Kaynak (hangi OSINT modülünden geldi)
    #[serde(default)]
    pub source: String,
}

impl Relationship {
    /// Türkçe: Yeni ilişki oluştur
    pub fn new(
        source_id: ObjectId,
        target_id: ObjectId,
        rel_type: RelationshipType,
        source: &str
    ) -> Self {
        Self {
            id: None,
            source_entity_id: source_id,
            target_entity_id: target_id,
            relationship_type: rel_type,
            properties: HashMap::new(),
            discovered_at: Utc::now(),
            source: source.to_string(),
        }
    }
    
    /// Türkçe: Özellik ekle
    pub fn with_property(mut self, key: &str, value: serde_json::Value) -> Self {
        self.properties.insert(key.to_string(), value);
        self
    }
    
    /// Türkçe: Frontend için JSON çıktısı (graph edge)
    pub fn to_graph_edge(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id.map(|id| id.to_hex()).unwrap_or_default(),
            "source": self.source_entity_id.to_hex(),
            "target": self.target_entity_id.to_hex(),
            "type": self.relationship_type.as_str(),
            "label": self.relationship_type.label(),
            "color": self.relationship_type.color(),
            "properties": &self.properties
        })
    }
}
