//! Hash Types Detection and Algorithm Support
//! 
//! Supports modern hash algorithms:
//! - MD5, SHA1, SHA256, SHA512 (legacy)
//! - SHA3-256, SHA3-512 (modern)
//! - BLAKE2b, BLAKE2s (modern, fast)
//! - BLAKE3 (ultra-modern, fastest)
//! - bcrypt, scrypt, Argon2 (password hashing)
//! - NTLM, MySQL5, LM (legacy Windows/DB)

use serde::{Deserialize, Serialize};
use regex::Regex;
use once_cell::sync::Lazy;

/// Detected hash information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInfo {
    pub hash_type: HashType,
    pub confidence: u8,
    pub description: String,
    pub security_level: SecurityLevel,
    pub crack_difficulty: CrackDifficulty,
    pub example_tools: Vec<String>,
    /// Uyarı mesajı - HMAC, salt, veya özel durumlar için
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Bu hash kırılabilir mi? (HMAC gibi keyed hash'ler için false)
    #[serde(default = "default_crackable")]
    pub is_crackable: bool,
}

fn default_crackable() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HashType {
    // Legacy (easily crackable)
    Md5,
    Sha1,
    Ntlm,
    Lm,
    MySql5,
    
    // Standard (moderate difficulty)
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    
    // Modern Fast (BLAKE family)
    Blake2b256,
    Blake2b512,
    Blake2s256,
    Blake3,
    
    // Password Hashing (hardened)
    Bcrypt,
    Scrypt,
    Argon2i,
    Argon2d,
    Argon2id,
    Pbkdf2Sha256,
    Pbkdf2Sha512,
    
    // Unknown
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    Broken,      // MD5, SHA1, LM - should never be used
    Weak,        // NTLM, MySQL5
    Moderate,    // SHA256, SHA512
    Strong,      // SHA3, BLAKE2/3
    Hardened,    // bcrypt, scrypt, Argon2
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrackDifficulty {
    Trivial,     // < 1 second with wordlist
    Easy,        // seconds to minutes
    Moderate,    // minutes to hours
    Hard,        // hours to days
    VeryHard,    // days to weeks
    Extreme,     // practically impossible
}

// Regex patterns for hash detection
static MD5_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]{32}$").unwrap());
static SHA1_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]{40}$").unwrap());
static SHA256_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]{64}$").unwrap());
static SHA512_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]{128}$").unwrap());
static BCRYPT_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$").unwrap());
static ARGON2_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$").unwrap());
static SCRYPT_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\$scrypt\$").unwrap());
static PBKDF2_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\$pbkdf2-sha(256|512)\$").unwrap());
static MYSQL5_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\*[A-Fa-f0-9]{40}$").unwrap());
static NTLM_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Fa-f0-9]{32}$").unwrap());
static BLAKE2B_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\$blake2b\$").unwrap());
static BLAKE3_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-fA-F0-9]{64}$").unwrap()); // Same as SHA256, needs context

/// Detect hash type from input string
pub fn detect_hash(input: &str) -> HashInfo {
    let input = input.trim();
    
    // Password hashing algorithms (with prefixes)
    if BCRYPT_PATTERN.is_match(input) {
        return HashInfo {
            hash_type: HashType::Bcrypt,
            confidence: 100,
            description: "bcrypt - Blowfish-based password hash".to_string(),
            security_level: SecurityLevel::Hardened,
            crack_difficulty: CrackDifficulty::VeryHard,
            example_tools: vec!["hashcat -m 3200".to_string(), "john --format=bcrypt".to_string()],
            warning: Some("🛡️ bcrypt güçlü bir algoritma, kırması çok uzun sürebilir.".to_string()),
            is_crackable: true,
        };
    }
    
    if ARGON2_PATTERN.is_match(input) {
        let variant = if input.contains("$argon2id$") {
            HashType::Argon2id
        } else if input.contains("$argon2d$") {
            HashType::Argon2d
        } else {
            HashType::Argon2i
        };
        return HashInfo {
            hash_type: variant,
            confidence: 100,
            description: "Argon2 - Password Hashing Competition winner (2015)".to_string(),
            security_level: SecurityLevel::Hardened,
            crack_difficulty: CrackDifficulty::Extreme,
            example_tools: vec!["hashcat -m 32xxx".to_string(), "john --format=argon2".to_string()],
            warning: Some("🛡️ Argon2 en güçlü parola hash algoritmasıdır. Kırmak pratik olarak imkansızdır.".to_string()),
            is_crackable: true,
        };
    }
    
    if SCRYPT_PATTERN.is_match(input) {
        return HashInfo {
            hash_type: HashType::Scrypt,
            confidence: 100,
            description: "scrypt - Memory-hard key derivation".to_string(),
            security_level: SecurityLevel::Hardened,
            crack_difficulty: CrackDifficulty::Extreme,
            example_tools: vec!["hashcat -m 8900".to_string(), "john --format=scrypt".to_string()],
            warning: Some("🛡️ scrypt memory-hard algoritma, kırmak çok zor.".to_string()),
            is_crackable: true,
        };
    }
    
    if PBKDF2_PATTERN.is_match(input) {
        let variant = if input.contains("sha512") {
            HashType::Pbkdf2Sha512
        } else {
            HashType::Pbkdf2Sha256
        };
        return HashInfo {
            hash_type: variant,
            confidence: 100,
            description: "PBKDF2 - Password-Based Key Derivation Function 2".to_string(),
            security_level: SecurityLevel::Hardened,
            crack_difficulty: CrackDifficulty::Hard,
            example_tools: vec!["hashcat -m 10900".to_string(), "john --format=pbkdf2-hmac-sha256".to_string()],
            warning: Some("🛡️ PBKDF2 iterasyon sayısına bağlı olarak kırması uzun sürebilir.".to_string()),
            is_crackable: true,
        };
    }
    
    // MySQL5 (starts with *)
    if MYSQL5_PATTERN.is_match(input) {
        return HashInfo {
            hash_type: HashType::MySql5,
            confidence: 95,
            description: "MySQL 5.x - SHA1(SHA1(password))".to_string(),
            security_level: SecurityLevel::Weak,
            crack_difficulty: CrackDifficulty::Easy,
            example_tools: vec!["hashcat -m 300".to_string(), "john --format=mysql-sha1".to_string()],
            warning: None,
            is_crackable: true,
        };
    }
    
    // Length-based detection
    let len = input.len();
    match len {
        32 => {
            // Could be MD5 or NTLM
            let is_uppercase = input.chars().all(|c| c.is_uppercase() || c.is_ascii_digit());
            if is_uppercase {
                HashInfo {
                    hash_type: HashType::Ntlm,
                    confidence: 70,
                    description: "NTLM - Windows NT hash (or MD5 uppercase)".to_string(),
                    security_level: SecurityLevel::Weak,
                    crack_difficulty: CrackDifficulty::Easy,
                    example_tools: vec!["hashcat -m 1000".to_string(), "john --format=nt".to_string()],
                    warning: None,
                    is_crackable: true,
                }
            } else {
                HashInfo {
                    hash_type: HashType::Md5,
                    confidence: 90,
                    description: "MD5 - Message Digest Algorithm 5 (BROKEN!)".to_string(),
                    security_level: SecurityLevel::Broken,
                    crack_difficulty: CrackDifficulty::Trivial,
                    example_tools: vec!["hashcat -m 0".to_string(), "john --format=raw-md5".to_string()],
                    warning: None,
                    is_crackable: true,
                }
            }
        }
        40 => HashInfo {
            hash_type: HashType::Sha1,
            confidence: 90,
            description: "SHA1 - Secure Hash Algorithm 1 (BROKEN!)".to_string(),
            security_level: SecurityLevel::Broken,
            crack_difficulty: CrackDifficulty::Trivial,
            warning: Some("⚠️ Bu hash HMAC-SHA1 olabilir. HMAC secret key ile oluşturulur ve key bilinmeden kırılamaz.".to_string()),
            is_crackable: true,
            example_tools: vec!["hashcat -m 100".to_string(), "john --format=raw-sha1".to_string()],
        },
        64 => HashInfo {
            hash_type: HashType::Sha256,
            confidence: 85, // Could also be BLAKE3, SHA3-256, or HMAC-SHA256
            description: "SHA256 / SHA3-256 / BLAKE3 / HMAC-SHA256 (64 char hex)".to_string(),
            security_level: SecurityLevel::Moderate,
            crack_difficulty: CrackDifficulty::Moderate,
            example_tools: vec!["hashcat -m 1400".to_string(), "john --format=raw-sha256".to_string()],
            warning: Some("⚠️ DİKKAT: Bu hash HMAC-SHA256 olabilir! HMAC hash'leri secret key ile oluşturulur ve secret key bilinmeden kırılamaz. Eğer hash bir API veya authentication sisteminden geliyorsa, büyük ihtimalle HMAC'tır.".to_string()),
            is_crackable: true, // Varsayılan olarak true, kullanıcı HMAC olduğunu söylerse false olacak
        },
        128 => HashInfo {
            hash_type: HashType::Sha512,
            confidence: 90,
            description: "SHA512 / SHA3-512 / BLAKE2b-512".to_string(),
            security_level: SecurityLevel::Strong,
            crack_difficulty: CrackDifficulty::Moderate,
            example_tools: vec!["hashcat -m 1700".to_string(), "john --format=raw-sha512".to_string()],
            warning: Some("⚠️ Bu hash HMAC-SHA512 olabilir. HMAC secret key ile oluşturulur.".to_string()),
            is_crackable: true,
        },
        _ => HashInfo {
            hash_type: HashType::Unknown,
            confidence: 0,
            description: "Unknown hash type".to_string(),
            security_level: SecurityLevel::Moderate,
            crack_difficulty: CrackDifficulty::Moderate,
            example_tools: vec![],
            warning: None,
            is_crackable: true,
        },
    }
}

/// Get all supported hash algorithms with descriptions
pub fn get_all_algorithms() -> Vec<AlgorithmInfo> {
    vec![
        // Legacy - BROKEN
        AlgorithmInfo {
            id: "md5".to_string(),
            name: "MD5".to_string(),
            category: "Legacy (Broken)".to_string(),
            length: 32,
            description: "Message Digest 5 - Cryptographically broken, vulnerable to collision attacks".to_string(),
            security_level: SecurityLevel::Broken,
            speed: "Ultra Fast (~10 GH/s GPU)".to_string(),
            use_cases: vec!["Legacy systems", "File checksums (non-security)", "Quick integrity checks"].iter().map(|s| s.to_string()).collect(),
            emoji: "💀".to_string(),
        },
        AlgorithmInfo {
            id: "sha1".to_string(),
            name: "SHA-1".to_string(),
            category: "Legacy (Broken)".to_string(),
            length: 40,
            description: "Secure Hash Algorithm 1 - Collision attacks demonstrated (SHAttered)".to_string(),
            security_level: SecurityLevel::Broken,
            speed: "Very Fast (~5 GH/s GPU)".to_string(),
            use_cases: vec!["Git commits", "Legacy certificates", "Old password storage"].iter().map(|s| s.to_string()).collect(),
            emoji: "⚠️".to_string(),
        },
        AlgorithmInfo {
            id: "ntlm".to_string(),
            name: "NTLM".to_string(),
            category: "Legacy (Weak)".to_string(),
            length: 32,
            description: "NT LAN Manager - Windows authentication hash, unsalted MD4".to_string(),
            security_level: SecurityLevel::Weak,
            speed: "Ultra Fast (~100 GH/s GPU)".to_string(),
            use_cases: vec!["Windows authentication", "Active Directory", "SAM database"].iter().map(|s| s.to_string()).collect(),
            emoji: "🪟".to_string(),
        },
        
        // Standard
        AlgorithmInfo {
            id: "sha256".to_string(),
            name: "SHA-256".to_string(),
            category: "Standard".to_string(),
            length: 64,
            description: "SHA-2 family, 256-bit output - Still secure but fast".to_string(),
            security_level: SecurityLevel::Moderate,
            speed: "Fast (~3 GH/s GPU)".to_string(),
            use_cases: vec!["Bitcoin mining", "TLS certificates", "File integrity"].iter().map(|s| s.to_string()).collect(),
            emoji: "🔐".to_string(),
        },
        AlgorithmInfo {
            id: "sha512".to_string(),
            name: "SHA-512".to_string(),
            category: "Standard".to_string(),
            length: 128,
            description: "SHA-2 family, 512-bit output - More secure, 64-bit optimized".to_string(),
            security_level: SecurityLevel::Moderate,
            speed: "Fast (~1 GH/s GPU)".to_string(),
            use_cases: vec!["Linux shadow passwords", "High-security checksums"].iter().map(|s| s.to_string()).collect(),
            emoji: "🔒".to_string(),
        },
        
        // Modern SHA-3 (Keccak)
        AlgorithmInfo {
            id: "sha3_256".to_string(),
            name: "SHA3-256".to_string(),
            category: "Modern (SHA-3)".to_string(),
            length: 64,
            description: "Keccak-based, NIST standard 2015 - Completely different structure from SHA-2".to_string(),
            security_level: SecurityLevel::Strong,
            speed: "Moderate (~500 MH/s GPU)".to_string(),
            use_cases: vec!["Ethereum", "Post-quantum preparation", "Modern applications"].iter().map(|s| s.to_string()).collect(),
            emoji: "🌟".to_string(),
        },
        
        // BLAKE Family (Modern & Fast)
        AlgorithmInfo {
            id: "blake2b".to_string(),
            name: "BLAKE2b".to_string(),
            category: "Modern (BLAKE)".to_string(),
            length: 128,
            description: "BLAKE2b-512 - Faster than MD5, more secure than SHA-3".to_string(),
            security_level: SecurityLevel::Strong,
            speed: "Very Fast (~2 GH/s GPU)".to_string(),
            use_cases: vec!["WireGuard VPN", "Zcash", "Password hashing base"].iter().map(|s| s.to_string()).collect(),
            emoji: "⚡".to_string(),
        },
        AlgorithmInfo {
            id: "blake3".to_string(),
            name: "BLAKE3".to_string(),
            category: "Ultra-Modern (2020)".to_string(),
            length: 64,
            description: "BLAKE3 (2020) - 5x faster than BLAKE2, parallelizable, tree hashing".to_string(),
            security_level: SecurityLevel::Strong,
            speed: "Ultra Fast (parallelized)".to_string(),
            use_cases: vec!["Modern file hashing", "KDF replacement", "Streaming verification"].iter().map(|s| s.to_string()).collect(),
            emoji: "🚀".to_string(),
        },
        
        // Password Hashing (Hardened)
        AlgorithmInfo {
            id: "bcrypt".to_string(),
            name: "bcrypt".to_string(),
            category: "Password Hashing".to_string(),
            length: 60,
            description: "Blowfish-based, adaptive cost factor - Industry standard for passwords".to_string(),
            security_level: SecurityLevel::Hardened,
            speed: "Intentionally Slow (~10 KH/s GPU)".to_string(),
            use_cases: vec!["User passwords", "Web applications", "Authentication systems"].iter().map(|s| s.to_string()).collect(),
            emoji: "🏰".to_string(),
        },
        AlgorithmInfo {
            id: "scrypt".to_string(),
            name: "scrypt".to_string(),
            category: "Password Hashing".to_string(),
            length: 0, // Variable
            description: "Memory-hard KDF - Resistant to ASIC/GPU attacks via memory usage".to_string(),
            security_level: SecurityLevel::Hardened,
            speed: "Very Slow (memory-bound)".to_string(),
            use_cases: vec!["Cryptocurrency (Litecoin)", "Key derivation", "Password storage"].iter().map(|s| s.to_string()).collect(),
            emoji: "💎".to_string(),
        },
        AlgorithmInfo {
            id: "argon2id".to_string(),
            name: "Argon2id".to_string(),
            category: "Password Hashing (Best)".to_string(),
            length: 0, // Variable
            description: "PHC Winner 2015 - Combines Argon2i + Argon2d, GPU/ASIC resistant, configurable memory/time".to_string(),
            security_level: SecurityLevel::Hardened,
            speed: "Extremely Slow (configurable)".to_string(),
            use_cases: vec!["Modern password hashing", "Key derivation", "Credential storage"].iter().map(|s| s.to_string()).collect(),
            emoji: "👑".to_string(),
        },
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmInfo {
    pub id: String,
    pub name: String,
    pub category: String,
    pub length: usize,
    pub description: String,
    pub security_level: SecurityLevel,
    pub speed: String,
    pub use_cases: Vec<String>,
    pub emoji: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_md5_detection() {
        let hash = "5d41402abc4b2a76b9719d911017c592";
        let info = detect_hash(hash);
        assert_eq!(info.hash_type, HashType::Md5);
    }
    
    #[test]
    fn test_bcrypt_detection() {
        let hash = "$2a$10$N9qo8uLOickgx2ZMRZoMye3/RDe.4TtIz5tBqX0DOJQFP7kq2fKqi";
        let info = detect_hash(hash);
        assert_eq!(info.hash_type, HashType::Bcrypt);
    }
    
    #[test]
    fn test_argon2_detection() {
        let hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
        let info = detect_hash(hash);
        assert_eq!(info.hash_type, HashType::Argon2id);
    }
}
