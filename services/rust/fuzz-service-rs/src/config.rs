use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub mongodb_uri: String,
    pub mongodb_database: String,
    pub osint_database: String,
    pub wordlist_path: String,
    pub virustotal_api_key: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: env::var("PORT")
                .unwrap_or_else(|_| "8011".to_string())
                .parse()
                .unwrap_or(8011),
            mongodb_uri: env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://mongodb:27017".to_string()),
            mongodb_database: env::var("MONGODB_DATABASE")
                .unwrap_or_else(|_| "kadim_security".to_string()),
            osint_database: env::var("OSINT_DATABASE")
                .unwrap_or_else(|_| "kadim_osint".to_string()),
            wordlist_path: env::var("WORDLIST_PATH")
                .unwrap_or_else(|_| "/app/files".to_string()),
            virustotal_api_key: env::var("VIRUSTOTAL_API_KEY").ok(),
        }
    }
}
