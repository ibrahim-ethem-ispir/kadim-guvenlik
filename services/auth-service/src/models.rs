use serde::{Deserialize, Serialize};
use mongodb::bson::oid::ObjectId;
use chrono::{DateTime, Utc};

// Türkçe: Varsayılan olarak kullanıcıları aktif kabul et (eski kayıtlar için backward compatibility)
fn default_active() -> bool { true }

// Türkçe: Esnek tarih formatı (Hem String hem BSON Date destekler)
mod flexible_date {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use chrono::{DateTime, Utc};
    use mongodb::bson::DateTime as BsonDateTime;

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bson_date = BsonDateTime::from(*date);
        serde::Serialize::serialize(&bson_date, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use mongodb::bson::Bson;
        
        let bson_val = Bson::deserialize(deserializer)?;
        match bson_val {
            Bson::DateTime(dt) => Ok(dt.to_chrono()),
            Bson::String(s) => {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .or_else(|_| {
                         // Fallback for %Y-%m-%dT%H:%M:%S%.fZ format
                         DateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.fZ")
                            .map(|dt| dt.with_timezone(&Utc))
                    })
                    .or_else(|_| {
                        // Fallback for simple date format if necessary
                        DateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                           .map(|dt| dt.with_timezone(&Utc))
                   })
                    .map_err(serde::de::Error::custom)
            },
            Bson::Int64(ts) => {
                 // Handle timestamp (milliseconds)
                 let seconds = ts / 1000;
                 let nanoseconds = ((ts % 1000) * 1_000_000) as u32;
                 DateTime::from_timestamp(seconds, nanoseconds)
                     .map(|dt| dt.with_timezone(&Utc))
                     .ok_or_else(|| serde::de::Error::custom("Invalid timestamp"))
            },
            _ => Err(serde::de::Error::custom(format!("Unexpected BSON type for date: {:?}", bson_val))),
        }
    }
}

// Option handler is needed because Option<T> with "with" attribute is tricky
mod flexible_date_option {
    use super::flexible_date;
    use serde::{self, Deserialize, Deserializer, Serializer};
    use chrono::{DateTime, Utc};

    pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            Some(dt) => flexible_date::serialize(dt, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "flexible_date")] DateTime<Utc>);

        let v = Option::deserialize(deserializer)?;
        Ok(v.map(|Wrapper(dt)| dt))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub username: String,
    pub password_hash: String,
    pub role: String, // "admin", "viewer"
    // Türkçe: Kullanıcı aktif mi? Pasif kullanıcılar giriş yapamaz
    #[serde(default = "default_active")]
    pub is_active: bool,
    #[serde(with = "flexible_date")]
    pub created_at: DateTime<Utc>,
    #[serde(default, with = "flexible_date_option")]
    pub last_login: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

// Türkçe: Admin paneli için kullanıcı yanıtı (password_hash olmadan)
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

// Türkçe: Kullanıcı güncelleme isteği
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub is_active: Option<bool>,
}

// Türkçe: Şifre değiştirme isteği (Admin tarafından)
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub new_password: String,
}


