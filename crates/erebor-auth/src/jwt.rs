use chrono::{Duration, Utc};
use erebor_common::{EreborError, Result, UserId};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,       // user_id
    pub exp: i64,          // expiration
    pub iat: i64,          // issued at
    pub jti: String,       // unique token id
    pub providers: Vec<String>, // linked auth providers
}

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl JwtManager {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            access_ttl: Duration::minutes(15),
            refresh_ttl: Duration::days(30),
        }
    }

    pub fn issue_access_token(&self, user_id: &UserId, providers: &[String]) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.0.to_string(),
            exp: (now + self.access_ttl).timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            providers: providers.to_vec(),
        };
        let mut header = Header::default();
        header.alg = Algorithm::HS256;
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| EreborError::AuthError(format!("JWT encode failed: {e}")))
    }

    pub fn issue_refresh_token(&self, user_id: &UserId) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.0.to_string(),
            exp: (now + self.refresh_ttl).timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            providers: vec![],
        };
        let mut header = Header::default();
        header.alg = Algorithm::HS256;
        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| EreborError::AuthError(format!("JWT encode failed: {e}")))
    }

    pub fn verify(&self, token: &str) -> Result<TokenData<Claims>> {
        let mut validation = Validation::default();
        validation.algorithms = vec![Algorithm::HS256];
        decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| EreborError::InvalidToken(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_roundtrip() {
        let mgr = JwtManager::new(b"test-secret-key-at-least-32-bytes!");
        let user_id = UserId::new();
        let token = mgr.issue_access_token(&user_id, &["google".into()]).unwrap();
        let decoded = mgr.verify(&token).unwrap();
        assert_eq!(decoded.claims.sub, user_id.0.to_string());
        assert_eq!(decoded.claims.providers, vec!["google"]);
    }

    #[test]
    fn test_jwt_expired() {
        let mgr = JwtManager {
            encoding_key: EncodingKey::from_secret(b"test-secret"),
            decoding_key: DecodingKey::from_secret(b"test-secret"),
            access_ttl: Duration::seconds(-120), // already expired (past leeway)
            refresh_ttl: Duration::days(30),
        };
        let user_id = UserId::new();
        let token = mgr.issue_access_token(&user_id, &[]).unwrap();
        assert!(mgr.verify(&token).is_err());
    }

    #[test]
    fn test_jwt_invalid_signature() {
        let mgr1 = JwtManager::new(b"secret-one-at-least-32-bytes!!!!");
        let mgr2 = JwtManager::new(b"secret-two-at-least-32-bytes!!!!");
        let user_id = UserId::new();
        let token = mgr1.issue_access_token(&user_id, &[]).unwrap();
        assert!(mgr2.verify(&token).is_err());
    }

    #[test]
    fn test_refresh_token() {
        let mgr = JwtManager::new(b"test-secret-key-at-least-32-bytes!");
        let user_id = UserId::new();
        let token = mgr.issue_refresh_token(&user_id).unwrap();
        let decoded = mgr.verify(&token).unwrap();
        assert_eq!(decoded.claims.sub, user_id.0.to_string());
    }
}
