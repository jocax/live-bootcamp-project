
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use jsonwebtoken::errors::ErrorKind;
use serde::{Deserialize, Serialize};
use crate::BannedTokenStoreType;
use crate::domain::types::Email;
use super::constants::JWT_COOKIE_NAME;
use super::constants::JWT_SECRET;

///
/// Read: https://crates.io/crates/jsonwebtoken
///

// Create cookie with a new JWT auth token
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>, GenerateTokenError> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Create cookie and set the value to the passed-in token string
fn create_auth_cookie(token: String) -> Cookie<'static> {
    let cookie = Cookie::build((JWT_COOKIE_NAME, token))
        .path("/") // apple cookie to all URLs on the server
        .http_only(true) // prevent JavaScript from accessing the cookie
        .same_site(SameSite::Lax) // send cookie with "same-site" requests, and with "cross-site" top-level navigations.
        .build();

    cookie
}

#[derive(Debug)]
pub enum GenerateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    UnexpectedError,
}

// This value determines how long the JWT auth token is valid for
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Create JWT auth token
fn generate_auth_token(email: &Email) -> Result<String, GenerateTokenError> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .ok_or(GenerateTokenError::UnexpectedError)?;

    // Create JWT expiration time
    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError)?
        .timestamp();

    // Cast exp to a usize, which is what Claims expects
    let exp: usize = exp
        .try_into()
        .map_err(|_| GenerateTokenError::UnexpectedError)?;

    let sub = email.as_ref().to_owned();

    let claims = Claims { sub, exp };

    create_token(&claims).map_err(GenerateTokenError::TokenError)
}

// Check if JWT auth token is valid by decoding it using the JWT secret and check against the banned token store
pub async fn validate_token(token: &str, banned_token_store: &BannedTokenStoreType) -> Result<Claims, jsonwebtoken::errors::Error> {
    // First, decode the token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;

    // Then check if it's banned
    let banned_store = banned_token_store.read().await;
    let is_banned = banned_store.is_banned(token).await
        .map_err(|_| jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))?;

    if is_banned {
        return Err(jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken));
    }

    Ok(token_data.claims)
}

// Create JWT auth token by encoding claims using the JWT secret
fn create_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use chrono::Duration;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use tokio::sync::RwLock;
    use crate::services::HashMapBannedTokenStore;

    fn create_test_token(exp_hours: i64) -> String {
        let claims = Claims {
            sub: "test@example.com".to_string(),
            exp: (Utc::now() + Duration::hours(exp_hours)).timestamp() as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        )
            .unwrap()
    }

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::try_from("test@example.com".to_owned()).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::try_from("test@example.com".to_owned()).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::try_from("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let banned_store: BannedTokenStoreType = Arc::new(RwLock::new(HashMapBannedTokenStore::new()));

        let result = validate_token(&token, &banned_store).await.unwrap();
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid.token.here";
        let banned_store: BannedTokenStoreType = Arc::new(RwLock::new(HashMapBannedTokenStore::new()));
        let result = validate_token(&token, &banned_store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_expired_token() {
        let token = create_test_token(-1); // expired 1 hour ago
        let banned_store: BannedTokenStoreType = Arc::new(RwLock::new(HashMapBannedTokenStore::new()));

        let result = validate_token(&token, &banned_store).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), &ErrorKind::ExpiredSignature);
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::try_from("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let banned_store: BannedTokenStoreType = Arc::new(RwLock::new(HashMapBannedTokenStore::new()));

        // Ban the token
        {
            let mut store = banned_store.write().await;
            store.ban_with_ttl(&token, Duration::hours(1)).await.unwrap();
        }

        // Try to validate the banned token
        let result = validate_token(&token, &banned_store).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), &ErrorKind::InvalidToken);
    }

    #[tokio::test]
    async fn test_validate_token_banned_but_expired_ban() {
        let email = Email::try_from("test@example.com".to_owned()).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let banned_store: BannedTokenStoreType = Arc::new(RwLock::new(HashMapBannedTokenStore::new()));

        // Ban the token with zero duration (immediately expired ban)
        {
            let mut store = banned_store.write().await;
            store.ban_with_ttl(&token, Duration::seconds(0)).await.unwrap();
        }

        // Wait a tiny bit to ensure ban is expired
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Token should validate successfully since ban is expired
        let result = validate_token(&token, &banned_store).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "test@example.com");
    }
}
