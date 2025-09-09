use chrono::{DateTime, Duration, Utc};
use crate::domain::types::{Email};
use crate::domain::user::User;

#[cfg_attr(any(test), mockall::automock)]
#[async_trait::async_trait]
pub trait UserStore: Send + Sync + std::fmt::Debug {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    fn validate_user(&self, email: &Email, password: &str) -> Result<(), UserStoreError>;
}


#[derive(Debug, PartialEq, Default)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    #[default]
    UnexpectedError,
}


#[cfg_attr(any(test), mockall::automock)]
#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync + std::fmt::Debug {
    /// Add a token to the ban list until its natural expiration
    async fn ban_until_expiry(&mut self, token: &str, exp: usize) -> Result<(), BannedTokenStoreError>;

    /// Add a token with a specific TTL
    async fn ban_with_ttl(&mut self, token: &str, ttl: Duration) -> Result<(), BannedTokenStoreError>;

    /// Check if a token is banned
    async fn is_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError>;

    /// Check if a token is banned
    async fn get(&self, token: &str) -> Result<BannedTokenInfo, BannedTokenStoreError>;

}

#[derive(Debug, PartialEq, Default)]
pub enum BannedTokenStoreError {
    TokenNotValidAnymore,
    #[default]
    UnexpectedError,
}

#[derive(Debug, Clone)]
pub struct BannedTokenInfo {
    pub token: String,
    pub expires_at:  DateTime<Utc>,
    pub banned_at:  DateTime<Utc>,
    pub banned_exp:  DateTime<Utc>,
    pub banned_ttl:  DateTime<Utc>,
}

#[cfg_attr(any(test), mockall::automock)]
#[async_trait::async_trait]
pub trait Standard2FaStore: Send + Sync + std::fmt::Debug {

    // Store a new 2FA code (replaces any existing)
    async fn store_2fa_code(
        &mut self,
        email: &Email,
        code: String,
        ttl_seconds: u64,
    ) -> Result<String, Standard2FaError>; // Returns attempt_id

    // Verify and consume the 2FA code
    async fn verify_and_consume_2fa_code(
        &mut self,
        email: &Email,
        code: &str,
    ) -> Result<(), Standard2FaError>;

    // Check if user has an active 2FA code
    async fn has_active_2fa_code(
        &self,
        email: &Email,
    ) -> Result<Option<Standard2FaInfo>, Standard2FaError>;

}

#[derive(Debug, Clone)]
pub struct Standard2FaInfo {
    pub attempt_id: String,
    pub code_2fa: String,
    pub expires_at: DateTime<Utc>,
}


#[derive(Debug, PartialEq, Default)]
pub enum Standard2FaError {
    AlreadyExists,
    Expired,
    InvalidCode,
    NotFound,
    #[default]
    UnexpectedError,
}

