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

