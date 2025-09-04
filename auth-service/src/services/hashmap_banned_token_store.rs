use std::collections::HashMap;
use std::fmt::Debug;
use chrono::{DateTime, Duration, Utc};
use crate::domain::data_stores::{BannedTokenInfo, BannedTokenStore, BannedTokenStoreError};

pub struct HashMapBannedTokenStore {
    tokens: HashMap<String, BannedTokenInfo>,
}

impl Default for HashMapBannedTokenStore {
    fn default() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }
}

impl Debug for HashMapBannedTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HashMapBannedTokenStore {{ tokens: {:?} }}", self.tokens.len())
    }
}

impl HashMapBannedTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for HashMapBannedTokenStore {
    async fn ban_until_expiry(&mut self, token: &str, exp: usize) -> Result<(), BannedTokenStoreError> {
        let now = Utc::now();
        let expires_at = DateTime::<Utc>::from_timestamp(exp as i64, 0)
            .ok_or(BannedTokenStoreError::UnexpectedError)?;

        let banned_info = BannedTokenInfo {
            token: token.to_string(),
            expires_at,
            banned_at: now,
            banned_exp: expires_at,
            banned_ttl: expires_at,
        };

        self.tokens.insert(token.to_string(), banned_info);
        Ok(())
    }

    async fn ban_with_ttl(&mut self, token: &str, ttl: Duration) -> Result<(), BannedTokenStoreError> {
        let now = Utc::now();
        let expires_at = now + ttl;

        let banned_info = BannedTokenInfo {
            token: token.to_string(),
            expires_at,
            banned_at: now,
            banned_exp: expires_at,
            banned_ttl: expires_at,
        };

        self.tokens.insert(token.to_string(), banned_info);
        Ok(())
    }

    async fn is_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        if let Some(info) = self.tokens.get(token) {
            if Utc::now() < info.expires_at {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn get(&self, token: &str) -> Result<BannedTokenInfo, BannedTokenStoreError> {
        self.tokens
            .get(token)
            .cloned()
            .ok_or(BannedTokenStoreError::TokenNotValidAnymore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, Utc};

    #[tokio::test]
    async fn test_new_store_is_empty() {
        let store = HashMapBannedTokenStore::new();
        assert_eq!(store.tokens.len(), 0);
    }

    #[tokio::test]
    async fn test_ban_until_expiry_success() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "test_token_123";
        let exp = (Utc::now() + Duration::hours(1)).timestamp() as usize;

        let result = store.ban_until_expiry(token, exp).await;

        assert!(result.is_ok());
        assert_eq!(store.tokens.len(), 1);
        assert!(store.tokens.contains_key(token));
    }

    #[tokio::test]
    async fn test_ban_until_expiry_with_past_timestamp() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "expired_token";
        let exp = (Utc::now() - Duration::hours(1)).timestamp() as usize;

        let result = store.ban_until_expiry(token, exp).await;

        assert!(result.is_ok());
        assert_eq!(store.tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_ban_until_expiry_invalid_timestamp() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "invalid_token";
        let exp = i64::MAX as usize; // This should fail to convert to DateTime

        let result = store.ban_until_expiry(token, exp).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BannedTokenStoreError::UnexpectedError);
        assert_eq!(store.tokens.len(), 0);
    }

    #[tokio::test]
    async fn test_ban_with_ttl_success() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "ttl_token";
        let ttl = Duration::minutes(30);

        let before = Utc::now();
        let result = store.ban_with_ttl(token, ttl).await;
        let after = Utc::now();

        assert!(result.is_ok());
        assert_eq!(store.tokens.len(), 1);

        let info = store.tokens.get(token).unwrap();
        assert_eq!(info.token, token);
        assert!(info.banned_at >= before && info.banned_at <= after);
        assert!(info.expires_at > info.banned_at);
        assert_eq!(info.expires_at, info.banned_at + ttl);
    }

    #[tokio::test]
    async fn test_ban_with_zero_ttl() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "zero_ttl_token";
        let ttl = Duration::seconds(0);

        let result = store.ban_with_ttl(token, ttl).await;

        assert!(result.is_ok());
        let info = store.tokens.get(token).unwrap();
        assert_eq!(info.expires_at, info.banned_at);
    }

    #[tokio::test]
    async fn test_ban_with_negative_ttl() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "negative_ttl_token";
        let ttl = Duration::seconds(-3600);

        let result = store.ban_with_ttl(token, ttl).await;

        assert!(result.is_ok());
        let info = store.tokens.get(token).unwrap();
        assert!(info.expires_at < info.banned_at);
    }

    #[tokio::test]
    async fn test_is_banned_for_active_ban() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "active_token";
        let ttl = Duration::hours(1);

        store.ban_with_ttl(token, ttl).await.unwrap();

        let result = store.is_banned(token).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_is_banned_for_expired_ban() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "expired_token";

        // Manually insert an expired ban
        let expired_info = BannedTokenInfo {
            token: token.to_string(),
            expires_at: Utc::now() - Duration::hours(1),
            banned_at: Utc::now() - Duration::hours(2),
            banned_exp: Utc::now() - Duration::hours(1),
            banned_ttl: Utc::now() - Duration::hours(1),
        };
        store.tokens.insert(token.to_string(), expired_info);

        let result = store.is_banned(token).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_is_banned_for_nonexistent_token() {
        let store = HashMapBannedTokenStore::new();
        let token = "nonexistent_token";

        let result = store.is_banned(token).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_get_existing_token() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "get_test_token";
        let exp = (Utc::now() + Duration::hours(1)).timestamp() as usize;

        store.ban_until_expiry(token, exp).await.unwrap();

        let result = store.get(token).await;
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.token, token);
    }

    #[tokio::test]
    async fn test_get_nonexistent_token() {
        let store = HashMapBannedTokenStore::new();
        let token = "missing_token";

        let result = store.get(token).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), BannedTokenStoreError::TokenNotValidAnymore);
    }

    #[tokio::test]
    async fn test_overwrite_existing_ban() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "overwrite_token";

        // First ban
        let ttl1 = Duration::minutes(30);
        store.ban_with_ttl(token, ttl1).await.unwrap();
        let first_info = store.get(token).await.unwrap();

        // Wait a bit to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Second ban (overwrite)
        let ttl2 = Duration::hours(2);
        store.ban_with_ttl(token, ttl2).await.unwrap();
        let second_info = store.get(token).await.unwrap();

        assert!(second_info.banned_at > first_info.banned_at);
        assert!(second_info.expires_at > first_info.expires_at);
        assert_eq!(store.tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_tokens() {
        let mut store = HashMapBannedTokenStore::new();
        let tokens = vec!["token1", "token2", "token3"];

        for (i, token) in tokens.iter().enumerate() {
            let ttl = Duration::minutes((i as i64 + 1) * 10);
            store.ban_with_ttl(token, ttl).await.unwrap();
        }

        assert_eq!(store.tokens.len(), 3);

        for token in &tokens {
            assert!(store.is_banned(token).await.unwrap());
        }
    }

    #[tokio::test]
    async fn test_ban_empty_token() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "";
        let ttl = Duration::hours(1);

        let result = store.ban_with_ttl(token, ttl).await;

        assert!(result.is_ok());
        assert!(store.tokens.contains_key(""));
    }

    #[tokio::test]
    async fn test_ban_very_long_token() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "a".repeat(1000); // 1000 character token
        let ttl = Duration::hours(1);

        let result = store.ban_with_ttl(&token, ttl).await;

        assert!(result.is_ok());
        assert!(store.tokens.contains_key(&token));
    }

    #[tokio::test]
    async fn test_ban_until_expiry_correct_fields() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "field_test_token";
        let exp_timestamp = (Utc::now() + Duration::hours(2)).timestamp() as usize;

        store.ban_until_expiry(token, exp_timestamp).await.unwrap();

        let info = store.get(token).await.unwrap();
        let expected_exp = DateTime::<Utc>::from_timestamp(exp_timestamp as i64, 0).unwrap();

        assert_eq!(info.expires_at, expected_exp);
        assert_eq!(info.banned_exp, expected_exp);
        assert_eq!(info.banned_ttl, expected_exp);
        assert!(info.banned_at <= Utc::now());
    }

    #[tokio::test]
    async fn test_ban_with_ttl_correct_fields() {
        let mut store = HashMapBannedTokenStore::new();
        let token = "ttl_field_test";
        let ttl = Duration::minutes(45);

        let before = Utc::now();
        store.ban_with_ttl(token, ttl).await.unwrap();

        let info = store.get(token).await.unwrap();
        let expected_expires = info.banned_at + ttl;

        assert_eq!(info.expires_at, expected_expires);
        assert_eq!(info.banned_exp, expected_expires);
        assert_eq!(info.banned_ttl, expected_expires);
        assert!(info.banned_at >= before);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let store = Arc::new(RwLock::new(HashMapBannedTokenStore::new()));
        let mut handles = vec![];

        // Spawn multiple tasks that ban different tokens
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = tokio::spawn(async move {
                let token = format!("concurrent_token_{}", i);
                // Use at least 1 minute TTL to ensure tokens don't expire during test
                let ttl = Duration::minutes((i as i64) + 1);
                store_clone.write().await.ban_with_ttl(&token, ttl).await.unwrap();
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all tokens were banned
        let store_read = store.read().await;
        assert_eq!(store_read.tokens.len(), 10);
        for i in 0..10 {
            let token = format!("concurrent_token_{}", i);
            assert!(store_read.is_banned(&token).await.unwrap());
        }
    }
}
