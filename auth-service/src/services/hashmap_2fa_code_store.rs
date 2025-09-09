use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use chrono::{Duration, Utc};
use uuid::Uuid;
use crate::domain::data_stores::{Standard2FaError, Standard2FaInfo, Standard2FaStore};
use crate::domain::types::Email;

pub struct HashMapStandard2FaStore {
    infos: HashMap<Email, Standard2FaInfo>,
}

impl HashMapStandard2FaStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for HashMapStandard2FaStore {
    fn default() -> Self {
        HashMapStandard2FaStore {
            infos: HashMap::new(),
        }
    }
}

impl Debug for HashMapStandard2FaStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashMapStandard2FaStoreStore")
            .field("infos", &self.infos.len())
            .finish()
    }
}

impl HashMapStandard2FaStore {

    async fn store_2fa_code(
        &mut self,
        email: &Email,
        code: String,
        ttl_seconds: u64,
    ) -> Result<String, Standard2FaError> {
        // Clean up expired codes first
        self.cleanup_expired();

        let attempt_id = Uuid::now_v7().to_string();
        let expires_at = Utc::now() + Duration::seconds(ttl_seconds as i64);

        let info = Standard2FaInfo {
            attempt_id: attempt_id.clone(),
            code_2fa: code,
            expires_at,
        };

        // Replace any existing code for this email
        self.infos.insert(email.clone(), info);

        Ok(attempt_id)
    }

    async fn verify_and_consume_2fa_code(
        &mut self,
        email: &Email,
        code: &str,
    ) -> Result<(), Standard2FaError> {
        match self.infos.get(email) {
            Some(info) => {
                // Check if expired
                if info.expires_at < Utc::now() {
                    self.infos.remove(email); // Clean up expired code
                    return Err(Standard2FaError::Expired);
                }

                // Check if code matches
                if info.code_2fa != code {
                    return Err(Standard2FaError::InvalidCode);
                }

                // Code is valid - remove it (consume)
                self.infos.remove(email);
                Ok(())
            }
            None => Err(Standard2FaError::NotFound),
        }
    }

    async fn has_active_2fa_code(
        &self,
        email: &Email,
    ) -> Result<Option<Standard2FaInfo>, Standard2FaError> {
        match self.infos.get(email) {
            Some(info) => {
                // Check if expired
                if info.expires_at > Utc::now() {
                    Ok(Some(info.clone()))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    // Helper method to clean up expired codes
    fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.infos.retain(|_, info| info.expires_at > now);
    }

}

#[async_trait::async_trait]
impl Standard2FaStore for HashMapStandard2FaStore {
    async fn store_2fa_code(&mut self, email: &Email, code: String, ttl_seconds: u64) -> Result<String, Standard2FaError> {
        self.store_2fa_code(email, code, ttl_seconds).await
    }

    async fn verify_and_consume_2fa_code(&mut self, email: &Email, code: &str) -> Result<(), Standard2FaError> {
        self.verify_and_consume_2fa_code(email, code).await
    }

    async fn has_active_2fa_code(&self, email: &Email) -> Result<Option<Standard2FaInfo>, Standard2FaError> {
        self.has_active_2fa_code(email).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_new_store_is_empty() {
        let store = HashMapStandard2FaStore::new();
        assert_eq!(store.infos.len(), 0);
    }

    // Helper function to create a test email
    fn test_email(email: &str) -> Email {
        Email::try_from(email).unwrap()
    }

    #[tokio::test]
    async fn test_store_2fa_code_success() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");
        let code = "ABC123".to_string();

        let attempt_id = store.store_2fa_code(&email, code.clone(), 300).await.unwrap();

        // Verify attempt_id is not empty
        assert!(!attempt_id.is_empty());

        // Verify code is stored
        assert!(store.has_active_2fa_code(&email).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_store_2fa_code_replaces_existing() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");

        // Store first code
        let first_code = "ABC123".to_string();
        let first_attempt_id = store.store_2fa_code(&email, first_code, 300).await.unwrap();

        // Store second code (should replace first)
        let second_code = "XYZ789".to_string();
        let second_attempt_id = store.store_2fa_code(&email, second_code.clone(), 300).await.unwrap();

        // Verify attempt IDs are different
        assert_ne!(first_attempt_id, second_attempt_id);

        // Verify first code no longer works
        assert_eq!(
            store.verify_and_consume_2fa_code(&email, "ABC123").await.unwrap_err(),
            Standard2FaError::InvalidCode
        );

        // Verify second code works
        assert!(store.verify_and_consume_2fa_code(&email, &second_code).await.is_ok());
    }

    #[tokio::test]
    async fn test_verify_and_consume_valid_code() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");
        let code = "ABC123".to_string();

        // Store code
        store.store_2fa_code(&email, code.clone(), 300).await.unwrap();

        // Verify and consume
        assert!(store.verify_and_consume_2fa_code(&email, &code).await.is_ok());

        // Verify code is consumed (no longer active)
        assert!(!store.has_active_2fa_code(&email).await.unwrap().is_some());

        // Verify same code can't be used again
        assert_eq!(
            store.verify_and_consume_2fa_code(&email, &code).await.unwrap_err(),
            Standard2FaError::NotFound
        );
    }

    #[tokio::test]
    async fn test_verify_invalid_code() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");

        // Store code
        store.store_2fa_code(&email, "ABC123".to_string(), 300).await.unwrap();

        // Try to verify with wrong code
        assert_eq!(
            store.verify_and_consume_2fa_code(&email, "WRONG").await.unwrap_err(),
            Standard2FaError::InvalidCode
        );

        // Verify the correct code is still active
        assert!(store.has_active_2fa_code(&email).await.is_ok());
    }

    #[tokio::test]
    async fn test_verify_nonexistent_code() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");

        // Try to verify without storing any code
        assert_eq!(
            store.verify_and_consume_2fa_code(&email, "ABC123").await.unwrap_err(),
            Standard2FaError::NotFound
        );
    }

    #[tokio::test]
    async fn test_expired_code() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");
        let code = "ABC123".to_string();

        // Store code with 0 second TTL (immediately expired)
        store.store_2fa_code(&email, code.clone(), 0).await.unwrap();

        // Small delay to ensure expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Check if code is active (should be false)
        assert!(!store.has_active_2fa_code(&email).await.unwrap().is_some());

        // Try to verify expired code
        assert_eq!(
            store.verify_and_consume_2fa_code(&email, &code).await.unwrap_err(),
            Standard2FaError::Expired
        );
    }

    #[tokio::test]
    async fn test_has_active_2fa_code() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");

        // Initially no code
        assert!(!store.has_active_2fa_code(&email).await.unwrap().is_some());

        // Store code
        store.store_2fa_code(&email, "ABC123".to_string(), 300).await.unwrap();
        assert!(store.has_active_2fa_code(&email).await.unwrap().is_some());

        // Consume code
        store.verify_and_consume_2fa_code(&email, "ABC123").await.unwrap();
        assert!(!store.has_active_2fa_code(&email).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let mut store = HashMapStandard2FaStore::new();
        let email1 = test_email("user1@example.com");
        let email2 = test_email("user2@example.com");

        // Store codes for different users
        store.store_2fa_code(&email1, "ABC123".to_string(), 300).await.unwrap();
        store.store_2fa_code(&email2, "XYZ789".to_string(), 300).await.unwrap();

        // Verify both have active codes
        assert!(store.has_active_2fa_code(&email1).await.unwrap().is_some());
        assert!(store.has_active_2fa_code(&email2).await.unwrap().is_some());

        // Verify user1's code
        assert!(store.verify_and_consume_2fa_code(&email1, "ABC123").await.is_ok());

        // User2's code should still be active
        assert!(store.has_active_2fa_code(&email2).await.unwrap().is_some());

        // Verify user2's code
        assert!(store.verify_and_consume_2fa_code(&email2, "XYZ789").await.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_expired_on_store() {
        let mut store = HashMapStandard2FaStore::new();
        let email1 = test_email("user1@example.com");
        let email2 = test_email("user2@example.com");

        // Manually insert expired code for user1
        store.infos.insert(
            email1.clone(),
            Standard2FaInfo {
                attempt_id: "expired".to_string(),
                code_2fa: "EXPIRED".to_string(),
                expires_at: Utc::now() - Duration::seconds(1),
            },
        );

        // Store new code for user2 (should trigger cleanup)
        store.store_2fa_code(&email2, "NEW123".to_string(), 300).await.unwrap();

        // Verify expired code was cleaned up
        assert!(!store.has_active_2fa_code(&email1).await.unwrap().is_some());
        assert!(store.has_active_2fa_code(&email2).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_case_sensitivity() {
        let mut store = HashMapStandard2FaStore::new();
        let email = test_email("user@example.com");

        // Store uppercase code
        store.store_2fa_code(&email, "ABC123".to_string(), 300).await.unwrap();

        // Verify with lowercase should fail (codes are case-sensitive)
        assert_eq!(
            store.verify_and_consume_2fa_code(&email, "abc123").await.unwrap_err(),
            Standard2FaError::InvalidCode
        );

        // Verify with correct case should work
        assert!(store.verify_and_consume_2fa_code(&email, "ABC123").await.is_ok());
    }

}



