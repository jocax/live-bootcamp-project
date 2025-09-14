use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use crate::domain::user::User;
use crate::domain::data_stores::UserStore;
pub(crate) use crate::domain::data_stores::UserStoreError;
use crate::domain::types::{Email};

pub struct HashMapUserStore {
    users: HashMap<Email, User>,
}

impl HashMapUserStore {

    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.get_email()) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.get_email().clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users.get(email)
            .ok_or(UserStoreError::UserNotFound)
            .map(|user| user.clone())
    }

    pub fn validate_user(&self, email: &Email, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;
        if user.get_password().verify_password(password) {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

impl Default for HashMapUserStore {
    fn default() -> Self {
        HashMapUserStore {
            users: HashMap::new(),
        }
    }
}

impl Debug for HashMapUserStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashmapUserStore")
            .field("users", &self.users.len())
            .finish()
    }
}

#[async_trait::async_trait]
impl UserStore for HashMapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        self.add_user(user)
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.get_user(email)
    }

    async fn validate_user(&self, email: &Email, password: &str) -> Result<(), UserStoreError> {
        self.validate_user(email, password)
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::types::Password;
    use super::*;
    use crate::domain::user::User;

    #[tokio::test]
    pub async fn test_add_user() {
        let user = User::new(
            Email::try_from("user@example.com").unwrap(),
            Password::try_from("myPassword123").unwrap(),
            false,
        );
        let mut store = HashMapUserStore::default();
        store.add_user(user.clone()).unwrap();
        assert_eq!(store.users.get(&user.get_email()), Some(&user));
    }

    #[tokio::test]
    pub async fn test_add_user_already_exists() {
        let user = User::new(
            Email::try_from("user@example.com").unwrap(),
            Password::try_from("myPassword123").unwrap(),
            false,
        );
        let mut store = HashMapUserStore::default();
        store.add_user(user.clone()).unwrap();

        //second add must throw an error
        let error = store.add_user(user.clone());
        assert_eq!(error, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let user = User::new(
            Email::try_from("user@example.com").unwrap(),
            Password::try_from("myPassword123").unwrap(),
            false,
        );
        let mut store = HashMapUserStore::default();
        store.add_user(user.clone()).unwrap();
        assert_eq!(store.users.get(&user.get_email()), Some(&user));

        let email = &Email::try_from("user@example.com").unwrap();
        let found_user = store.get_user(email).unwrap();
        assert_eq!(found_user.get_email(), user.get_email())
    }

    #[tokio::test]
    async fn test_get_user_does_not_exist() {
        let store = HashMapUserStore::default();

        let email = &Email::try_from("user@example.com").unwrap();
        let result = store.get_user(email);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UserStoreError::UserNotFound
        ));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let email_address = "user@example.com";
        let password = "myPassword123";
        let user = User::new(
            Email::try_from(email_address).unwrap(),
            Password::try_from(password).unwrap(),
            false,
        );

        let mut store = HashMapUserStore::default();
        store.add_user(user).unwrap();

        let email = &Email::try_from("user@example.com").unwrap();
        let negative_error_result = store.validate_user(email, "otherPassword");

        assert!(negative_error_result.is_err());
        assert!(matches!(
            negative_error_result.unwrap_err(),
            UserStoreError::InvalidCredentials
        ));

        let positive_error_result = store.validate_user(email,"myPassword123");

        assert!(positive_error_result.is_ok());
        assert!(matches!(
            positive_error_result.unwrap(),
            ()
        ));
    }
}
