use std::collections::HashMap;

use crate::domain::user::User;

#[derive(Debug, PartialEq, Default)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    #[default]
    UnexpectedError,
}

pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl Default for HashmapUserStore {
    fn default() -> HashmapUserStore {
        HashmapUserStore {
            users: HashMap::new(),
        }
    }
}

impl HashmapUserStore {

    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.get_email()) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.get_email().clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users.get(email)
            .ok_or(UserStoreError::UserNotFound)
            .map(|user| user.clone())
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email)?;
        if user.verify_password(password) {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::user::User;

    #[tokio::test]
    pub async fn test_add_user() {
        let user = User::new(
            String::from("user@example.com"),
            String::from("myPassword"),
            false,
        );
        let mut store = HashmapUserStore::default();
        store.add_user(user.clone()).unwrap();
        assert_eq!(store.users.get(&user.get_email()), Some(&user));
    }

    #[tokio::test]
    pub async fn test_add_user_already_exists() {
        let user = User::new(
            String::from("user@example.com"),
            String::from("myPassword"),
            false,
        );
        let mut store = HashmapUserStore::default();
        store.add_user(user.clone()).unwrap();

        //second add must throw an error
        let error = store.add_user(user.clone());
        assert_eq!(error, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let user = User::new(
            String::from("user@example.com"),
            String::from("myPassword"),
            false,
        );
        let mut store = HashmapUserStore::default();
        store.add_user(user.clone()).unwrap();
        assert_eq!(store.users.get(&user.get_email()), Some(&user));

        let found_user = store.get_user("user@example.com").unwrap();
        assert_eq!(found_user.get_email(), user.get_email())
    }

    #[tokio::test]
    async fn test_get_user_does_not_exist() {
        let store = HashmapUserStore::default();

        let result = store.get_user("user@example.com");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UserStoreError::UserNotFound
        ));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let user = User::new(
            String::from("user@example.com"),
            String::from("myPassword"),
            false,
        );
        let mut store = HashmapUserStore::default();
        store.add_user(user.clone()).unwrap();

        let negative_error_result = store.validate_user("user@example.com", "otherPassword");
        assert!(negative_error_result.is_err());
        assert!(matches!(
            negative_error_result.unwrap_err(),
            UserStoreError::InvalidCredentials
        ));

        let positive_error_result = store.validate_user("user@example.com", "myPassword");
        assert!(positive_error_result.is_ok());
        assert!(matches!(
            positive_error_result.unwrap(),
            ()
        ));
    }
}
