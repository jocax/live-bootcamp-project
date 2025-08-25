use crate::domain::user::User;

#[cfg_attr(any(test), mockall::automock)]
#[async_trait::async_trait]
pub trait UserStore: Send + Sync + std::fmt::Debug {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &str) -> Result<User, UserStoreError>;
    fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError>;
}

#[derive(Debug, PartialEq, Default)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    #[default]
    UnexpectedError,
}
