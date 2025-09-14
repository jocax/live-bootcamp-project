use crate::domain::data_stores::{UserStore, UserStoreError};
use crate::domain::types::{Email, Password};
use crate::domain::user::User;
use sqlx::{PgPool};
use std::fmt::{Debug, Formatter};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl Debug for PostgresUserStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresUserStore")
            .field("pool size:", &self.pool.size())
            .finish()
    }
}

#[derive(sqlx::FromRow)]
struct UserRow {
    email: String,
    password_hash: String,
    requires_2fa: bool,
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {

        let email = user.get_email().as_ref().to_string();
        let password_hash = user.get_password().as_ref().to_string();
        let requires_2fa = user.get_requires2fa();

        sqlx::query!(
            "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)",
            email,
            password_hash,
            requires_2fa
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {

        let row: UserRow = sqlx::query_as!(
            UserRow,
            "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1",
            email.as_ref().to_string()
        )
        .fetch_one(&self.pool)
        .await?;

        let email = Email::try_from(row.email).unwrap();
        let password = Password::from_hash(row.password_hash);
        let requires_2fa = row.requires_2fa;

        Ok(User::new(email, password, requires_2fa))
    }

    async fn validate_user(&self, email: &Email, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.get_password().verify_password(password) {
            Ok(())
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }
}

impl From<sqlx::Error> for UserStoreError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => UserStoreError::UserNotFound,
            _ => UserStoreError::UnexpectedError,
        }
    }
}

#[cfg(test)]
mod tests {
    //WE USE COMPILE TIME CHECKING FOR THE SQL AND TEST CONTAINERS IN ITESTS
}
