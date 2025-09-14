use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use auth_service::domain::data_stores::{UserStore, UserStoreError};
use auth_service::domain::types::{Email, Password};
use auth_service::domain::user::User;
use auth_service::services::data_stores::postgres_user_store::PostgresUserStore;


async fn setup_test_db() -> (PgPool, impl Drop) {
    let postgres = Postgres::default()
        .with_db_name("test_db")
        .with_user("postgres")
        .with_password("postgres");

    let container = postgres.start().await.unwrap();

    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();

    let connection_string = format!(
        "postgres://postgres:postgres@{}:{}/test_db",
        host, port
    );

    let pool = PgPool::connect(&connection_string).await.unwrap();

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .unwrap();

    (pool, container)
}

#[tokio::test]
async fn test_add_user() {
    let (pool, _container) = setup_test_db().await;
    let mut user_store = PostgresUserStore::new(pool.clone());

    let email = Email::try_from("user@example.com").unwrap();
    let password = Password::try_from("password123").unwrap();
    let user = User::new(email, password, true);

    // Check that table is empty before insert
    let count_before = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_before, 0, "Table should be empty before insert");


    let result = user_store.add_user(user).await;
    assert!(result.is_ok());

    let count_after = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_after, 1, "Table should have exactly one entry after insert");

    // Container is automatically cleaned up when _container goes out of scope
}

#[tokio::test]
async fn test_get_user() {
    let (pool, _container) = setup_test_db().await;
    let mut store = PostgresUserStore::new(pool.clone());

    let email = Email::try_from("user@example.com").unwrap();
    let password = Password::try_from("password123").unwrap();
    let user = User::new(email.clone(), password.clone(), true);

    store.add_user(user).await.unwrap();

    let retrieved_user = store.get_user(&email).await.unwrap();
    assert_eq!(retrieved_user.get_email(), email);
    assert_eq!(retrieved_user.get_password(), password);
    assert_eq!(retrieved_user.get_requires2fa(), true);

    let non_existent = Email::try_from("nonexistent@example.com").unwrap();
    let result = store.get_user(&non_existent).await;
    assert!(matches!(result, Err(UserStoreError::UserNotFound)));
}

#[tokio::test]
async fn test_validate_user() {
    let (pool, _container) = setup_test_db().await;
    let mut store = PostgresUserStore::new(pool.clone());

    // Create a user with a known password
    let email = Email::try_from("test@example.com").unwrap();
    let raw_password = "MySecurePassword123!";
    let password = Password::try_from(raw_password.to_string()).unwrap(); // This will hash it
    let user = User::new(email.clone(), password, false);

    // Add user to database
    store.add_user(user).await.unwrap();

    // Test 1: Validate with correct password
    let result = store.validate_user(&email, raw_password).await;
    assert!(result.is_ok(), "Should validate with correct password");

    // Test 2: Validate with incorrect password
    let wrong_result = store.validate_user(&email, "WrongPassword123!").await;
    assert!(
        matches!(wrong_result, Err(UserStoreError::InvalidCredentials)),
        "Should fail with InvalidCredentials for wrong password"
    );

    // Test 3: Validate with empty password
    let empty_result = store.validate_user(&email, "").await;
    assert!(
        matches!(empty_result, Err(UserStoreError::InvalidCredentials)),
        "Should fail with InvalidCredentials for empty password"
    );

    // Test 4: Validate non-existent user
    let non_existent_email = Email::try_from("nonexistent@example.com").unwrap();
    let result = store.validate_user(&non_existent_email, "AnyPassword").await;
    assert!(
        matches!(result, Err(UserStoreError::UserNotFound)),
        "Should fail with UserNotFound for non-existent user"
    );

    // Test 5: Case sensitivity test (if your email comparison is case-sensitive)
    let wrong_case_email = Email::try_from("TEST@EXAMPLE.COM").unwrap();
    let case_result = store.validate_user(&wrong_case_email, raw_password).await;
    assert!(
        matches!(case_result, Err(UserStoreError::UserNotFound)),
        "Should fail with UserNotFound for wrong email case"
    );
}
