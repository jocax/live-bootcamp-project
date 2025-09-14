use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use auth_service::domain::data_stores::UserStore;
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
