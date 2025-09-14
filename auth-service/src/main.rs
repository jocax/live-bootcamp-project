use std::sync::Arc;
use sqlx::{PgPool};
use tokio::sync::RwLock;
use auth_service::{get_postgres_pool, AppState, Application, BannedTokenStoreType, EmailClientType, Standard2FACodeStoreType, UserStoreType};
use auth_service::services::{HashMapBannedTokenStore, HashMapUserStore, StdoutEmailClient};
use auth_service::services::data_stores::hashmap_2fa_code_store::HashMapStandard2FaStore;
use auth_service::utils::constants::{prod, DATABASE_URL};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");
    //user data
    let user_store: UserStoreType = Arc::new(RwLock::new(HashMapUserStore::default()));
    //token data
    let token_store: BannedTokenStoreType = Arc::new(RwLock::new(HashMapBannedTokenStore::default()));
    // 2FA data
    let standard_2fa_store: Standard2FACodeStoreType = Arc::new(RwLock::new(HashMapStandard2FaStore::default()));
    // Email
    let email_client: EmailClientType =  Arc::new(RwLock::new(StdoutEmailClient::default()));
    // app state
    let app_state = AppState::new(user_store, token_store, standard_2fa_store, email_client);

    let pg_pool:PgPool = configure_postgresql().await;

    // Method 1: Quick check with SELECT 1
    match sqlx::query("SELECT 1")
        .fetch_one(&pg_pool)
        .await
    {
        Ok(_) => println!("✅ Database connection successful!"),
        Err(e) => eprintln!("❌ Database connection failed: {}", e),
    }


    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}


async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}
