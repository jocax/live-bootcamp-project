use std::sync::Arc;
use tokio::sync::RwLock;
use auth_service::{AppState, Application, BannedTokenStoreType, UserStoreType};
use auth_service::services::{HashMapBannedTokenStore, HashMapUserStore};
use auth_service::utils::constants::prod;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");
    //user data
    let user_store: UserStoreType = Arc::new(RwLock::new(HashMapUserStore::default()));
    //token data
    let token_store: BannedTokenStoreType = Arc::new(RwLock::new(HashMapBannedTokenStore::default()));
    // app state
    let app_state = AppState::new(user_store, token_store);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
