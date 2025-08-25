use std::sync::Arc;
use tokio::sync::RwLock;
use auth_service::{AppState, Application, UserStoreType};
use auth_service::services::HashMapUserStore;


#[tokio::main]
async fn main() {
    //user data
    let user_store: UserStoreType = Arc::new(RwLock::new(HashMapUserStore::default()));
    // app state
    let app_state = AppState::new(user_store);

    let app = Application::build(app_state, "0.0.0.0:8001")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}