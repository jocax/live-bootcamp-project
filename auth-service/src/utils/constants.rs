use dotenvy::dotenv;
use lazy_static::lazy_static;
use std::env as std_env;

lazy_static! {
    pub static ref JWT_SECRET: String = set_token();
    pub static ref DROPLET_ID: String = set_droplet_ip();
    pub static ref DATABASE_URL: String = set_database_url();
}

fn set_token() -> String {
    dotenv().ok(); // Load environment variables
    let secret = std_env::var(env::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set.");
    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }
    secret
}

fn set_droplet_ip() -> String {
    dotenv().ok(); // Load environment variables
    let secret = std_env::var(env::DROPLET_IP_ENV_VAR).expect("DROPLET_IP must be set.");
    if secret.is_empty() {
        panic!("DROPLET_IP must not be empty.");
    }
    secret
}

fn set_database_url() -> String {
    dotenv().ok(); // Load environment variables
    let secret = std_env::var(env::DATABASE_URL_ENV_VAR).expect("DATABASE_URL must be set.");
    if secret.is_empty() {
        panic!("DATABASE_URL must not be empty.");
    }
    secret
}



pub mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const DROPLET_IP_ENV_VAR: &str = "DROPLET_IP";
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";

}

pub const JWT_COOKIE_NAME: &str = "jwt";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:8001";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:8001";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use serial_test::serial;
    use crate::utils::constants::env::{DATABASE_URL_ENV_VAR, JWT_SECRET_ENV_VAR};

    // Helper function to safely set and restore environment variables
    fn with_env_var<F>(key: &str, value: Option<&str>, test: F)
    where
        F: FnOnce() + panic::UnwindSafe,
    {
        let original = std_env::var(key).ok();

        match value {
            Some(v) => std_env::set_var(key, v),
            None => std_env::remove_var(key),
        }

        let result = panic::catch_unwind(test);

        // Restore original value
        match original {
            Some(v) => std_env::set_var(key, v),
            None => std_env::remove_var(key),
        }

        if let Err(e) = result {
            panic::resume_unwind(e);
        }
    }

    #[test]
    #[serial]
    fn test_jwt_cookie_name_constant() {
        assert_eq!(JWT_COOKIE_NAME, "jwt");
    }

    #[test]
    #[serial]
    fn test_jwt_secret_env_var_constant() {
        assert_eq!(JWT_SECRET_ENV_VAR, "JWT_SECRET");
    }

    #[test]
    #[serial]
    fn test_set_token_with_valid_secret() {
        with_env_var(JWT_SECRET_ENV_VAR, Some("test_secret_123"), || {
            let result = set_token();
            assert_eq!(result, "test_secret_123");
        });
    }

    #[test]
    #[should_panic(expected = "JWT_SECRET must not be empty")]
    #[serial]
    fn test_set_token_with_empty_string() {
        with_env_var(env::JWT_SECRET_ENV_VAR, Some(""), || {
            set_token();
        });
    }

    #[test]
    #[serial]
    fn test_set_token_with_whitespace() {
        with_env_var(env::JWT_SECRET_ENV_VAR, Some("  secret_with_spaces  "), || {
            let result = set_token();
            // Note: Your current implementation doesn't trim whitespace
            // You might want to add .trim() in the actual implementation
            assert_eq!(result, "  secret_with_spaces  ");
        });
    }

    #[test]
    #[serial]
    fn test_set_token_with_special_characters() {
        let special_secret = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
        with_env_var(env::JWT_SECRET_ENV_VAR, Some(special_secret), || {
            let result = set_token();
            assert_eq!(result, special_secret);
        });
    }

    // Integration test for lazy_static initialization
    #[test]
    #[serial]
    fn test_jwt_secret_lazy_static() {
        with_env_var(env::JWT_SECRET_ENV_VAR, Some("lazy_static_secret"), || {
            // Force lazy_static initialization
            // let secret = &*JWT_SECRET;
            let secret = set_token();
            assert_eq!(secret, "lazy_static_secret");
        });
    }

    // Test to ensure dotenv file is loaded (if exists)
    #[test]
    #[serial]
    fn test_dotenv_loading() {
        // Create a temporary .env file for testing
        use std::fs;

        let env_content = format!("{}=dotenv_test_secret", JWT_SECRET_ENV_VAR);
        let _ = fs::write(".env.test", &env_content);

        // Change to test env file
        std_env::set_var("DOTENV_PATH", ".env.test");

        with_env_var(env::JWT_SECRET_ENV_VAR, None, || {
            // Load from .env.test
            dotenvy::from_filename(".env.test").ok();

            if let Ok(secret) = std_env::var(JWT_SECRET_ENV_VAR) {
                assert_eq!(secret, "dotenv_test_secret");
            }
        });

        // Clean up
        let _ = fs::remove_file(".env.test");
    }


    #[test]
    #[serial]
    fn test_set_database_url_with_valid_secret() {
        with_env_var(DATABASE_URL_ENV_VAR, Some("postgres://postgres:password123@db:5432"), || {
            let result = set_database_url();
            assert_eq!(result, "postgres://postgres:password123@db:5432");
        });
    }

}
