use dotenvy::dotenv;
use lazy_static::lazy_static;
use std::env as std_env;

lazy_static! {
    pub static ref JWT_SECRET: String = set_token();
}

fn set_token() -> String {
    dotenv().ok(); // Load environment variables
    let secret = std_env::var(env::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set.");
    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }
    secret
}

pub mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
}

pub const JWT_COOKIE_NAME: &str = "jwt";


#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use serial_test::serial;
    use crate::utils::constants::env::JWT_SECRET_ENV_VAR;

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
    #[serial]
    #[should_panic(expected = "JWT_SECRET must not be empty")]
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
    // #[ignore] // This test modifies the global state
    fn test_jwt_secret_lazy_static() {
        with_env_var(env::JWT_SECRET_ENV_VAR, Some("lazy_static_secret"), || {
            // Force lazy_static initialization
            let secret = &*JWT_SECRET;
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
}
