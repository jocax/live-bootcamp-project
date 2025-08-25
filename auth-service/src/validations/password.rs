use std::borrow::Cow;
use validator::ValidationError;

//We use this public method in the annotation. Very basic password protection.
pub fn validate_password_default(password: &str) -> Result<(), ValidationError> {
    validate_password_default_with_length(password)?;
    validate_password_default_with_regex(password)
}

fn validate_password_default_with_length(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 {
        let mut error = ValidationError::new("password_too_short");
        error.message = Some(Cow::Borrowed("Password must be at least 8 characters long"));
        return Err(error);
    }

    if password.len() > 32 {
        let mut error = ValidationError::new("password_too_long");
        error.message = Some(Cow::Borrowed("Password must not exceed 32 characters"));
        return Err(error);
    }
    Ok(())
}

fn validate_password_default_with_regex(password: &str) -> Result<(), ValidationError> {

    let has_numeric = password.chars().any(|c| c.is_numeric());
    let has_alphabetic = password.chars().any(|c| c.is_alphabetic());

    if !has_numeric {
        let mut error = ValidationError::new("password_missing_number");
        error.message = Some(Cow::Borrowed("Password must contain at least one number"));
        return Err(error);
    }

    if !has_alphabetic {
        let mut error = ValidationError::new("password_missing_letter");
        error.message = Some(Cow::Borrowed("Password must contain at least one letter"));
        return Err(error);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::validations::password::validate_password_default;

    #[test]
    fn test_validate_password_length() {
        // Too short (less than 8)
        assert!(validate_password_default("1234567").is_err());
        assert!(validate_password_default("abc123").is_err());
        assert!(validate_password_default("").is_err());

        // Valid length (8-32)
        assert!(validate_password_default("abc12345").is_ok());
        assert!(validate_password_default("myPassword123").is_ok());

        // Too long (more than 32)
        let long_password = "a1".repeat(17); // 34 characters
        assert!(validate_password_default(&long_password).is_err());
    }

    #[test]
    fn test_validate_password_content() {
        // Only numbers - should fail
        assert!(validate_password_default("12345678").is_err());
        assert!(validate_password_default("99999999").is_err());

        // Only letters - should fail
        assert!(validate_password_default("abcdefgh").is_err());
        assert!(validate_password_default("PASSWORD").is_err());

        // Mix of letters and numbers - should pass
        assert!(validate_password_default("password1").is_ok());
        assert!(validate_password_default("abc12345").is_ok());
        assert!(validate_password_default("Test1234").is_ok());
        assert!(validate_password_default("8letters").is_ok());
    }

    #[test]
    fn test_validate_password_special_cases() {
        // With special characters but has both letters and numbers
        assert!(validate_password_default("Pass123!@#").is_ok());
        assert!(validate_password_default("a1!@#$%^").is_ok());

        // Edge cases for length
        assert!(validate_password_default("a1234567").is_ok()); // Exactly 8
        assert!(validate_password_default(&"a1".repeat(16)).is_ok()); // Exactly 32

        // International characters
        assert!(validate_password_default("café1234").is_ok()); // Has letter and number
        assert!(validate_password_default("пароль123").is_ok()); // Cyrillic + numbers
    }

    #[test]
    fn test_error_messages() {
        // Test specific error types
        match validate_password_default("12345") {
            Err(e) => assert_eq!(e.code, "password_too_short"),
            Ok(_) => panic!("Expected error for short password"),
        }

        match validate_password_default("abcdefgh") {
            Err(e) => assert_eq!(e.code, "password_missing_number"),
            Ok(_) => panic!("Expected error for password without numbers"),
        }

        match validate_password_default("12345678") {
            Err(e) => assert_eq!(e.code, "password_missing_letter"),
            Ok(_) => panic!("Expected error for password without letters"),
        }
    }

}
