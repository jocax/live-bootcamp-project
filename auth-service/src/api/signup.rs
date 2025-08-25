use derivative::Derivative;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Serialize, Deserialize, Derivative, Validate)]
#[derivative(Debug)]
pub struct SignUpRequest {
    #[validate(
        email(message = "Valid email required"),
        custom(function = "validate_email_domain", message = "Email must have a valid domain with TLD")
    )]
    email: String,
    #[derivative(Debug = "ignore")]
    #[validate(length(min = 8, max = 32, message = "Password must be 8-32 characters"))]
    password: String,
    #[serde(rename = "requires2FA")]
    requires_2fa: bool,
}

impl SignUpRequest {
    pub fn new(email: String, password: String, requires2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa: requires2fa,
        }
    }
    pub fn get_email(&self) -> String {
        self.email.clone()
    }
    pub fn get_password(&self) -> String {
        String::from("*****")
    }
    pub fn get_requires2fa(&self) -> bool {
        self.requires_2fa
    }
}

fn validate_email_domain(email: &str) -> Result<(), ValidationError> {
    // Check if email has a proper domain with TLD
    if let Some(at_pos) = email.rfind('@') {
        let domain = &email[at_pos + 1..];

        // Check for at least one dot in the domain part
        if !domain.contains('.') {
            return Err(ValidationError::new("invalid_domain"));
        }

        // Check that domain doesn't start or end with a dot
        if domain.starts_with('.') || domain.ends_with('.') {
            return Err(ValidationError::new("invalid_domain"));
        }

        // Check for valid TLD (at least 2 characters after the last dot)
        if let Some(last_dot) = domain.rfind('.') {
            let tld = &domain[last_dot + 1..];
            if tld.len() < 2 {
                return Err(ValidationError::new("invalid_tld"));
            }
        }

        // Check for spaces in domain
        if domain.contains(' ') {
            return Err(ValidationError::new("invalid_domain"));
        }
    }

    Ok(())
}


#[derive(Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct SignUpResponse {
    message: String,
}

impl SignUpResponse {
    pub fn new(message: String) -> Self {
        Self { message }
    }
    pub fn get_message(&self) -> String {
        self.message.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_up_request_and_ensure_debug_ignores_password() {
        let request = SignUpRequest::new("my@email.de".to_string(), "myPassword".to_string(), false);

        //with password
        let serialized = serde_json::to_string(&request).unwrap();
        assert_eq!(serialized, "{\"email\":\"my@email.de\",\"password\":\"myPassword\",\"requires2FA\":false}");

        //no password
        let request_debugged = format!("{:?}", request);
        assert_eq!(request_debugged, "SignUpRequest { email: \"my@email.de\", requires_2fa: false }");
    }

    #[test]
    fn test_validate_email_domain() {
        // Valid emails
        assert!(validate_email_domain("user@example.com").is_ok());
        assert!(validate_email_domain("user+tag@example.com").is_ok());
        assert!(validate_email_domain("user@sub.example.com").is_ok());
        assert!(validate_email_domain("user@example.co.uk").is_ok());

        // Invalid emails - no TLD
        assert!(validate_email_domain("user@example").is_err());
        assert!(validate_email_domain("user@localhost").is_err());

        // Invalid emails - improper domain format
        assert!(validate_email_domain("user@.com").is_err());
        assert!(validate_email_domain("user@example.").is_err());
        assert!(validate_email_domain("user@example.c").is_err()); // TLD too short
        assert!(validate_email_domain("user@exam ple.com").is_err()); // space in domain
    }

}
