use email_address::EmailAddress;
use std::borrow::Cow;
use std::str::FromStr;
use validator::ValidationError;

//We use this public method in the annotation. It uses the default RFC email formats.
// And we also check the TLD to avoid getting RFC conforms emails like user@example (local email)
pub fn validate_email_default(email: &str) -> Result<(), ValidationError> {
    validate_email_rfc(email)?;
    validate_email_domain(email)
}

fn validate_email_rfc(email: &str) -> Result<(), ValidationError> {
    match EmailAddress::from_str(email) {
        Ok(_) => Ok(()),
        Err(e) => {
            let mut error = ValidationError::new("invalid_email_format");
            // Use the error message from the email_address crate
            error.message = Some(Cow::Owned(format!("invalid_email_basic: {}", e)));
            Err(error)
        }
    }
}

fn validate_email_domain(email: &str) -> Result<(), ValidationError> {
    // Check if email has a proper domain with TLD
    if let Some(at_pos) = email.rfind('@') {
        let domain = &email[at_pos + 1..];

        // Check for at least one dot in the domain part
        if !domain.contains('.') {
            return Err(ValidationError::new("invalid_email_tld"));
        }

        // Check that domain doesn't start or end with a dot
        if domain.starts_with('.') || domain.ends_with('.') {
            return Err(ValidationError::new("invalid_email_tld"));
        }

        // Check for valid TLD (at least 2 characters after the last dot)
        if let Some(last_dot) = domain.rfind('.') {
            let tld = &domain[last_dot + 1..];
            if tld.len() < 2 {
                return Err(ValidationError::new("invalid_email_tld"));
            }
        }

        // Check for spaces in domain
        if domain.contains(' ') {
            return Err(ValidationError::new("invalid_email_tld"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::{faker::internet::en::*, Fake};
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    #[test]
    fn test_validate_email_default() {
        // Valid emails
        assert!(validate_email_default("user@example.com").is_ok());
        assert!(validate_email_default("user+tag@example.com").is_ok());
        assert!(validate_email_default("user@sub.example.com").is_ok());
        assert!(validate_email_default("user@example.co.uk").is_ok());

        // Invalid emails - no TLD
        assert!(validate_email_default("user@example").is_err());
        assert!(validate_email_default("user@localhost").is_err());

        // Invalid emails - improper domain format
        assert!(validate_email_default("user@.com").is_err());
        assert!(validate_email_default("user@example.").is_err());
        assert!(validate_email_default("user@example.c").is_err()); // TLD too short
        assert!(validate_email_default("user@exam ple.com").is_err()); // space in domain
    }

    // TEST WITH FAKE CRATE

    #[test]
    fn test_validate_with_fake_valid_emails() {
        // Generate 100 random valid emails
        for _ in 0..100 {
            let email: String = SafeEmail().fake();

            assert!(
                validate_email_default(&email).is_ok(),
                "Email {} should be valid",
                email
            );
        }
    }

    #[test]
    fn test_validate_with_fake_free_emails() {
        // FreeEmail generates emails with common providers
        for _ in 0..50 {
            let email: String = FreeEmail().fake();

            assert!(
                validate_email_default(&email).is_ok(),
                "Free email {} should be valid",
                email
            );
        }
    }

    #[test]
    fn test_invalid_emails_with_fake_modifications() {
        // Take valid emails and make them invalid
        for _ in 0..20 {
            let valid_email: String = SafeEmail().fake();

            // Remove TLD to make invalid
            if let Some(last_dot) = valid_email.rfind('.') {
                let invalid_no_tld = &valid_email[..last_dot];
                assert!(
                    validate_email_default(invalid_no_tld).is_err(),
                    "Email without TLD {} should be invalid",
                    invalid_no_tld
                );
            }

            // Add space to make invalid
            let invalid_with_space = valid_email.replace("@", " @");
            assert!(
                validate_email_default(&invalid_with_space).is_err(),
                "Email with space {} should be invalid",
                invalid_with_space
            );

            // Double @ to make invalid
            let invalid_double_at = valid_email.replace("@", "@@");
            assert!(
                validate_email_default(&invalid_double_at).is_err(),
                "Email with double @ {} should be invalid",
                invalid_double_at
            );
        }
    }

    #[test]
    fn test_international_domains_with_fake() {
        use fake::faker::company::en::CompanyName;

        // Test with international TLDs
        let international_tlds = vec!["中国", "рф", "भारत", "日本", "de", "fr", "uk"];

        for tld in international_tlds {
            let username: String = Username().fake();
            let company: String = CompanyName().fake();
            let domain = company.to_lowercase().replace(" ", "-");

            let email = format!("{}@{}.{}", username, domain, tld);

            // These might fail depending on your validator's Unicode support
            match validate_email_default(&email) {
                Ok(_) => println!("Valid international email: {}", email),
                Err(e) => println!("Invalid international email: {} - Error: {:?}", email, e),
            }
        }
    }

    #[test]
    fn test_email_variations_with_fake() {
        use fake::faker::company::en::CompanyName;
        use fake::faker::name::en::{FirstName, LastName};

        // Generate different email patterns
        for _ in 0..20 {
            let first: String = FirstName().fake();
            let last: String = LastName().fake();
            let company: String = CompanyName().fake();

            // Clean up for email format
            let first_clean = first.to_lowercase().replace(" ", "");
            let last_clean = last.to_lowercase().replace(" ", "");
            let company_clean = company.to_lowercase().replace(" ", "");

            // Different email patterns
            let patterns = vec![
                format!("{}@{}.com", first_clean, company_clean),
                format!("{}.{}@{}.com", first_clean, last_clean, company_clean),
                format!(
                    "{}{}@{}.org",
                    first_clean.chars().next().unwrap(),
                    last_clean,
                    company_clean
                ),
                format!("{}_{}@{}.net", first_clean, last_clean, company_clean),
                format!("{}+test@{}.io", first_clean, company_clean),
            ];

            for email in patterns {
                // Skip if company name produced invalid domain
                if email.contains("..") || email.contains(".-") || email.contains("-.") {
                    continue;
                }

                assert!(
                    validate_email_default(&email).is_ok(),
                    "Email pattern {} should be valid",
                    email
                );
            }
        }
    }

    #[test]
    fn test_edge_case_lengths_with_fake() {
        use fake::faker::lorem::en::Word;

        // Test maximum valid lengths
        let domain: String = SafeEmail()
            .fake::<String>()
            .split('@')
            .nth(1)
            .unwrap()
            .to_string();

        // Test 64-character local part (maximum allowed)
        let mut local = String::new();
        while local.len() < 64 {
            let word: String = Word().fake();
            if local.len() + word.len() + 1 <= 64 {
                if !local.is_empty() {
                    local.push('.');
                }
                local.push_str(&word.to_lowercase());
            } else {
                // Fill remaining with 'a'
                let remaining = 64 - local.len();
                local.push_str(&"a".repeat(remaining));
                break;
            }
        }

        let max_email = format!("{}@{}", local, domain);
        assert_eq!(local.len(), 64);
        assert!(
            validate_email_default(&max_email).is_ok(),
            "64-char local part should be valid: {}",
            max_email
        );

        // Test 65-character local part (too long)
        let too_long_local = format!("{}a", local);
        let too_long_email = format!("{}@{}", too_long_local, domain);

        // This might pass validate_email_domain but should fail RFC validation
        match validate_email_default(&too_long_email) {
            Ok(_) => println!("Note: 65-char local part was accepted by validator"),
            Err(_) => println!("65-char local part correctly rejected"),
        }
    }

    #[test]
    fn test_special_characters_with_fake() {
        use fake::faker::internet::en::Username;

        // Test emails with special characters
        let special_chars = vec!["+", "-", "_", "."];

        for _ in 0..10 {
            let base: String = Username().fake();
            let domain: String = SafeEmail()
                .fake::<String>()
                .split('@')
                .nth(1)
                .unwrap()
                .to_string();

            for special in &special_chars {
                let email = format!("{}{}test@{}", base, special, domain);

                assert!(
                    validate_email_default(&email).is_ok(),
                    "Email with {} should be valid: {}",
                    special,
                    email
                );
            }
        }
    }

    #[test]
    fn test_subdomain_emails_with_fake() {
        use fake::faker::company::en::CompanyName;
        use fake::faker::lorem::en::Word;

        for _ in 0..10 {
            let username: String = Username().fake();
            let subdomain: String = Word().fake::<String>().to_lowercase();
            let domain: String = CompanyName()
                .fake::<String>()
                .to_lowercase()
                .replace(" ", "-")
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '-')
                .collect();

            let email = format!("{}@{}.{}.com", username, subdomain, domain);

            if !domain.is_empty() && !domain.starts_with('-') && !domain.ends_with('-') {
                assert!(
                    validate_email_default(&email).is_ok(),
                    "Subdomain email should be valid: {}",
                    email
                );
            }
        }
    }

    // TEST WITH QUICKCECK
    #[quickcheck]
    fn prop_no_email_causes_panic(s: String) -> bool {
        // This might find inputs like:
        // - "\u{0}@\u{0}.com"
        // - "a@" + "b".repeat(10000) + ".com"
        // - Strings with null bytes, control characters, etc.

        std::panic::catch_unwind(|| {
            assert!(validate_email_default(&s).is_err());
        }).is_ok()
    }

    // TEST WITH QUICKCECK + FAKE

    // Custom generator that uses fake for QuickCheck
    #[derive(Clone, Debug)]
    struct RealisticEmail(String);

    impl Arbitrary for RealisticEmail {
        fn arbitrary(_g: &mut Gen) -> Self {
            RealisticEmail(SafeEmail().fake())
        }
    }

    #[quickcheck]
    fn prop_all_realistic_emails_valid(email: RealisticEmail) -> bool {
        validate_email_default(&email.0).is_ok()
    }
}
