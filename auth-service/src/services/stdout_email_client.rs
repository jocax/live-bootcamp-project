use std::fmt::Debug;
use crate::domain::email_client::EmailClient;
use crate::domain::types::Email;

pub struct StdoutEmailClient;

impl Default for StdoutEmailClient {
    fn default() -> Self {
        StdoutEmailClient
    }
}

impl Debug for StdoutEmailClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StdoutEmailClient")
    }
}

impl StdoutEmailClient {

    pub async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        println!(
            "Sending email to {} with subject: {} and content: {}",
            recipient.as_ref(),
            subject,
            content
        );

        Ok(())
    }
}
#[async_trait::async_trait]
impl EmailClient for StdoutEmailClient {
    async fn send_email(&self, recipient: &Email, subject: &str, content: &str) -> Result<(), String> {
        self.send_email(recipient, subject, content).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    pub async fn test_send_email() {

        let email_client = StdoutEmailClient::default();

        let recipient = &Email::try_from("user@example.com").unwrap();

        let result = email_client.send_email(
            recipient, "my subject", "my content"
        );

        assert!(result.await.is_ok())
    }
}

