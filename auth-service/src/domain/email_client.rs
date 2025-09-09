use crate::domain::types::Email;

#[cfg_attr(any(test), mockall::automock)]
#[async_trait::async_trait]
pub trait EmailClient: Send + Sync + std::fmt::Debug{
    async fn send_email(
        &self,
        recipient: &Email,
        subject: &str,
        content: &str,
    ) -> Result<(), String>;
}
