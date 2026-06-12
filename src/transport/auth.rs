use crate::error::SshMapError;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanAuth {
    pub identity_file: Option<PathBuf>,
    pub use_agent: bool,
    pub agent_socket: Option<PathBuf>,
    pub identities_only: bool,
}

impl ScanAuth {
    pub fn has_identity_source(&self) -> bool {
        self.identity_file.is_some() || self.use_agent
    }
}

pub fn resolve_agent_socket(explicit_path: Option<&Path>) -> Option<PathBuf> {
    explicit_path.map(Path::to_path_buf).or_else(|| {
        std::env::var_os("SSH_AUTH_SOCK")
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
    })
}

pub fn validate_ssh_username(username: &str) -> Result<()> {
    if is_valid_ssh_username(username) {
        Ok(())
    } else {
        Err(SshMapError::InvalidUsername(username.to_string()).into())
    }
}

pub fn is_valid_ssh_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && username.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ssh_usernames() {
        validate_ssh_username("audit-user_01").unwrap();
        assert!(validate_ssh_username("audit@example").is_err());
        assert!(validate_ssh_username("").is_err());
    }
}
