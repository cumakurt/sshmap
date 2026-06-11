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
