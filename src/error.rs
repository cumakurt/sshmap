use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshMapError {
    #[error("no targets were provided")]
    NoTargets,

    #[error("invalid port value: {0}")]
    InvalidPort(String),

    #[error("invalid target value: {0}")]
    InvalidTarget(String),

    #[error("invalid SSH username: {0}")]
    InvalidUsername(String),

    #[error("target scope expands to {count} endpoints, which exceeds the limit of {max}")]
    TooManyTargets { count: usize, max: usize },
}
