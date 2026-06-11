use anyhow::{Result, bail};
use russh::keys::check_known_hosts_path;
use russh::keys::known_hosts::learn_known_hosts_path;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictHostKeyPolicy {
    No,
    Yes(PathBuf),
    AcceptNew(PathBuf),
}

impl StrictHostKeyPolicy {
    pub fn parse(value: &str, known_hosts_file: PathBuf) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "no" | "off" | "false" => Ok(Self::No),
            "yes" | "on" | "true" => Ok(Self::Yes(known_hosts_file)),
            "accept-new" | "accept_new" => Ok(Self::AcceptNew(known_hosts_file)),
            other => bail!("unsupported strict host key policy: {other}"),
        }
    }

    pub fn openssh_option(&self) -> Option<&'static str> {
        match self {
            Self::No => Some("no"),
            Self::Yes(_) => Some("yes"),
            Self::AcceptNew(_) => Some("accept-new"),
        }
    }

    pub fn known_hosts_path(&self) -> Option<&Path> {
        match self {
            Self::Yes(path) | Self::AcceptNew(path) => Some(path),
            Self::No => None,
        }
    }

    pub fn verify_host_key(
        &self,
        host: &str,
        port: u16,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, russh::Error> {
        match self {
            Self::No => Ok(true),
            Self::Yes(path) => {
                check_known_hosts_path(host, port, public_key, path).map_err(russh::Error::Keys)
            }
            Self::AcceptNew(path) => match check_known_hosts_path(host, port, public_key, path) {
                Ok(true) => Ok(true),
                Ok(false) => learn_known_hosts_path(host, port, public_key, path)
                    .map(|()| true)
                    .map_err(russh::Error::Keys),
                Err(error) => Err(russh::Error::Keys(error)),
            },
        }
    }
}

pub fn default_known_hosts_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".ssh").join("known_hosts"))
}

pub fn resolve_known_hosts_file(config_path: Option<&Path>, cli_path: Option<&Path>) -> PathBuf {
    if let Some(path) = cli_path {
        return path.to_path_buf();
    }
    if let Some(path) = config_path {
        return path.to_path_buf();
    }
    default_known_hosts_path().unwrap_or_else(|| PathBuf::from(".ssh/known_hosts"))
}

pub fn resolve_strict_host_key_policy(
    config_value: Option<&str>,
    cli_value: Option<&str>,
    known_hosts_file: PathBuf,
) -> Result<StrictHostKeyPolicy> {
    let value = cli_value.or(config_value).unwrap_or("accept-new");
    StrictHostKeyPolicy::parse(value, known_hosts_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_strict_host_key_policies() {
        let path = PathBuf::from("/tmp/known_hosts");
        assert_eq!(
            StrictHostKeyPolicy::parse("yes", path.clone()).unwrap(),
            StrictHostKeyPolicy::Yes(path.clone())
        );
        assert_eq!(
            StrictHostKeyPolicy::parse("accept-new", path.clone()).unwrap(),
            StrictHostKeyPolicy::AcceptNew(path)
        );
        assert_eq!(
            StrictHostKeyPolicy::parse("no", PathBuf::from("/tmp/x")).unwrap(),
            StrictHostKeyPolicy::No
        );
    }

    #[test]
    fn accept_new_persists_unknown_host_key() {
        use russh::keys::parse_public_key_base64;

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("known_hosts");
        let public_key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .expect("parse key");
        let policy = StrictHostKeyPolicy::AcceptNew(path.clone());

        assert!(
            policy
                .verify_host_key("scan-target.example.com", 22, &public_key)
                .expect("accept new host key")
        );

        assert!(check_known_hosts_path("scan-target.example.com", 22, &public_key, &path).unwrap());
    }

    #[test]
    fn accept_new_rejects_changed_host_key() {
        use russh::keys::parse_public_key_base64;
        use std::io::Write;

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("known_hosts");
        let mut file = std::fs::File::create(&path).expect("create known_hosts");
        writeln!(
            file,
            "scan-target.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF"
        )
        .expect("write known_hosts");

        let public_key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .expect("parse key");
        let policy = StrictHostKeyPolicy::AcceptNew(path);

        assert!(
            policy
                .verify_host_key("scan-target.example.com", 22, &public_key)
                .is_err()
        );
    }
}
