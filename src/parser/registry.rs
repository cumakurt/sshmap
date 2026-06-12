use std::path::Path;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ParserKind {
    HostsFile,
    Passwd,
    Group,
    SshdConfig,
    SshConfig,
    AuthorizedKeys,
    KnownHosts,
    Sudoers,
}

impl ParserKind {
    pub fn evidence_type(self) -> &'static str {
        match self {
            Self::HostsFile => "hosts_file",
            Self::Passwd => "passwd",
            Self::Group => "group",
            Self::SshdConfig => "sshd_config",
            Self::SshConfig => "ssh_config",
            Self::AuthorizedKeys => "authorized_keys",
            Self::KnownHosts => "known_hosts",
            Self::Sudoers => "sudoers",
        }
    }

    pub fn source(self) -> &'static str {
        match self {
            Self::HostsFile => "hosts_file",
            Self::Passwd => "passwd",
            Self::Group => "group",
            Self::SshdConfig => "sshd_config",
            Self::SshConfig => "ssh_config",
            Self::AuthorizedKeys => "authorized_keys",
            Self::KnownHosts => "known_hosts",
            Self::Sudoers => "sudoers",
        }
    }

    pub fn requires_user(self) -> bool {
        matches!(self, Self::AuthorizedKeys)
    }
}

pub fn detect_parser(path: &Path, content: &str) -> Option<ParserKind> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let path_text = path.to_string_lossy();

    match filename {
        "hosts" if path_text.ends_with("/etc/hosts") || looks_like_hosts_file(content) => {
            return Some(ParserKind::HostsFile);
        }
        "passwd" => return Some(ParserKind::Passwd),
        "group" => return Some(ParserKind::Group),
        "sshd_config" => return Some(ParserKind::SshdConfig),
        "config" if path_text.contains(".ssh") => return Some(ParserKind::SshConfig),
        "ssh_config" => return Some(ParserKind::SshConfig),
        "authorized_keys" => return Some(ParserKind::AuthorizedKeys),
        "known_hosts" => return Some(ParserKind::KnownHosts),
        "sudoers" => return Some(ParserKind::Sudoers),
        _ => {}
    }

    if content.contains("-----BEGIN") {
        return None;
    }
    if looks_like_authorized_keys(content) {
        return Some(ParserKind::AuthorizedKeys);
    }
    if looks_like_hosts_file(content) {
        return Some(ParserKind::HostsFile);
    }
    if content
        .lines()
        .any(|line| line.trim_start().starts_with("Host "))
    {
        return Some(ParserKind::SshConfig);
    }
    if content
        .lines()
        .any(|line| line.to_ascii_lowercase().contains("permitrootlogin"))
    {
        return Some(ParserKind::SshdConfig);
    }

    None
}

fn looks_like_hosts_file(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.split('#').next().unwrap_or_default().trim();
        let mut parts = line.split_whitespace();
        parts
            .next()
            .is_some_and(|value| value.parse::<std::net::IpAddr>().is_ok())
            && parts.next().is_some()
    })
}

fn looks_like_authorized_keys(content: &str) -> bool {
    const KEY_TYPES: &[&str] = &["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-", "sk-ssh-ed25519"];
    content.lines().any(|line| {
        let line = line.trim_start();
        KEY_TYPES.iter().any(|key_type| line.contains(key_type))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hosts_file_by_content() {
        assert_eq!(
            detect_parser(Path::new("sample"), "10.0.0.1 web01 web01.internal"),
            Some(ParserKind::HostsFile)
        );
    }
}
