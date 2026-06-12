#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SudoPolicy {
    Never,
    Prefer,
    Require,
}

#[derive(Debug, Clone, Copy)]
pub struct RemoteCommand {
    pub name: &'static str,
    pub evidence_type: &'static str,
    pub command: &'static str,
    pub sudo_policy: SudoPolicy,
}

impl RemoteCommand {
    pub fn render(self, sudo_enabled: bool) -> Option<String> {
        match self.sudo_policy {
            SudoPolicy::Never => Some(self.command.to_string()),
            SudoPolicy::Prefer if sudo_enabled => Some(format!("sudo -n {}", self.command)),
            SudoPolicy::Prefer => Some(self.command.to_string()),
            SudoPolicy::Require if sudo_enabled => Some(format!("sudo -n {}", self.command)),
            SudoPolicy::Require => None,
        }
    }
}

pub fn default_local_commands() -> Vec<RemoteCommand> {
    default_remote_commands()
}

pub fn default_remote_commands() -> Vec<RemoteCommand> {
    vec![
        RemoteCommand {
            name: "hostname",
            evidence_type: "hostname",
            command: "hostname -f || hostname",
            sudo_policy: SudoPolicy::Never,
        },
        RemoteCommand {
            name: "passwd",
            evidence_type: "passwd",
            command: "getent passwd",
            sudo_policy: SudoPolicy::Never,
        },
        RemoteCommand {
            name: "group",
            evidence_type: "group",
            command: "getent group",
            sudo_policy: SudoPolicy::Never,
        },
        RemoteCommand {
            name: "hosts_file",
            evidence_type: "hosts_file",
            command: "cat /etc/hosts 2>/dev/null",
            sudo_policy: SudoPolicy::Never,
        },
        RemoteCommand {
            name: "sshd_config",
            evidence_type: "sshd_config",
            command: "cat /etc/ssh/sshd_config 2>/dev/null",
            sudo_policy: SudoPolicy::Prefer,
        },
        RemoteCommand {
            name: "sshd_config_directory",
            evidence_type: "sshd_config",
            command: "find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' -exec sh -c 'for file do printf \"\\n--- SSHMAP_FILE:%s ---\\n\" \"$file\"; cat \"$file\" 2>/dev/null; done' sh {} + 2>/dev/null",
            sudo_policy: SudoPolicy::Prefer,
        },
        RemoteCommand {
            name: "home_authorized_keys",
            evidence_type: "authorized_keys",
            command: "find /home -maxdepth 3 -path '*/.ssh/authorized_keys' -type f -exec sh -c 'for file do printf \"\\n--- SSHMAP_FILE:%s ---\\n\" \"$file\"; cat \"$file\" 2>/dev/null; done' sh {} + 2>/dev/null",
            sudo_policy: SudoPolicy::Prefer,
        },
        RemoteCommand {
            name: "root_authorized_keys",
            evidence_type: "authorized_keys",
            command: "cat /root/.ssh/authorized_keys 2>/dev/null",
            sudo_policy: SudoPolicy::Require,
        },
        RemoteCommand {
            name: "sudoers",
            evidence_type: "sudoers",
            command: "cat /etc/sudoers 2>/dev/null",
            sudo_policy: SudoPolicy::Require,
        },
        RemoteCommand {
            name: "sudoers_directory",
            evidence_type: "sudoers",
            command: "find /etc/sudoers.d -maxdepth 1 -type f -exec sh -c 'for file do printf \"\\n--- SSHMAP_FILE:%s ---\\n\" \"$file\"; cat \"$file\" 2>/dev/null; done' sh {} + 2>/dev/null",
            sudo_policy: SudoPolicy::Require,
        },
        RemoteCommand {
            name: "user_known_hosts",
            evidence_type: "known_hosts",
            command: "find /home -maxdepth 3 -path '*/.ssh/known_hosts' -type f -exec sh -c 'for file do printf \"\\n--- SSHMAP_FILE:%s ---\\n\" \"$file\"; cat \"$file\" 2>/dev/null; done' sh {} + 2>/dev/null",
            sudo_policy: SudoPolicy::Prefer,
        },
        RemoteCommand {
            name: "root_known_hosts",
            evidence_type: "known_hosts",
            command: "cat /root/.ssh/known_hosts 2>/dev/null",
            sudo_policy: SudoPolicy::Require,
        },
        RemoteCommand {
            name: "system_ssh_config",
            evidence_type: "ssh_config",
            command: "cat /etc/ssh/ssh_config 2>/dev/null",
            sudo_policy: SudoPolicy::Never,
        },
        RemoteCommand {
            name: "system_ssh_config_directory",
            evidence_type: "ssh_config",
            command: "find /etc/ssh/ssh_config.d -maxdepth 1 -type f -name '*.conf' -exec sh -c 'for file do printf \"\\n--- SSHMAP_FILE:%s ---\\n\" \"$file\"; cat \"$file\" 2>/dev/null; done' sh {} + 2>/dev/null",
            sudo_policy: SudoPolicy::Never,
        },
        RemoteCommand {
            name: "user_ssh_config",
            evidence_type: "ssh_config",
            command: "find /home -maxdepth 3 -path '*/.ssh/config' -type f -exec sh -c 'for file do printf \"\\n--- SSHMAP_FILE:%s ---\\n\" \"$file\"; cat \"$file\" 2>/dev/null; done' sh {} + 2>/dev/null",
            sudo_policy: SudoPolicy::Prefer,
        },
        RemoteCommand {
            name: "root_ssh_config",
            evidence_type: "ssh_config",
            command: "cat /root/.ssh/config 2>/dev/null",
            sudo_policy: SudoPolicy::Require,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_sudo_required_commands_when_sudo_is_disabled() {
        let command = RemoteCommand {
            name: "sudoers",
            evidence_type: "sudoers",
            command: "cat /etc/sudoers",
            sudo_policy: SudoPolicy::Require,
        };

        assert_eq!(command.render(false), None);
    }

    #[test]
    fn includes_client_side_collection_commands() {
        let commands = default_remote_commands();
        let evidence_types = commands
            .iter()
            .map(|command| command.evidence_type)
            .collect::<Vec<_>>();

        assert!(evidence_types.contains(&"known_hosts"));
        assert!(evidence_types.contains(&"ssh_config"));
        assert!(evidence_types.contains(&"hosts_file"));
    }

    #[test]
    fn prefixes_sudo_when_required_and_enabled() {
        let command = RemoteCommand {
            name: "sudoers",
            evidence_type: "sudoers",
            command: "cat /etc/sudoers",
            sudo_policy: SudoPolicy::Require,
        };

        assert_eq!(
            command.render(true),
            Some("sudo -n cat /etc/sudoers".to_string())
        );
    }
}
