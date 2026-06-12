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
            name: "host_metadata",
            evidence_type: "host_metadata",
            command: "(cat /etc/os-release 2>/dev/null || true; printf '\\nSSHMAP_UNAME='; uname -srm 2>/dev/null || true)",
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
            name: "sshd_effective_config",
            evidence_type: "sshd_effective_config",
            command: "sshd -T 2>/dev/null",
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
        RemoteCommand {
            name: "pam_sshd",
            evidence_type: "pam_config",
            command: "cat /etc/pam.d/sshd 2>/dev/null",
            sudo_policy: SudoPolicy::Prefer,
        },
        RemoteCommand {
            name: "pam_common_auth",
            evidence_type: "pam_config",
            command: "cat /etc/pam.d/common-auth 2>/dev/null",
            sudo_policy: SudoPolicy::Prefer,
        },
        RemoteCommand {
            name: "nsswitch",
            evidence_type: "nsswitch",
            command: "cat /etc/nsswitch.conf 2>/dev/null",
            sudo_policy: SudoPolicy::Never,
        },
    ]
}

const FORBIDDEN_REMOTE_COMMAND_FRAGMENTS: &[&str] = &[
    " rm ",
    " mv ",
    " cp ",
    " touch ",
    " chmod ",
    " chown ",
    " useradd ",
    " userdel ",
    " shutdown ",
    " reboot ",
    " systemctl ",
    " service ",
    " apt ",
    " yum ",
    " dnf ",
    " pip ",
    " curl ",
    " wget ",
    " tee ",
    " dd ",
    " mkfs ",
    " mount ",
    " umount ",
];

pub fn validate_read_only_command_manifest() -> Result<(), String> {
    for command in default_remote_commands() {
        let rendered = command
            .render(false)
            .or_else(|| command.render(true))
            .ok_or_else(|| format!("command {} cannot be rendered", command.name))?;
        if let Err(reason) = is_read_only_command(&rendered) {
            return Err(format!(
                "command {} renders non read-only shell: {reason}: {rendered}",
                command.name
            ));
        }
    }
    Ok(())
}

fn is_read_only_command(command: &str) -> Result<(), &'static str> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err("empty command");
    }
    if trimmed.contains('<') {
        return Err("shell input redirection is not allowed");
    }
    if trimmed.contains('>')
        && !trimmed.contains("2>/dev/null")
        && !trimmed.contains("2> /dev/null")
    {
        return Err("shell output redirection is not allowed");
    }
    if trimmed.contains("$(`") || trimmed.contains("${") {
        return Err("command substitution is not allowed");
    }
    let lower = format!(" {trimmed} ").to_ascii_lowercase();
    for fragment in FORBIDDEN_REMOTE_COMMAND_FRAGMENTS {
        if lower.contains(fragment) {
            return Err("forbidden command fragment detected");
        }
    }
    if lower.contains(" passwd") && !lower.contains("getent passwd") {
        return Err("interactive passwd command is not allowed");
    }
    Ok(())
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
        assert!(evidence_types.contains(&"host_metadata"));
        assert!(evidence_types.contains(&"sshd_effective_config"));
    }

    #[test]
    fn remote_command_manifest_is_read_only() {
        validate_read_only_command_manifest().expect("read-only manifest");
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
