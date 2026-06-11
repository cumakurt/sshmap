mod policy;

pub use policy::{RiskPolicy, load_optional as load_risk_policy};

use crate::models::{
    GeneratedRisk, NormalizedAnalysis, ParsedAuthorizedKey, ParsedSshClientConfigEntry,
    ParsedSudoRule,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn generate_risks(analysis: &NormalizedAnalysis, policy: &RiskPolicy) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();
    risks.extend(generate_sshd_config_risks(analysis));
    risks.extend(generate_user_account_risks(analysis));
    risks.extend(generate_authorized_key_risks(analysis));
    risks.extend(generate_sudo_risks(analysis));
    risks.extend(generate_client_config_risks(analysis));
    risks.extend(generate_key_reuse_risks(analysis, policy));
    risks.extend(generate_combined_risks(analysis));
    policy::apply_policy(risks, policy)
}

fn generate_sshd_config_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();

    for entry in &analysis.sshd_config_entries {
        let key = entry.key.to_ascii_lowercase();
        let value = entry
            .value
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();

        match (key.as_str(), value.as_str()) {
            ("permitrootlogin", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_ROOT_LOGIN_ENABLED",
                severity: "CRITICAL",
                score: 95,
                title: "Root login is enabled",
                description: "The SSH daemon allows direct root login.",
                impact: "A compromised root credential or authorized key grants immediate full control of the host.",
                evidence: format!(
                    "{}:{} sets PermitRootLogin yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Set PermitRootLogin to no and require named user accounts with audited privilege escalation.",
            })),
            ("permitrootlogin", "prohibit-password" | "without-password") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_ROOT_LOGIN_WITH_KEYS",
                severity: "HIGH",
                score: 80,
                title: "Root login with public keys is enabled",
                description: "The SSH daemon permits direct root login when public key authentication is used.",
                impact: "A reused or stale root authorized key can grant direct administrative access.",
                evidence: format!(
                    "{}:{} sets PermitRootLogin {}",
                    entry.source_file, entry.line_number, value
                ),
                recommendation: "Set PermitRootLogin to no and use named accounts with sudo.",
            })),
            ("passwordauthentication", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_PASSWORD_AUTH_ENABLED",
                severity: "HIGH",
                score: 75,
                title: "Password authentication is enabled",
                description: "The SSH daemon allows password-based authentication.",
                impact: "Password authentication increases exposure to credential stuffing, password reuse, and brute-force attempts.",
                evidence: format!(
                    "{}:{} sets PasswordAuthentication yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Disable PasswordAuthentication and require public key or stronger multi-factor authentication.",
            })),
            ("permitemptypasswords", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_EMPTY_PASSWORD_ALLOWED",
                severity: "CRITICAL",
                score: 100,
                title: "Empty passwords are allowed",
                description: "The SSH daemon permits accounts with empty passwords.",
                impact: "Any account with an empty password may be remotely accessible.",
                evidence: format!(
                    "{}:{} sets PermitEmptyPasswords yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Set PermitEmptyPasswords to no and remove empty account passwords.",
            })),
            ("allowtcpforwarding", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_TCP_FORWARDING_ENABLED",
                severity: "MEDIUM",
                score: 50,
                title: "TCP forwarding is enabled",
                description: "The SSH daemon allows TCP forwarding.",
                impact: "Compromised accounts may use SSH tunnels for lateral movement or data exfiltration.",
                evidence: format!(
                    "{}:{} sets AllowTcpForwarding yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Disable AllowTcpForwarding unless explicitly required.",
            })),
            ("allowagentforwarding", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_FORWARD_AGENT_ENABLED",
                severity: "MEDIUM",
                score: 55,
                title: "SSH agent forwarding is enabled",
                description: "The SSH daemon allows agent forwarding.",
                impact: "A compromised remote host may abuse forwarded agent keys for lateral movement.",
                evidence: format!(
                    "{}:{} sets AllowAgentForwarding yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Disable AllowAgentForwarding unless explicitly required.",
            })),
            ("stricthostkeychecking", "no") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_STRICT_HOST_KEY_CHECKING_DISABLED",
                severity: "HIGH",
                score: 70,
                title: "Strict host key checking is disabled",
                description: "The SSH daemon disables strict host key checking.",
                impact: "Clients may connect without validating host identity, increasing MITM risk.",
                evidence: format!(
                    "{}:{} sets StrictHostKeyChecking no",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Set StrictHostKeyChecking to yes or accept-new.",
            })),
            ("gatewayports", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_GATEWAY_PORTS_ENABLED",
                severity: "HIGH",
                score: 65,
                title: "Gateway ports are enabled",
                description: "The SSH daemon allows remote host port forwarding bindings.",
                impact: "Remote users may expose internal services through forwarded ports.",
                evidence: format!(
                    "{}:{} sets GatewayPorts yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Disable GatewayPorts unless explicitly required.",
            })),
            _ => {}
        }
    }

    risks
}

fn generate_user_account_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    analysis
        .users
        .iter()
        .filter(|user| {
            user.is_service_account
                && user.shell.as_deref().is_some_and(|shell| {
                    shell.ends_with("/bash")
                        || shell.ends_with("/sh")
                        || shell.ends_with("/zsh")
                })
        })
        .map(|user| GeneratedRisk {
            host_id: Some(user.host_id),
            username: Some(user.username.clone()),
            public_key_fingerprint: None,
            risk_code: "USER_SERVICE_ACCOUNT_INTERACTIVE_SHELL".to_string(),
            severity: "MEDIUM".to_string(),
            score: 50,
            confidence: "HIGH".to_string(),
            title: "Service account has an interactive shell".to_string(),
            description: "A service account is configured with an interactive login shell.".to_string(),
            impact: "Service accounts with interactive shells are easier to abuse after SSH access is obtained.".to_string(),
            evidence: format!(
                "user {} uses shell {}",
                user.username,
                user.shell.as_deref().unwrap_or("-")
            ),
            recommendation: "Use /usr/sbin/nologin or a non-interactive shell for service accounts.".to_string(),
        })
        .collect()
}

fn generate_authorized_key_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let mut risks: Vec<GeneratedRisk> = analysis
        .authorized_keys
        .iter()
        .filter(|entry| authorized_key_is_unrestricted(entry))
        .map(|entry| {
            if entry.username == "root" {
                GeneratedRisk {
                    host_id: Some(entry.host_id),
                    username: Some(entry.username.clone()),
                    public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
                    risk_code: "SSH_ROOT_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS".to_string(),
                    severity: "CRITICAL".to_string(),
                    score: 90,
                    confidence: "HIGH".to_string(),
                    title: "Root authorized key has no restrictions".to_string(),
                    description: "A root authorized_keys entry does not restrict source addresses, forced command, PTY, or forwarding.".to_string(),
                    impact: "The key can provide broad interactive root access if the private key is compromised.".to_string(),
                    evidence: format!("{}:{} contains {}", entry.source_file, entry.line_number, entry.public_key.fingerprint_sha256),
                    recommendation: "Add restrictive authorized_keys options or remove direct root keys entirely.".to_string(),
                }
            } else {
                GeneratedRisk {
                    host_id: Some(entry.host_id),
                    username: Some(entry.username.clone()),
                    public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
                    risk_code: "SSH_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS".to_string(),
                    severity: "MEDIUM".to_string(),
                    score: 55,
                    confidence: "HIGH".to_string(),
                    title: "Authorized key has no restrictions".to_string(),
                    description: "An authorized_keys entry does not restrict source addresses, forced command, PTY, or forwarding.".to_string(),
                    impact: "The key can be used for broad interactive access if the private key is compromised.".to_string(),
                    evidence: format!("{}:{} contains {}", entry.source_file, entry.line_number, entry.public_key.fingerprint_sha256),
                    recommendation: "Add from=, command=, no-pty, no-port-forwarding, and no-agent-forwarding options where appropriate.".to_string(),
                }
            }
        })
        .collect();

    risks.extend(
        analysis
            .authorized_keys
            .iter()
            .filter(|entry| entry.permits_agent_forwarding && authorized_key_is_unrestricted(entry))
            .map(|entry| GeneratedRisk {
                host_id: Some(entry.host_id),
                username: Some(entry.username.clone()),
                public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
                risk_code: "SSH_FORWARD_AGENT_WILDCARD".to_string(),
                severity: "HIGH".to_string(),
                score: 70,
                confidence: "HIGH".to_string(),
                title: "Authorized key allows unrestricted agent forwarding".to_string(),
                description:
                    "An authorized_keys entry permits agent forwarding without strong restrictions."
                        .to_string(),
                impact:
                    "A compromised session may expose forwarded agent keys to lateral movement."
                        .to_string(),
                evidence: format!(
                    "{}:{} allows agent forwarding for {}",
                    entry.source_file, entry.line_number, entry.public_key.fingerprint_sha256
                ),
                recommendation:
                    "Add no-agent-forwarding or restrict the key with from= and command= options."
                        .to_string(),
            }),
    );

    risks
}

fn generate_sudo_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    analysis
        .sudo_rules
        .iter()
        .filter_map(sudo_rule_to_risk)
        .collect()
}

fn sudo_rule_to_risk(rule: &ParsedSudoRule) -> Option<GeneratedRisk> {
    let command = rule.command.as_deref().unwrap_or_default();
    if rule.nopasswd && command == "ALL" {
        return Some(GeneratedRisk {
            host_id: Some(rule.host_id),
            username: (rule.subject_type == "user").then(|| rule.subject.clone()),
            public_key_fingerprint: None,
            risk_code: "SUDO_NOPASSWD_ALL".to_string(),
            severity: "CRITICAL".to_string(),
            score: 95,
            confidence: "HIGH".to_string(),
            title: "Passwordless sudo allows all commands".to_string(),
            description: "A sudoers rule grants NOPASSWD access to ALL commands.".to_string(),
            impact: "Any SSH access to the subject can become full privileged access without another authentication step.".to_string(),
            evidence: format!("{}:{} grants {} NOPASSWD:ALL", rule.source_file, rule.line_number, rule.subject),
            recommendation: "Remove NOPASSWD:ALL and replace it with the smallest required command allowlist.".to_string(),
        });
    }

    if rule.nopasswd && rule.risk_level.as_deref() == Some("HIGH") {
        return Some(GeneratedRisk {
            host_id: Some(rule.host_id),
            username: (rule.subject_type == "user").then(|| rule.subject.clone()),
            public_key_fingerprint: None,
            risk_code: "SUDO_DANGEROUS_BINARY_NOPASSWD".to_string(),
            severity: "HIGH".to_string(),
            score: 80,
            confidence: "HIGH".to_string(),
            title: "Passwordless sudo allows a dangerous binary".to_string(),
            description: "A sudoers rule grants NOPASSWD access to a command that can often be abused for shell escape or data movement.".to_string(),
            impact: "The subject may be able to escalate privileges or move data without another authentication step.".to_string(),
            evidence: format!(
                "{}:{} grants {} NOPASSWD:{}",
                rule.source_file, rule.line_number, rule.subject, command
            ),
            recommendation: "Remove NOPASSWD for dangerous binaries or replace the command with a constrained wrapper.".to_string(),
        });
    }

    if rule.subject_type == "group" && command == "ALL" {
        return Some(GeneratedRisk {
            host_id: Some(rule.host_id),
            username: None,
            public_key_fingerprint: None,
            risk_code: "SUDO_GROUP_WIDE_ADMIN".to_string(),
            severity: "HIGH".to_string(),
            score: 85,
            confidence: "HIGH".to_string(),
            title: "Group-wide sudo grants all commands".to_string(),
            description: "A sudoers rule grants a group access to ALL commands.".to_string(),
            impact: "Any member of the group may obtain broad privileged access after SSH authentication.".to_string(),
            evidence: format!(
                "{}:{} grants %{} ALL",
                rule.source_file, rule.line_number, rule.subject
            ),
            recommendation: "Replace group-wide ALL rules with the smallest required command allowlist.".to_string(),
        });
    }

    None
}

fn generate_client_config_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();

    for entry in &analysis.ssh_client_config_entries {
        if (entry.host_pattern == "*" || entry.host_pattern.contains('*'))
            && entry.forward_agent.as_deref() == Some("yes")
        {
            risks.push(client_config_risk(
                entry,
                ClientConfigRiskDetails {
                    risk_code: "SSH_FORWARD_AGENT_WILDCARD",
                    severity: "HIGH",
                    score: 70,
                    title: "Global SSH client forward agent is enabled",
                    description: "An ssh_config Host * block enables ForwardAgent.",
                    impact: "Forwarded agent keys may be exposed on untrusted remote hosts.",
                    recommendation:
                        "Disable ForwardAgent globally or restrict it to named Host blocks.",
                },
            ));
        }

        if entry.strict_host_key_checking.as_deref() == Some("no") {
            risks.push(client_config_risk(
                entry,
                ClientConfigRiskDetails {
                    risk_code: "SSH_STRICT_HOST_KEY_CHECKING_DISABLED",
                    severity: "MEDIUM",
                    score: 55,
                    title: "SSH client disables strict host key checking",
                    description: "An ssh_config entry sets StrictHostKeyChecking to no.",
                    impact: "The client may accept unknown or changed host keys.",
                    recommendation: "Set StrictHostKeyChecking to yes or accept-new.",
                },
            ));
        }

        if entry.proxy_jump.is_some() {
            risks.push(client_config_risk(
                entry,
                ClientConfigRiskDetails {
                    risk_code: "SSH_PROXYJUMP_CHAIN_DETECTED",
                    severity: "MEDIUM",
                    score: 60,
                    title: "SSH client config defines a ProxyJump chain",
                    description:
                        "An ssh_config entry defines ProxyJump for lateral movement paths.",
                    impact:
                        "Compromise of an intermediate host may expose downstream SSH targets.",
                    recommendation:
                        "Review ProxyJump chains and restrict them to required admin paths.",
                },
            ));
        }

        if entry.remote_forward.is_some() || entry.dynamic_forward.is_some() {
            risks.push(client_config_risk(
                entry,
                ClientConfigRiskDetails {
                    risk_code: "SSH_TCP_FORWARDING_ENABLED",
                    severity: "MEDIUM",
                    score: 50,
                    title: "SSH client config enables forwarding",
                    description: "An ssh_config entry defines remote or dynamic forwarding.",
                    impact: "Compromised sessions may expose tunnels for lateral movement.",
                    recommendation:
                        "Remove unnecessary LocalForward, RemoteForward, and DynamicForward entries.",
                },
            ));
        }
    }

    risks
}

struct ClientConfigRiskDetails<'a> {
    risk_code: &'a str,
    severity: &'a str,
    score: i64,
    title: &'a str,
    description: &'a str,
    impact: &'a str,
    recommendation: &'a str,
}

fn client_config_risk(
    entry: &ParsedSshClientConfigEntry,
    details: ClientConfigRiskDetails<'_>,
) -> GeneratedRisk {
    GeneratedRisk {
        host_id: Some(entry.host_id),
        username: entry.ssh_user.clone(),
        public_key_fingerprint: None,
        risk_code: details.risk_code.to_string(),
        severity: details.severity.to_string(),
        score: details.score,
        confidence: "MEDIUM".to_string(),
        title: details.title.to_string(),
        description: details.description.to_string(),
        impact: details.impact.to_string(),
        evidence: format!(
            "{}:{} Host {} sets client SSH option",
            entry.source_file, entry.line_number, entry.host_pattern
        ),
        recommendation: details.recommendation.to_string(),
    }
}

fn generate_key_reuse_risks(
    analysis: &NormalizedAnalysis,
    policy: &RiskPolicy,
) -> Vec<GeneratedRisk> {
    let high_threshold = policy.key_reuse_high_threshold();
    let critical_threshold = policy.key_reuse_critical_threshold();
    let mut by_fingerprint: BTreeMap<&str, Vec<&ParsedAuthorizedKey>> = BTreeMap::new();
    for entry in &analysis.authorized_keys {
        by_fingerprint
            .entry(entry.public_key.fingerprint_sha256.as_str())
            .or_default()
            .push(entry);
    }

    let mut risks = Vec::new();
    for (fingerprint, entries) in by_fingerprint {
        let host_count = entries
            .iter()
            .map(|entry| entry.host_id)
            .collect::<BTreeSet<_>>()
            .len();
        let usernames = entries
            .iter()
            .map(|entry| entry.username.as_str())
            .collect::<BTreeSet<_>>();
        let has_root = usernames.contains("root");

        if host_count >= critical_threshold {
            risks.push(GeneratedRisk {
                host_id: None,
                username: None,
                public_key_fingerprint: Some(fingerprint.to_string()),
                risk_code: "SSH_KEY_REUSED_MANY_HOSTS".to_string(),
                severity: "CRITICAL".to_string(),
                score: 95,
                confidence: "HIGH".to_string(),
                title: "SSH public key is reused across many hosts".to_string(),
                description: format!(
                    "The same SSH public key appears in authorized_keys on at least {critical_threshold} hosts."
                ),
                impact: "Compromise of the matching private key can expose many systems at once.".to_string(),
                evidence: format!("{fingerprint} appears on {host_count} hosts"),
                recommendation: "Replace shared keys with host- or user-scoped keys and remove stale authorized_keys entries.".to_string(),
            });
        } else if host_count >= high_threshold {
            risks.push(GeneratedRisk {
                host_id: None,
                username: None,
                public_key_fingerprint: Some(fingerprint.to_string()),
                risk_code: "SSH_KEY_REUSED_MANY_HOSTS".to_string(),
                severity: "HIGH".to_string(),
                score: 75,
                confidence: "HIGH".to_string(),
                title: "SSH public key is reused across many hosts".to_string(),
                description: format!(
                    "The same SSH public key appears in authorized_keys on at least {high_threshold} hosts."
                ),
                impact: "Compromise of the matching private key can expose multiple systems at once.".to_string(),
                evidence: format!("{fingerprint} appears on {host_count} hosts"),
                recommendation: "Replace shared keys with host- or user-scoped keys and remove stale authorized_keys entries.".to_string(),
            });
        }

        if has_root && host_count > 1 {
            risks.push(GeneratedRisk {
                host_id: None,
                username: Some("root".to_string()),
                public_key_fingerprint: Some(fingerprint.to_string()),
                risk_code: "SSH_KEY_REUSED_ROOT".to_string(),
                severity: "CRITICAL".to_string(),
                score: 95,
                confidence: "HIGH".to_string(),
                title: "SSH public key is reused for root access".to_string(),
                description: "The same SSH public key grants root access and appears on more than one host.".to_string(),
                impact: "A single private key compromise can grant direct or near-direct administrative access across hosts.".to_string(),
                evidence: format!("{fingerprint} appears on {host_count} hosts and includes root"),
                recommendation: "Remove shared root keys and disable direct root SSH login.".to_string(),
            });
        }

        if usernames.len() > 1 {
            risks.push(GeneratedRisk {
                host_id: None,
                username: None,
                public_key_fingerprint: Some(fingerprint.to_string()),
                risk_code: "SSH_KEY_USED_BY_MULTIPLE_USERS".to_string(),
                severity: "MEDIUM".to_string(),
                score: 60,
                confidence: "HIGH".to_string(),
                title: "SSH public key is used by multiple users".to_string(),
                description: "The same SSH public key appears under multiple usernames.".to_string(),
                impact: "Identity attribution becomes weaker and a single private key can cross user boundaries.".to_string(),
                evidence: format!("{fingerprint} appears for {} usernames", usernames.len()),
                recommendation: "Assign unique public keys per user identity and remove shared personal keys.".to_string(),
            });
        }
    }

    risks
}

fn generate_combined_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let mut by_fingerprint: BTreeMap<&str, Vec<&ParsedAuthorizedKey>> = BTreeMap::new();
    for entry in &analysis.authorized_keys {
        by_fingerprint
            .entry(entry.public_key.fingerprint_sha256.as_str())
            .or_default()
            .push(entry);
    }

    let nopasswd_users_by_host: BTreeMap<i64, BTreeSet<String>> = analysis
        .sudo_rules
        .iter()
        .filter(|rule| rule.nopasswd && rule.subject_type == "user")
        .fold(BTreeMap::new(), |mut map, rule| {
            map.entry(rule.host_id)
                .or_default()
                .insert(rule.subject.clone());
            map
        });

    let mut risks = Vec::new();
    for (fingerprint, entries) in by_fingerprint {
        let host_ids = entries
            .iter()
            .map(|entry| entry.host_id)
            .collect::<BTreeSet<_>>();
        if host_ids.len() < 2 {
            continue;
        }

        let mut sudo_hosts = BTreeSet::new();
        for entry in entries {
            if nopasswd_users_by_host
                .get(&entry.host_id)
                .is_some_and(|users| users.contains(&entry.username))
            {
                sudo_hosts.insert(entry.host_id);
            }
        }

        if sudo_hosts.is_empty() {
            continue;
        }

        risks.push(GeneratedRisk {
            host_id: None,
            username: None,
            public_key_fingerprint: Some(fingerprint.to_string()),
            risk_code: "SSH_KEY_REUSE_WITH_SUDO".to_string(),
            severity: "CRITICAL".to_string(),
            score: 100,
            confidence: "HIGH".to_string(),
            title: "Reused SSH key reaches passwordless sudo".to_string(),
            description: "The same SSH public key appears on multiple hosts and at least one target user has passwordless sudo.".to_string(),
            impact: "Compromise of one private key can expose multiple systems and escalate to privileged access without another authentication step.".to_string(),
            evidence: format!(
                "{fingerprint} used on {} hosts; passwordless sudo found on {} host(s)",
                host_ids.len(),
                sudo_hosts.len()
            ),
            recommendation: "Remove shared keys, disable passwordless sudo, and enforce unique keys per user and host.".to_string(),
        });
    }

    risks
}

fn authorized_key_is_unrestricted(entry: &ParsedAuthorizedKey) -> bool {
    !entry.has_from_restriction
        && !entry.has_command_restriction
        && entry.permits_pty
        && entry.permits_port_forwarding
        && entry.permits_agent_forwarding
        && entry.permits_x11_forwarding
}

struct HostRiskInput<'a> {
    host_id: i64,
    risk_code: &'a str,
    severity: &'a str,
    score: i64,
    title: &'a str,
    description: &'a str,
    impact: &'a str,
    evidence: String,
    recommendation: &'a str,
}

fn host_risk(input: HostRiskInput<'_>) -> GeneratedRisk {
    GeneratedRisk {
        host_id: Some(input.host_id),
        username: None,
        public_key_fingerprint: None,
        risk_code: input.risk_code.to_string(),
        severity: input.severity.to_string(),
        score: input.score,
        confidence: "HIGH".to_string(),
        title: input.title.to_string(),
        description: input.description.to_string(),
        impact: input.impact.to_string(),
        evidence: input.evidence,
        recommendation: input.recommendation.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        NormalizedAnalysis, ParsedAuthorizedKey, ParsedPublicKey, ParsedSshdConfigEntry,
        ParsedSudoRule,
    };

    #[test]
    fn generates_root_login_and_password_auth_risks() {
        let analysis = NormalizedAnalysis {
            sshd_config_entries: vec![
                ParsedSshdConfigEntry {
                    host_id: 1,
                    key: "PermitRootLogin".to_string(),
                    value: Some("yes".to_string()),
                    source_file: "/etc/ssh/sshd_config".to_string(),
                    line_number: 1,
                },
                ParsedSshdConfigEntry {
                    host_id: 1,
                    key: "PasswordAuthentication".to_string(),
                    value: Some("yes".to_string()),
                    source_file: "/etc/ssh/sshd_config".to_string(),
                    line_number: 2,
                },
            ],
            ..Default::default()
        };

        let codes = generate_risks(&analysis, &RiskPolicy::default())
            .into_iter()
            .map(|risk| risk.risk_code)
            .collect::<BTreeSet<_>>();

        assert!(codes.contains("SSH_ROOT_LOGIN_ENABLED"));
        assert!(codes.contains("SSH_PASSWORD_AUTH_ENABLED"));
    }

    #[test]
    fn generates_sudo_nopasswd_all_risk() {
        let analysis = NormalizedAnalysis {
            sudo_rules: vec![ParsedSudoRule {
                host_id: 1,
                subject: "deploy".to_string(),
                subject_type: "user".to_string(),
                run_as: Some("ALL".to_string()),
                command: Some("ALL".to_string()),
                tags: Some("NOPASSWD".to_string()),
                nopasswd: true,
                source_file: "/etc/sudoers".to_string(),
                line_number: 1,
                risk_level: Some("CRITICAL".to_string()),
            }],
            ..Default::default()
        };

        let risks = generate_risks(&analysis, &RiskPolicy::default());

        assert_eq!(risks[0].risk_code, "SUDO_NOPASSWD_ALL");
    }

    #[test]
    fn generates_unrestricted_authorized_key_risk() {
        let analysis = NormalizedAnalysis {
            authorized_keys: vec![authorized_key(1, "deploy", "SHA256:test")],
            ..Default::default()
        };

        let risks = generate_risks(&analysis, &RiskPolicy::default());

        assert!(
            risks
                .iter()
                .any(|risk| risk.risk_code == "SSH_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS")
        );
    }

    #[test]
    fn generates_key_reuse_risk_at_five_hosts() {
        let analysis = NormalizedAnalysis {
            authorized_keys: (1..=5)
                .map(|host_id| authorized_key(host_id, "deploy", "SHA256:shared"))
                .collect(),
            ..Default::default()
        };

        let risks = generate_risks(&analysis, &RiskPolicy::default());

        assert!(
            risks
                .iter()
                .any(|risk| risk.risk_code == "SSH_KEY_REUSED_MANY_HOSTS")
        );
    }

    fn authorized_key(host_id: i64, username: &str, fingerprint: &str) -> ParsedAuthorizedKey {
        ParsedAuthorizedKey {
            host_id,
            username: username.to_string(),
            public_key: ParsedPublicKey {
                key_type: "ssh-ed25519".to_string(),
                fingerprint_sha256: fingerprint.to_string(),
                key_comment: None,
                normalized_public_key: format!("ssh-ed25519 {fingerprint}"),
            },
            source_file: format!("/home/{username}/.ssh/authorized_keys"),
            line_number: 1,
            options: None,
            has_from_restriction: false,
            has_command_restriction: false,
            permits_pty: true,
            permits_port_forwarding: true,
            permits_agent_forwarding: true,
            permits_x11_forwarding: true,
        }
    }
}
