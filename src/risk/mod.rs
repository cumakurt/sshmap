mod enrichment;
mod policy;

pub use policy::{RiskPolicy, load_optional as load_risk_policy};

use crate::models::{
    GeneratedRisk, NormalizedAnalysis, ParsedAuthorizedKey, ParsedSshClientConfigEntry,
    ParsedSudoRule, RemediationRecord,
};
use std::collections::{BTreeMap, BTreeSet};

pub use enrichment::RiskEnrichmentInput;

const VALID_RISK_SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW"];

pub fn validate_risk_severity(severity: &str) -> anyhow::Result<()> {
    if VALID_RISK_SEVERITIES.contains(&severity) {
        Ok(())
    } else {
        anyhow::bail!("severity must be one of CRITICAL, HIGH, MEDIUM, or LOW")
    }
}

pub fn remediation_for_code(risk_code: &str) -> Option<RemediationRecord> {
    let code = risk_code.trim().to_ascii_uppercase();
    let record = match code.as_str() {
        "SSH_ROOT_LOGIN_ENABLED" | "SSH_ROOT_LOGIN_WITH_KEYS" => RemediationRecord {
            risk_code: code,
            title: "Disable direct root SSH login".to_string(),
            verify: vec![
                "sshd -T | grep -i '^permitrootlogin'".to_string(),
                "grep -Rni '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null".to_string(),
            ],
            fix: vec![
                "Set PermitRootLogin no in sshd_config or an included drop-in.".to_string(),
                "Reload SSH with systemctl reload sshd or systemctl reload ssh.".to_string(),
            ],
            rollback: vec!["Restore the previous PermitRootLogin value and reload SSH.".to_string()],
            ansible: Some(
                "- lineinfile:\n    path: /etc/ssh/sshd_config\n    regexp: '^#?PermitRootLogin'\n    line: 'PermitRootLogin no'\n  notify: reload sshd".to_string(),
            ),
        },
        "SSH_PASSWORD_AUTH_ENABLED" => RemediationRecord {
            risk_code: code,
            title: "Disable SSH password authentication".to_string(),
            verify: vec!["sshd -T | grep -i '^passwordauthentication'".to_string()],
            fix: vec![
                "Set PasswordAuthentication no after confirming key-based access works.".to_string(),
                "Reload SSH and test a new session before closing the current one.".to_string(),
            ],
            rollback: vec!["Set PasswordAuthentication yes and reload SSH if emergency access is required.".to_string()],
            ansible: Some(
                "- lineinfile:\n    path: /etc/ssh/sshd_config\n    regexp: '^#?PasswordAuthentication'\n    line: 'PasswordAuthentication no'\n  notify: reload sshd".to_string(),
            ),
        },
        "SSH_EMPTY_PASSWORD_ALLOWED" => RemediationRecord {
            risk_code: code,
            title: "Reject empty-password SSH logins".to_string(),
            verify: vec!["sshd -T | grep -i '^permitemptypasswords'".to_string()],
            fix: vec![
                "Set PermitEmptyPasswords no.".to_string(),
                "Lock or set passwords for any account with an empty password hash.".to_string(),
            ],
            rollback: vec!["Restore the previous PermitEmptyPasswords value only for controlled break-glass recovery.".to_string()],
            ansible: None,
        },
        "SSH_FORWARD_AGENT_ENABLED" | "SSH_FORWARD_AGENT_WILDCARD" => RemediationRecord {
            risk_code: code,
            title: "Restrict SSH agent forwarding".to_string(),
            verify: vec!["sshd -T | grep -i '^allowagentforwarding'".to_string()],
            fix: vec![
                "Set AllowAgentForwarding no where forwarding is not required.".to_string(),
                "Add no-agent-forwarding to broad authorized_keys entries.".to_string(),
            ],
            rollback: vec!["Re-enable forwarding for a narrow Match block or specific key if required.".to_string()],
            ansible: None,
        },
        "SSH_TCP_FORWARDING_ENABLED" | "SSH_GATEWAY_PORTS_ENABLED" => RemediationRecord {
            risk_code: code,
            title: "Restrict SSH forwarding exposure".to_string(),
            verify: vec![
                "sshd -T | grep -Ei '^(allowtcpforwarding|gatewayports)'".to_string(),
            ],
            fix: vec![
                "Disable forwarding globally unless explicitly required.".to_string(),
                "Use Match blocks for narrow exceptions.".to_string(),
            ],
            rollback: vec!["Restore previous forwarding settings for approved workflows.".to_string()],
            ansible: None,
        },
        "SSH_MAX_AUTH_TRIES_HIGH" => RemediationRecord {
            risk_code: code,
            title: "Lower SSH authentication retry count".to_string(),
            verify: vec!["sshd -T | grep -i '^maxauthtries'".to_string()],
            fix: vec!["Set MaxAuthTries to 3 or 4 and reload SSH.".to_string()],
            rollback: vec!["Restore the previous MaxAuthTries value and reload SSH.".to_string()],
            ansible: None,
        },
        "SSH_PERMIT_USER_ENVIRONMENT" => RemediationRecord {
            risk_code: code,
            title: "Disable user-controlled SSH environment".to_string(),
            verify: vec!["sshd -T | grep -i '^permituserenvironment'".to_string()],
            fix: vec!["Set PermitUserEnvironment no and reload SSH.".to_string()],
            rollback: vec![
                "Restore the previous PermitUserEnvironment value for approved use cases."
                    .to_string(),
            ],
            ansible: None,
        },
        "SSH_X11_FORWARDING_ENABLED" => RemediationRecord {
            risk_code: code,
            title: "Disable SSH X11 forwarding".to_string(),
            verify: vec!["sshd -T | grep -i '^x11forwarding'".to_string()],
            fix: vec!["Set X11Forwarding no and reload SSH.".to_string()],
            rollback: vec!["Restore X11Forwarding for approved desktop workflows.".to_string()],
            ansible: None,
        },
        "SSHD_EFFECTIVE_CONFIG_MISMATCH" => RemediationRecord {
            risk_code: code,
            title: "Reconcile file and effective SSHD configuration".to_string(),
            verify: vec![
                "sshd -T | sort".to_string(),
                "grep -Rni '<reported directive>' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null".to_string(),
            ],
            fix: vec![
                "Review Include and Match blocks that change the effective value.".to_string(),
                "Move the intended setting into a deterministic drop-in and reload SSH.".to_string(),
            ],
            rollback: vec!["Restore the previous drop-in or directive ordering.".to_string()],
            ansible: None,
        },
        "SSH_WEAK_KEY_ALGORITHM" | "SSH_LEGACY_RSA_KEY" => RemediationRecord {
            risk_code: code,
            title: "Rotate weak SSH authorized keys".to_string(),
            verify: vec!["Review the reported authorized_keys file and fingerprint.".to_string()],
            fix: vec![
                "Replace DSA and legacy ssh-rsa keys with Ed25519 or RSA >= 3072-bit keys."
                    .to_string(),
                "Remove the old public key after confirming replacement access.".to_string(),
            ],
            rollback: vec!["Temporarily restore the previous public key if replacement access fails.".to_string()],
            ansible: None,
        },
        "SSH_CERTIFICATE_AUTHORIZED_KEY" => RemediationRecord {
            risk_code: code,
            title: "Review SSH certificate trust".to_string(),
            verify: vec!["Inspect certificate principals, CA trust, and validity policy.".to_string()],
            fix: vec![
                "Constrain certificate principals and CA trust to required users and hosts."
                    .to_string(),
                "Use short certificate lifetimes and monitored CA issuance.".to_string(),
            ],
            rollback: vec!["Restore previous authorized_keys certificate entries if access breaks.".to_string()],
            ansible: None,
        },
        "SUDO_WILDCARD_COMMAND" => RemediationRecord {
            risk_code: code,
            title: "Replace wildcard sudoers commands".to_string(),
            verify: vec!["Inspect the reported sudoers file and command pattern.".to_string()],
            fix: vec!["Use exact command paths and constrained arguments instead of wildcards.".to_string()],
            rollback: vec!["Restore the previous sudoers entry if the allowlist is incomplete.".to_string()],
            ansible: None,
        },
        "SSH_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS"
        | "SSH_ROOT_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS" => RemediationRecord {
            risk_code: code,
            title: "Restrict broad authorized_keys entries".to_string(),
            verify: vec!["Inspect the reported authorized_keys source file and line number.".to_string()],
            fix: vec![
                "Add from=, command=, no-pty, no-port-forwarding, and no-agent-forwarding where appropriate.".to_string(),
                "Remove stale or unknown keys.".to_string(),
            ],
            rollback: vec!["Restore the previous authorized_keys line from backup if access is broken.".to_string()],
            ansible: None,
        },
        "SSH_PUBLIC_KEY_REUSED" | "SSH_PUBLIC_KEY_REUSED_WIDELY" => RemediationRecord {
            risk_code: code,
            title: "Rotate reused SSH keys".to_string(),
            verify: vec!["List all locations for the key fingerprint in SSHMap key detail.".to_string()],
            fix: vec![
                "Issue unique keys per user and environment.".to_string(),
                "Remove the reused public key after rollout.".to_string(),
            ],
            rollback: vec!["Temporarily restore the previous key only for hosts that failed rollout validation.".to_string()],
            ansible: None,
        },
        _ => return None,
    };

    Some(record)
}

pub fn generate_risks_with_enrichment(
    analysis: &NormalizedAnalysis,
    policy: &RiskPolicy,
    enrichment_input: &enrichment::RiskEnrichmentInput<'_>,
) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();
    risks.extend(generate_sshd_config_risks(analysis));
    risks.extend(generate_user_account_risks(analysis));
    risks.extend(generate_authorized_key_risks(analysis));
    risks.extend(generate_sudo_risks(analysis));
    risks.extend(generate_client_config_risks(analysis));
    risks.extend(generate_key_reuse_risks(analysis, policy));
    risks.extend(generate_combined_risks(analysis));
    risks.extend(enrichment::generate_banner_cve_risks(enrichment_input));
    risks.extend(enrichment::generate_key_rotation_risks(
        enrichment_input,
        policy,
    ));
    risks.extend(enrichment::generate_server_host_key_risks(enrichment_input));
    risks.extend(generate_pam_risks(analysis));
    risks.extend(generate_match_block_risks(analysis));
    risks.extend(generate_certificate_expiry_risks(analysis));
    risks.extend(generate_sudo_escalation_path_risks(analysis));
    enrichment::apply_context_scoring(&mut risks, enrichment_input.hosts);
    policy::apply_policy(risks, policy)
}

fn generate_sshd_config_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();

    for entry in sshd_entries_for_risk(analysis) {
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
            ("maxauthtries", value) if value.parse::<i64>().is_ok_and(|tries| tries > 4) => {
                risks.push(host_risk(HostRiskInput {
                    host_id: entry.host_id,
                    risk_code: "SSH_MAX_AUTH_TRIES_HIGH",
                    severity: "MEDIUM",
                    score: 45,
                    title: "SSH MaxAuthTries is high",
                    description: "The SSH daemon permits many authentication attempts per connection.",
                    impact: "Higher retry counts increase the online brute-force surface and slow lockout detection.",
                    evidence: format!(
                        "{}:{} sets MaxAuthTries {}",
                        entry.source_file, entry.line_number, value
                    ),
                    recommendation: "Set MaxAuthTries to 3 or 4 unless there is a documented operational need.",
                }));
            }
            ("permituserenvironment", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_PERMIT_USER_ENVIRONMENT",
                severity: "HIGH",
                score: 70,
                title: "User-controlled SSH environment is enabled",
                description: "The SSH daemon allows users to set environment variables through SSH.",
                impact: "User-controlled environment variables can bypass assumptions in forced commands or privileged wrappers.",
                evidence: format!(
                    "{}:{} sets PermitUserEnvironment yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Set PermitUserEnvironment to no unless tightly controlled.",
            })),
            ("x11forwarding", "yes") => risks.push(host_risk(HostRiskInput {
                host_id: entry.host_id,
                risk_code: "SSH_X11_FORWARDING_ENABLED",
                severity: "MEDIUM",
                score: 45,
                title: "X11 forwarding is enabled",
                description: "The SSH daemon allows X11 forwarding.",
                impact: "Compromised sessions may expose desktop authentication channels or expand lateral movement options.",
                evidence: format!(
                    "{}:{} sets X11Forwarding yes",
                    entry.source_file, entry.line_number
                ),
                recommendation: "Disable X11Forwarding unless it is explicitly required.",
            })),
            _ => {}
        }
    }

    risks.extend(generate_sshd_effective_mismatch_risks(analysis));
    risks
}

fn sshd_entries_for_risk(
    analysis: &NormalizedAnalysis,
) -> Vec<&crate::models::ParsedSshdConfigEntry> {
    let hosts_with_effective = analysis
        .sshd_config_entries
        .iter()
        .filter(|entry| entry.effective)
        .map(|entry| entry.host_id)
        .collect::<std::collections::BTreeSet<_>>();

    analysis
        .sshd_config_entries
        .iter()
        .filter(|entry| {
            if hosts_with_effective.contains(&entry.host_id) {
                entry.effective
            } else {
                !entry.effective
            }
        })
        .collect()
}

fn generate_sshd_effective_mismatch_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    const WATCHED_KEYS: &[&str] = &[
        "permitrootlogin",
        "passwordauthentication",
        "permitemptypasswords",
        "allowtcpforwarding",
        "allowagentforwarding",
        "gatewayports",
        "maxauthtries",
        "permituserenvironment",
        "x11forwarding",
    ];

    let mut by_host_key: BTreeMap<(i64, String), (Option<String>, Option<String>)> =
        BTreeMap::new();
    for entry in &analysis.sshd_config_entries {
        let key = entry.key.to_ascii_lowercase();
        if !WATCHED_KEYS.contains(&key.as_str()) {
            continue;
        }
        let values = by_host_key.entry((entry.host_id, key)).or_default();
        if entry.effective {
            values.1 = entry.value.clone();
        } else {
            values.0 = entry.value.clone();
        }
    }

    by_host_key
        .into_iter()
        .filter_map(|((host_id, key), (file_value, effective_value))| {
            let file_value = file_value?;
            let effective_value = effective_value?;
            if file_value.eq_ignore_ascii_case(&effective_value) {
                return None;
            }
            Some(host_risk(HostRiskInput {
                host_id,
                risk_code: "SSHD_EFFECTIVE_CONFIG_MISMATCH",
                severity: "LOW",
                score: 30,
                title: "SSHD file config differs from effective config",
                description: "The parsed sshd_config file value differs from sshd -T effective output.",
                impact: "Drop-ins, defaults, or Match blocks may make file review misleading.",
                evidence: format!("{key}: file={file_value}, effective={effective_value}"),
                recommendation: "Review sshd -T output together with included files and Match blocks before remediation.",
            }))
        })
        .collect()
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

    risks.extend(analysis.authorized_keys.iter().filter_map(weak_key_risk));

    risks
}

fn weak_key_risk(entry: &ParsedAuthorizedKey) -> Option<GeneratedRisk> {
    let key_type = entry.public_key.key_type.as_str();
    if key_type == "ssh-dss" {
        return Some(GeneratedRisk {
            host_id: Some(entry.host_id),
            username: Some(entry.username.clone()),
            public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
            risk_code: "SSH_WEAK_KEY_ALGORITHM".to_string(),
            severity: "HIGH".to_string(),
            score: 78,
            confidence: "HIGH".to_string(),
            title: "Authorized key uses DSA".to_string(),
            description: "An authorized_keys entry uses the legacy ssh-dss algorithm.".to_string(),
            impact: "DSA keys are deprecated and may be disabled by modern SSH clients and policy baselines.".to_string(),
            evidence: format!(
                "{}:{} contains {} {}",
                entry.source_file,
                entry.line_number,
                key_type,
                entry.public_key.fingerprint_sha256
            ),
            recommendation: "Replace DSA keys with Ed25519 or RSA keys of at least 3072 bits.".to_string(),
        });
    }

    if key_type == "ssh-rsa" {
        let bits = entry.public_key.key_bits.unwrap_or_default();
        let (risk_code, severity, score, title, description) = if bits > 0 && bits < 2048 {
            (
                "SSH_LEGACY_RSA_KEY",
                "HIGH",
                76,
                "Authorized key uses weak RSA length",
                "An authorized_keys entry uses an RSA key smaller than 2048 bits.",
            )
        } else {
            (
                "SSH_WEAK_KEY_ALGORITHM",
                "MEDIUM",
                58,
                "Authorized key uses legacy ssh-rsa",
                "An authorized_keys entry uses the legacy ssh-rsa key type.",
            )
        };

        return Some(GeneratedRisk {
            host_id: Some(entry.host_id),
            username: Some(entry.username.clone()),
            public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
            risk_code: risk_code.to_string(),
            severity: severity.to_string(),
            score,
            confidence: "HIGH".to_string(),
            title: title.to_string(),
            description: description.to_string(),
            impact: "Legacy RSA/SHA-1 compatibility can weaken SSH authentication posture and may fail modern compliance baselines.".to_string(),
            evidence: format!(
                "{}:{} contains {} {} ({} bits)",
                entry.source_file,
                entry.line_number,
                key_type,
                entry.public_key.fingerprint_sha256,
                if bits > 0 { bits.to_string() } else { "unknown".to_string() }
            ),
            recommendation: "Prefer Ed25519 keys or RSA keys of at least 3072 bits; disable SHA-1 ssh-rsa signatures where possible.".to_string(),
        });
    }

    if key_type.ends_with("-cert-v01@openssh.com") {
        return Some(GeneratedRisk {
            host_id: Some(entry.host_id),
            username: Some(entry.username.clone()),
            public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
            risk_code: "SSH_CERTIFICATE_AUTHORIZED_KEY".to_string(),
            severity: "LOW".to_string(),
            score: 30,
            confidence: "MEDIUM".to_string(),
            title: "Authorized key is an SSH certificate".to_string(),
            description: "An authorized_keys entry accepts an SSH certificate key type.".to_string(),
            impact: "Certificate-based SSH should be reviewed for CA trust scope, principals, and expiry policy.".to_string(),
            evidence: format!(
                "{}:{} contains {} {}",
                entry.source_file,
                entry.line_number,
                key_type,
                entry.public_key.fingerprint_sha256
            ),
            recommendation: "Review SSH CA policy, principal constraints, and certificate validity periods.".to_string(),
        });
    }

    None
}

fn generate_certificate_expiry_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let now = chrono::Utc::now().timestamp();
    let soon = now + 14 * 86_400;
    analysis
        .authorized_keys
        .iter()
        .filter_map(|entry| {
            let valid_before = entry.public_key.certificate_valid_before?;
            if valid_before == 0 {
                return None;
            }
            if valid_before < now {
                return Some(GeneratedRisk {
                    host_id: Some(entry.host_id),
                    username: Some(entry.username.clone()),
                    public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
                    risk_code: "SSH_CERTIFICATE_EXPIRED".to_string(),
                    severity: "HIGH".to_string(),
                    score: 82,
                    confidence: "HIGH".to_string(),
                    title: "SSH certificate in authorized_keys has expired".to_string(),
                    description: "An authorized_keys certificate is past its valid-before timestamp.".to_string(),
                    impact: "Expired certificates may indicate stale access grants or broken rotation workflows.".to_string(),
                    evidence: format!(
                        "{}:{} valid_before={valid_before}",
                        entry.source_file, entry.line_number
                    ),
                    recommendation: "Remove expired certificates and reissue credentials through the SSH CA.".to_string(),
                });
            }
            if valid_before <= soon {
                return Some(GeneratedRisk {
                    host_id: Some(entry.host_id),
                    username: Some(entry.username.clone()),
                    public_key_fingerprint: Some(entry.public_key.fingerprint_sha256.clone()),
                    risk_code: "SSH_CERTIFICATE_EXPIRING_SOON".to_string(),
                    severity: "MEDIUM".to_string(),
                    score: 55,
                    confidence: "HIGH".to_string(),
                    title: "SSH certificate in authorized_keys expires soon".to_string(),
                    description: "An authorized_keys certificate will expire within 14 days.".to_string(),
                    impact: "Imminent expiry can cause sudden SSH access loss or emergency bypass changes.".to_string(),
                    evidence: format!(
                        "{}:{} valid_before={valid_before}",
                        entry.source_file, entry.line_number
                    ),
                    recommendation: "Rotate the certificate before expiry and monitor CA issuance.".to_string(),
                });
            }
            None
        })
        .collect()
}

fn generate_pam_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();
    for entry in &analysis.pam_entries {
        let module = entry.module_path.to_ascii_lowercase();
        if entry.module_type != "nsswitch" && module.contains("nullok") {
            risks.push(GeneratedRisk {
                host_id: Some(entry.host_id),
                username: None,
                public_key_fingerprint: None,
                risk_code: "PAM_NULLOK_ENABLED".to_string(),
                severity: "HIGH".to_string(),
                score: 78,
                confidence: "HIGH".to_string(),
                title: "PAM stack allows null passwords".to_string(),
                description: "A PAM module is configured with nullok.".to_string(),
                impact: "Accounts with empty passwords may authenticate when nullok is in effect."
                    .to_string(),
                evidence: format!(
                    "{}:{} {} {} {}",
                    entry.source_file,
                    entry.line_number,
                    entry.service,
                    entry.module_type,
                    entry.module_path
                ),
                recommendation:
                    "Remove nullok from PAM modules and enforce password or key-only SSH access."
                        .to_string(),
            });
        }
        if entry.service == "sshd" && module.contains("pam_unix.so") && !module.contains("pam_sss")
        {
            risks.push(GeneratedRisk {
                host_id: Some(entry.host_id),
                username: None,
                public_key_fingerprint: None,
                risk_code: "PAM_SSHD_PASSWORD_STACK".to_string(),
                severity: "MEDIUM".to_string(),
                score: 45,
                confidence: "MEDIUM".to_string(),
                title: "SSHD PAM stack includes local password authentication".to_string(),
                description: "The sshd PAM stack references pam_unix.".to_string(),
                impact: "Password-based SSH authentication may remain available depending on sshd settings.".to_string(),
                evidence: format!(
                    "{}:{} {}",
                    entry.source_file, entry.line_number, entry.module_path
                ),
                recommendation: "Confirm PasswordAuthentication is disabled and align PAM with key-only SSH policy.".to_string(),
            });
        }
        if entry.module_type == "nsswitch"
            && entry.service == "passwd"
            && entry.module_path.contains("compat")
        {
            risks.push(GeneratedRisk {
                host_id: Some(entry.host_id),
                username: None,
                public_key_fingerprint: None,
                risk_code: "PAM_LEGACY_NSSWITCH_COMPAT".to_string(),
                severity: "LOW".to_string(),
                score: 30,
                confidence: "MEDIUM".to_string(),
                title: "nsswitch passwd uses legacy compat source".to_string(),
                description: "nsswitch.conf references compat for passwd lookups.".to_string(),
                impact: "Legacy NSS sources can complicate account governance and central auth migration.".to_string(),
                evidence: format!(
                    "{}:{} passwd {}",
                    entry.source_file, entry.line_number, entry.module_path
                ),
                recommendation: "Migrate passwd lookups to files sss or other supported enterprise sources.".to_string(),
            });
        }
    }
    risks
}

fn generate_match_block_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();
    for block in &analysis.sshd_match_blocks {
        for (key, value) in &block.directives {
            let key_lower = key.to_ascii_lowercase();
            let value_lower = value.to_ascii_lowercase();
            if key_lower == "permitrootlogin"
                && (value_lower == "yes" || value_lower == "prohibit-password")
            {
                risks.push(GeneratedRisk {
                    host_id: Some(block.host_id),
                    username: None,
                    public_key_fingerprint: None,
                    risk_code: "SSH_MATCH_PERMIT_ROOT_LOGIN".to_string(),
                    severity: "HIGH".to_string(),
                    score: 82,
                    confidence: "HIGH".to_string(),
                    title: "Match block enables root SSH login".to_string(),
                    description: format!(
                        "Match {} overrides PermitRootLogin to {value_lower}.",
                        block.criteria
                    ),
                    impact: "Match blocks can re-enable root SSH for specific users, groups, or networks.".to_string(),
                    evidence: format!(
                        "{}:{} Match {}",
                        block.source_file, block.line_number, block.criteria
                    ),
                    recommendation: "Remove root login exceptions from Match blocks unless tightly scoped and audited.".to_string(),
                });
            }
            if key_lower == "passwordauthentication" && value_lower == "yes" {
                risks.push(GeneratedRisk {
                    host_id: Some(block.host_id),
                    username: None,
                    public_key_fingerprint: None,
                    risk_code: "SSH_MATCH_PASSWORD_AUTH".to_string(),
                    severity: "HIGH".to_string(),
                    score: 80,
                    confidence: "HIGH".to_string(),
                    title: "Match block enables SSH password authentication".to_string(),
                    description: format!(
                        "Match {} sets PasswordAuthentication yes.",
                        block.criteria
                    ),
                    impact: "Match blocks can expose password authentication to broader audiences than intended.".to_string(),
                    evidence: format!(
                        "{}:{} Match {}",
                        block.source_file, block.line_number, block.criteria
                    ),
                    recommendation: "Restrict password authentication to narrow Match criteria or disable it.".to_string(),
                });
            }
        }
    }
    risks
}

fn generate_sudo_escalation_path_risks(analysis: &NormalizedAnalysis) -> Vec<GeneratedRisk> {
    const ESCALATION_COMMANDS: &[&str] =
        &["/bin/su", "/usr/bin/sudo", "/bin/bash", "/usr/bin/bash"];
    analysis
        .sudo_rules
        .iter()
        .filter(|rule| {
            rule.nopasswd
                && rule.command.as_deref().is_some_and(|command| {
                    ESCALATION_COMMANDS
                        .iter()
                        .any(|needle| command.contains(needle))
                })
        })
        .map(|rule| GeneratedRisk {
            host_id: Some(rule.host_id),
            username: (rule.subject_type == "user").then(|| rule.subject.clone()),
            public_key_fingerprint: None,
            risk_code: "SUDO_PATH_TO_ROOT".to_string(),
            severity: "CRITICAL".to_string(),
            score: 92,
            confidence: "HIGH".to_string(),
            title: "Passwordless sudo provides a short path to root".to_string(),
            description: "A sudoers rule grants NOPASSWD access to a shell escalation command."
                .to_string(),
            impact: "SSH access to the subject can become immediate root access.".to_string(),
            evidence: format!(
                "{}:{} grants {} NOPASSWD:{}",
                rule.source_file,
                rule.line_number,
                rule.subject,
                rule.command.as_deref().unwrap_or("ALL")
            ),
            recommendation: "Remove NOPASSWD for su, sudo, and shell binaries.".to_string(),
        })
        .collect()
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

    if command.contains('*') {
        return Some(GeneratedRisk {
            host_id: Some(rule.host_id),
            username: (rule.subject_type == "user").then(|| rule.subject.clone()),
            public_key_fingerprint: None,
            risk_code: "SUDO_WILDCARD_COMMAND".to_string(),
            severity: "MEDIUM".to_string(),
            score: 58,
            confidence: "HIGH".to_string(),
            title: "Sudo rule contains a wildcard command".to_string(),
            description: "A sudoers rule grants access to a command pattern with a wildcard."
                .to_string(),
            impact: "Wildcard command patterns can be broader than intended and may allow argument or path abuse.".to_string(),
            evidence: format!(
                "{}:{} grants {} access to {}",
                rule.source_file, rule.line_number, rule.subject, command
            ),
            recommendation:
                "Replace wildcard sudoers entries with exact command paths and constrained arguments."
                    .to_string(),
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

    let mut group_members_by_host: BTreeMap<(i64, String), BTreeSet<String>> = BTreeMap::new();
    for group in &analysis.groups {
        group_members_by_host
            .entry((group.host_id, group.group_name.clone()))
            .or_default()
            .extend(group.members.iter().cloned());
    }

    let mut nopasswd_users_by_host: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for rule in analysis.sudo_rules.iter().filter(|rule| rule.nopasswd) {
        match rule.subject_type.as_str() {
            "user" => {
                nopasswd_users_by_host
                    .entry(rule.host_id)
                    .or_default()
                    .insert(rule.subject.clone());
            }
            "group" => {
                if let Some(members) =
                    group_members_by_host.get(&(rule.host_id, rule.subject.clone()))
                {
                    nopasswd_users_by_host
                        .entry(rule.host_id)
                        .or_default()
                        .extend(members.iter().cloned());
                }
            }
            _ => {}
        }
    }

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

    fn generate_risks_for_tests(
        analysis: &NormalizedAnalysis,
        policy: &RiskPolicy,
    ) -> Vec<GeneratedRisk> {
        generate_risks_with_enrichment(
            analysis,
            policy,
            &enrichment::RiskEnrichmentInput {
                hosts: &[],
                host_banners: &BTreeMap::new(),
                key_ages: &[],
                server_host_keys: &[],
            },
        )
    }

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
                    effective: false,
                },
                ParsedSshdConfigEntry {
                    host_id: 1,
                    key: "PasswordAuthentication".to_string(),
                    value: Some("yes".to_string()),
                    source_file: "/etc/ssh/sshd_config".to_string(),
                    line_number: 2,
                    effective: false,
                },
            ],
            ..Default::default()
        };

        let codes = generate_risks_for_tests(&analysis, &RiskPolicy::default())
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

        let risks = generate_risks_for_tests(&analysis, &RiskPolicy::default());

        assert_eq!(risks[0].risk_code, "SUDO_NOPASSWD_ALL");
    }

    #[test]
    fn generates_unrestricted_authorized_key_risk() {
        let analysis = NormalizedAnalysis {
            authorized_keys: vec![authorized_key(1, "deploy", "SHA256:test")],
            ..Default::default()
        };

        let risks = generate_risks_for_tests(&analysis, &RiskPolicy::default());

        assert!(
            risks
                .iter()
                .any(|risk| risk.risk_code == "SSH_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS")
        );
    }

    #[test]
    fn effective_sshd_config_takes_precedence_and_flags_mismatch() {
        let analysis = NormalizedAnalysis {
            sshd_config_entries: vec![
                ParsedSshdConfigEntry {
                    host_id: 1,
                    key: "PasswordAuthentication".to_string(),
                    value: Some("no".to_string()),
                    source_file: "/etc/ssh/sshd_config".to_string(),
                    line_number: 10,
                    effective: false,
                },
                ParsedSshdConfigEntry {
                    host_id: 1,
                    key: "passwordauthentication".to_string(),
                    value: Some("yes".to_string()),
                    source_file: "sshd -T".to_string(),
                    line_number: 1,
                    effective: true,
                },
            ],
            ..Default::default()
        };

        let codes = generate_risks_for_tests(&analysis, &RiskPolicy::default())
            .into_iter()
            .map(|risk| risk.risk_code)
            .collect::<BTreeSet<_>>();

        assert!(codes.contains("SSH_PASSWORD_AUTH_ENABLED"));
        assert!(codes.contains("SSHD_EFFECTIVE_CONFIG_MISMATCH"));
    }

    #[test]
    fn generates_legacy_rsa_key_risk() {
        let mut key = authorized_key(1, "deploy", "SHA256:rsa");
        key.public_key.key_type = "ssh-rsa".to_string();
        key.public_key.key_bits = Some(1024);
        let analysis = NormalizedAnalysis {
            authorized_keys: vec![key],
            ..Default::default()
        };

        let codes = generate_risks_for_tests(&analysis, &RiskPolicy::default())
            .into_iter()
            .map(|risk| risk.risk_code)
            .collect::<BTreeSet<_>>();

        assert!(codes.contains("SSH_LEGACY_RSA_KEY"));
    }

    #[test]
    fn generates_key_reuse_risk_at_five_hosts() {
        let analysis = NormalizedAnalysis {
            authorized_keys: (1..=5)
                .map(|host_id| authorized_key(host_id, "deploy", "SHA256:shared"))
                .collect(),
            ..Default::default()
        };

        let risks = generate_risks_for_tests(&analysis, &RiskPolicy::default());

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
                key_bits: Some(256),
                key_comment: None,
                normalized_public_key: format!("ssh-ed25519 {fingerprint}"),
                certificate_signing_ca: None,
                certificate_valid_after: None,
                certificate_valid_before: None,
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
