use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceControl {
    pub framework: String,
    pub control_id: String,
    pub title: String,
    pub risk_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceControlStatus {
    pub framework: String,
    pub control_id: String,
    pub title: String,
    pub status: String,
    pub failing_risk_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReport {
    pub framework: String,
    pub total_controls: usize,
    pub passing_controls: usize,
    pub failing_controls: usize,
    pub compliance_percent: f64,
    pub controls: Vec<ComplianceControlStatus>,
}

pub fn compliance_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            framework: "CIS".to_string(),
            control_id: "CIS-SSH-1".to_string(),
            title: "Disable direct root SSH login".to_string(),
            risk_codes: vec![
                "SSH_ROOT_LOGIN_ENABLED".to_string(),
                "SSH_ROOT_LOGIN_WITH_KEYS".to_string(),
            ],
        },
        ComplianceControl {
            framework: "CIS".to_string(),
            control_id: "CIS-SSH-2".to_string(),
            title: "Disable SSH password authentication".to_string(),
            risk_codes: vec!["SSH_PASSWORD_AUTH_ENABLED".to_string()],
        },
        ComplianceControl {
            framework: "CIS".to_string(),
            control_id: "CIS-SSH-3".to_string(),
            title: "Reject empty passwords".to_string(),
            risk_codes: vec!["SSH_EMPTY_PASSWORD_ALLOWED".to_string()],
        },
        ComplianceControl {
            framework: "CIS".to_string(),
            control_id: "CIS-SSH-4".to_string(),
            title: "Restrict SSH forwarding".to_string(),
            risk_codes: vec![
                "SSH_TCP_FORWARDING_ENABLED".to_string(),
                "SSH_FORWARD_AGENT_ENABLED".to_string(),
                "SSH_GATEWAY_PORTS_ENABLED".to_string(),
            ],
        },
        ComplianceControl {
            framework: "CIS".to_string(),
            control_id: "CIS-SSH-5".to_string(),
            title: "Harden authorized_keys entries".to_string(),
            risk_codes: vec![
                "SSH_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS".to_string(),
                "SSH_ROOT_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS".to_string(),
            ],
        },
        ComplianceControl {
            framework: "STIG".to_string(),
            control_id: "STIG-SSH-000001".to_string(),
            title: "Limit privileged sudo access".to_string(),
            risk_codes: vec![
                "SUDO_NOPASSWD_ALL".to_string(),
                "SUDO_WILDCARD_COMMAND".to_string(),
            ],
        },
        ComplianceControl {
            framework: "STIG".to_string(),
            control_id: "STIG-SSH-000002".to_string(),
            title: "Prevent SSH key reuse across hosts".to_string(),
            risk_codes: vec![
                "SSH_KEY_REUSED_MANY_HOSTS".to_string(),
                "SSH_PUBLIC_KEY_REUSED".to_string(),
                "SSH_PUBLIC_KEY_REUSED_WIDELY".to_string(),
            ],
        },
        ComplianceControl {
            framework: "STIG".to_string(),
            control_id: "STIG-SSH-000003".to_string(),
            title: "Maintain current OpenSSH versions".to_string(),
            risk_codes: vec!["SSH_OPENSSH_KNOWN_CVE".to_string()],
        },
        ComplianceControl {
            framework: "STIG".to_string(),
            control_id: "STIG-SSH-000004".to_string(),
            title: "Rotate stale SSH keys".to_string(),
            risk_codes: vec![
                "SSH_KEY_STALE".to_string(),
                "SSH_KEY_NEVER_ROTATED".to_string(),
            ],
        },
        ComplianceControl {
            framework: "STIG".to_string(),
            control_id: "STIG-SSH-000005".to_string(),
            title: "Maintain stable server host keys".to_string(),
            risk_codes: vec![
                "SSH_SERVER_HOST_KEY_CHANGED".to_string(),
                "SSH_SERVER_HOST_KEY_CONFLICT".to_string(),
            ],
        },
    ]
}

pub fn build_compliance_report(framework: &str, active_risk_codes: &[String]) -> ComplianceReport {
    let active = active_risk_codes
        .iter()
        .map(|code| code.to_ascii_uppercase())
        .collect::<BTreeSet<_>>();
    let controls = compliance_controls()
        .into_iter()
        .filter(|control| {
            framework.eq_ignore_ascii_case("all")
                || control.framework.eq_ignore_ascii_case(framework)
        })
        .map(|control| {
            let failing_risk_codes = control
                .risk_codes
                .iter()
                .filter(|code| active.contains(code.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            let status = if failing_risk_codes.is_empty() {
                "PASS"
            } else {
                "FAIL"
            }
            .to_string();
            ComplianceControlStatus {
                framework: control.framework,
                control_id: control.control_id,
                title: control.title,
                status,
                failing_risk_codes,
            }
        })
        .collect::<Vec<_>>();

    let total_controls = controls.len();
    let failing_controls = controls
        .iter()
        .filter(|control| control.status == "FAIL")
        .count();
    let passing_controls = total_controls.saturating_sub(failing_controls);
    let compliance_percent = if total_controls == 0 {
        100.0
    } else {
        (passing_controls as f64 / total_controls as f64) * 100.0
    };

    ComplianceReport {
        framework: framework.to_ascii_uppercase(),
        total_controls,
        passing_controls,
        failing_controls,
        compliance_percent,
        controls,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_compliance_percent() {
        let report = build_compliance_report("CIS", &["SSH_PASSWORD_AUTH_ENABLED".to_string()]);
        assert!(report.compliance_percent < 100.0);
        assert!(report.failing_controls >= 1);
    }
}
