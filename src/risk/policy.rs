use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RiskPolicy {
    #[serde(default)]
    pub rules: BTreeMap<String, RiskRulePolicy>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RiskRulePolicy {
    pub enabled: Option<bool>,
    pub severity: Option<String>,
    pub high_threshold: Option<usize>,
    pub critical_threshold: Option<usize>,
}

impl RiskPolicy {
    pub fn is_enabled(&self, risk_code: &str) -> bool {
        self.rules
            .get(risk_code)
            .and_then(|rule| rule.enabled)
            .unwrap_or(true)
    }

    pub fn severity_override(&self, risk_code: &str) -> Option<String> {
        self.rules
            .get(risk_code)
            .and_then(|rule| rule.severity.clone())
    }

    pub fn key_reuse_high_threshold(&self) -> usize {
        self.rules
            .get("SSH_KEY_REUSED_MANY_HOSTS")
            .and_then(|rule| rule.high_threshold)
            .unwrap_or(5)
    }

    pub fn key_reuse_critical_threshold(&self) -> usize {
        self.rules
            .get("SSH_KEY_REUSED_MANY_HOSTS")
            .and_then(|rule| rule.critical_threshold)
            .unwrap_or(20)
    }

    pub fn key_stale_days(&self) -> i64 {
        self.rules
            .get("SSH_KEY_STALE")
            .and_then(|rule| rule.high_threshold)
            .map(|value| value as i64)
            .unwrap_or(365)
    }
}

pub fn load_optional(path: Option<&Path>) -> Result<RiskPolicy> {
    let Some(path) = path else {
        return Ok(RiskPolicy::default());
    };

    let content = crate::security::read_text_file_limited(
        path,
        crate::security::MAX_CONFIG_FILE_BYTES,
        "risk policy",
    )?;
    serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse risk policy {}", path.display()))
}

pub fn apply_policy(
    mut risks: Vec<crate::models::GeneratedRisk>,
    policy: &RiskPolicy,
) -> Vec<crate::models::GeneratedRisk> {
    risks.retain(|risk| policy.is_enabled(&risk.risk_code));
    for risk in &mut risks {
        if let Some(severity) = policy.severity_override(&risk.risk_code) {
            risk.severity = severity.to_ascii_uppercase();
        }
    }
    risks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::GeneratedRisk;

    #[test]
    fn disables_rule_from_policy() {
        let policy = RiskPolicy {
            rules: BTreeMap::from([(
                "SSH_PASSWORD_AUTH_ENABLED".to_string(),
                RiskRulePolicy {
                    enabled: Some(false),
                    severity: None,
                    high_threshold: None,
                    critical_threshold: None,
                },
            )]),
        };
        let risks = vec![GeneratedRisk {
            host_id: Some(1),
            username: None,
            public_key_fingerprint: None,
            risk_code: "SSH_PASSWORD_AUTH_ENABLED".to_string(),
            severity: "HIGH".to_string(),
            score: 75,
            confidence: "HIGH".to_string(),
            title: "Password auth".to_string(),
            description: String::new(),
            impact: String::new(),
            evidence: String::new(),
            recommendation: String::new(),
        }];

        assert!(apply_policy(risks, &policy).is_empty());
    }
}
