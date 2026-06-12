use crate::models::{GeneratedRisk, RiskExceptionRecord};
use chrono::Utc;

pub fn apply_exceptions(
    risks: Vec<GeneratedRisk>,
    exceptions: &[RiskExceptionRecord],
) -> Vec<GeneratedRisk> {
    if exceptions.is_empty() {
        return risks;
    }

    let now = Utc::now();
    let active_exceptions = exceptions
        .iter()
        .filter(|exception| exception_is_active(exception, now))
        .collect::<Vec<_>>();

    risks
        .into_iter()
        .filter(|risk| {
            !active_exceptions
                .iter()
                .any(|exception| exception_matches_risk(exception, risk))
        })
        .collect()
}

fn exception_is_active(exception: &RiskExceptionRecord, now: chrono::DateTime<Utc>) -> bool {
    exception.expires_at.as_ref().is_none_or(|expires_at| {
        chrono::DateTime::parse_from_rfc3339(expires_at)
            .map(|value| value.with_timezone(&Utc) > now)
            .unwrap_or(false)
    })
}

fn exception_matches_risk(exception: &RiskExceptionRecord, risk: &GeneratedRisk) -> bool {
    if !exception.risk_code.eq_ignore_ascii_case(&risk.risk_code) {
        return false;
    }

    if let Some(host_id) = exception.host_id
        && risk.host_id != Some(host_id)
    {
        return false;
    }

    if let Some(username) = &exception.username
        && risk.username.as_deref() != Some(username.as_str())
    {
        return false;
    }

    if let Some(fingerprint) = &exception.public_key_fingerprint {
        let risk_fingerprint = risk.public_key_fingerprint.as_deref().unwrap_or_default();
        if !risk_fingerprint.eq_ignore_ascii_case(fingerprint) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod exception_tests {
    use super::*;

    #[test]
    fn filters_matching_exception() {
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
        let exceptions = vec![RiskExceptionRecord {
            id: 1,
            risk_code: "SSH_PASSWORD_AUTH_ENABLED".to_string(),
            host_id: Some(1),
            username: None,
            public_key_fingerprint: None,
            reason: "accepted risk".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: None,
        }];

        assert!(apply_exceptions(risks, &exceptions).is_empty());
    }

    #[test]
    fn ignores_exceptions_with_invalid_expiry() {
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
        let exceptions = vec![RiskExceptionRecord {
            id: 1,
            risk_code: "SSH_PASSWORD_AUTH_ENABLED".to_string(),
            host_id: Some(1),
            username: None,
            public_key_fingerprint: None,
            reason: "accepted risk".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: Some("not-a-date".to_string()),
        }];

        assert_eq!(apply_exceptions(risks, &exceptions).len(), 1);
    }
}
