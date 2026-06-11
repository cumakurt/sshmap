use crate::models::{BaselineRiskRecord, RiskRecord};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn snapshot_risk(risk: &RiskRecord) -> BaselineRiskRecord {
    BaselineRiskRecord {
        signature: risk_signature(risk),
        risk_code: risk.risk_code.clone(),
        severity: risk.severity.clone(),
        score: risk.score,
        target: risk_target(risk),
        title: risk.title.clone(),
        evidence: risk.evidence.clone(),
        status: risk.status.clone(),
    }
}

pub fn diff_risk_snapshots(
    from: &[BaselineRiskRecord],
    to: &[BaselineRiskRecord],
) -> (Vec<BaselineRiskRecord>, Vec<BaselineRiskRecord>, usize) {
    let from_by_signature = from
        .iter()
        .map(|risk| (risk.signature.as_str(), risk))
        .collect::<BTreeMap<_, _>>();
    let to_by_signature = to
        .iter()
        .map(|risk| (risk.signature.as_str(), risk))
        .collect::<BTreeMap<_, _>>();

    let new_risks = to_by_signature
        .iter()
        .filter(|(signature, _)| !from_by_signature.contains_key(**signature))
        .map(|(_, risk)| (*risk).clone())
        .collect::<Vec<_>>();

    let resolved_risks = from_by_signature
        .iter()
        .filter(|(signature, _)| !to_by_signature.contains_key(**signature))
        .map(|(_, risk)| (*risk).clone())
        .collect::<Vec<_>>();

    let unchanged_risks = from_by_signature
        .keys()
        .filter(|signature| to_by_signature.contains_key(**signature))
        .count();

    (new_risks, resolved_risks, unchanged_risks)
}

fn risk_signature(risk: &RiskRecord) -> String {
    let identity = [
        risk.risk_code.as_str(),
        risk.hostname.as_deref().unwrap_or(""),
        risk.ip_address.as_deref().unwrap_or(""),
        risk.username.as_deref().unwrap_or(""),
        risk.public_key_fingerprint.as_deref().unwrap_or(""),
        risk.evidence.as_deref().unwrap_or(""),
    ]
    .join("\u{1f}");

    hash_hex(identity.as_bytes())
}

fn risk_target(risk: &RiskRecord) -> String {
    if let Some(username) = &risk.username {
        let host = risk
            .hostname
            .as_deref()
            .or(risk.ip_address.as_deref())
            .unwrap_or("unknown-host");
        return format!("{username}@{host}");
    }

    if let Some(hostname) = &risk.hostname {
        return hostname.clone();
    }

    if let Some(ip_address) = &risk.ip_address {
        return ip_address.clone();
    }

    if let Some(fingerprint) = &risk.public_key_fingerprint {
        return fingerprint.clone();
    }

    "global".to_string()
}

fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_risk_with_stable_signature_and_target() {
        let first = sample_risk(
            "SSH_ROOT_LOGIN_ENABLED",
            "Root login is enabled",
            Some("web01"),
        );
        let mut second = first.clone();
        second.id = 99;
        second.first_seen = "2026-06-12T00:00:00Z".to_string();

        let first_snapshot = snapshot_risk(&first);
        let second_snapshot = snapshot_risk(&second);

        assert_eq!(first_snapshot.signature, second_snapshot.signature);
        assert_eq!(first_snapshot.target, "web01");
    }

    #[test]
    fn diffs_new_resolved_and_unchanged_risks() {
        let unchanged = snapshot_risk(&sample_risk(
            "SSH_ROOT_LOGIN_ENABLED",
            "Root login is enabled",
            Some("web01"),
        ));
        let resolved = snapshot_risk(&sample_risk(
            "SSH_PASSWORD_AUTH_ENABLED",
            "Password authentication is enabled",
            Some("web02"),
        ));
        let new = snapshot_risk(&sample_risk(
            "SUDO_NOPASSWD_ALL",
            "User has passwordless sudo",
            Some("web03"),
        ));

        let (new_risks, resolved_risks, unchanged_risks) = diff_risk_snapshots(
            &[unchanged.clone(), resolved.clone()],
            &[unchanged, new.clone()],
        );

        assert_eq!(new_risks, vec![new]);
        assert_eq!(resolved_risks, vec![resolved]);
        assert_eq!(unchanged_risks, 1);
    }

    fn sample_risk(code: &str, title: &str, hostname: Option<&str>) -> RiskRecord {
        RiskRecord {
            id: 1,
            host_id: Some(1),
            hostname: hostname.map(str::to_string),
            ip_address: Some("192.0.2.10".to_string()),
            username: None,
            public_key_fingerprint: None,
            risk_code: code.to_string(),
            severity: "HIGH".to_string(),
            score: 80,
            confidence: "HIGH".to_string(),
            title: title.to_string(),
            description: Some("Description".to_string()),
            impact: Some("Impact".to_string()),
            evidence: Some("Evidence".to_string()),
            recommendation: Some("Recommendation".to_string()),
            status: "open".to_string(),
            first_seen: "2026-06-11T00:00:00Z".to_string(),
            last_seen: "2026-06-11T00:00:00Z".to_string(),
        }
    }
}
