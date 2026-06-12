use crate::host_context::{adjust_score, adjust_severity, build_host_context_map};
use crate::models::{GeneratedRisk, HostContextRecord, HostServerKeyRecord, PublicKeyAgeRecord};
use crate::risk::policy::RiskPolicy;
use crate::ssh_version::{known_cves_for_version, parse_openssh_banner};
use std::collections::{BTreeMap, BTreeSet};

pub struct RiskEnrichmentInput<'a> {
    pub hosts: &'a [HostContextRecord],
    pub host_banners: &'a BTreeMap<i64, String>,
    pub key_ages: &'a [PublicKeyAgeRecord],
    pub server_host_keys: &'a [HostServerKeyRecord],
}

pub fn apply_context_scoring(risks: &mut [GeneratedRisk], hosts: &[HostContextRecord]) {
    let contexts = build_host_context_map(hosts);
    for risk in risks {
        let Some(host_id) = risk.host_id else {
            continue;
        };
        let Some(context) = contexts.get(&host_id) else {
            continue;
        };
        let multiplier = context.context_multiplier();
        risk.severity = adjust_severity(&risk.severity, multiplier);
        risk.score = adjust_score(risk.score, multiplier);
        if context.is_production_exposed()
            && matches!(
                risk.risk_code.as_str(),
                "SSH_PASSWORD_AUTH_ENABLED" | "SSH_ROOT_LOGIN_ENABLED" | "SSH_ROOT_LOGIN_WITH_KEYS"
            )
            && risk.severity != "CRITICAL"
        {
            risk.severity = "CRITICAL".to_string();
            risk.score = risk.score.max(90);
        }
    }
}

pub fn generate_banner_cve_risks(input: &RiskEnrichmentInput<'_>) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();
    for (host_id, banner) in input.host_banners {
        let Some(version) = parse_openssh_banner(Some(banner)) else {
            continue;
        };
        for finding in known_cves_for_version(&version) {
            risks.push(GeneratedRisk {
                host_id: Some(*host_id),
                username: None,
                public_key_fingerprint: None,
                risk_code: "SSH_OPENSSH_KNOWN_CVE".to_string(),
                severity: finding.severity.clone(),
                score: match finding.severity.as_str() {
                    "CRITICAL" => 95,
                    "HIGH" => 80,
                    "MEDIUM" => 55,
                    _ => 35,
                },
                confidence: "HIGH".to_string(),
                title: format!("Known OpenSSH vulnerability: {}", finding.cve_id),
                description: finding.title.clone(),
                impact: format!(
                    "OpenSSH {} is affected through {}.",
                    version.raw, finding.affected_through
                ),
                evidence: format!("Banner: {banner}"),
                recommendation: finding.recommendation.clone(),
            });
        }
    }
    risks
}

pub fn generate_key_rotation_risks(
    input: &RiskEnrichmentInput<'_>,
    policy: &RiskPolicy,
) -> Vec<GeneratedRisk> {
    let stale_days = policy.key_stale_days();
    let mut risks = Vec::new();

    for key in input.key_ages {
        if key.age_days >= stale_days {
            risks.push(GeneratedRisk {
                host_id: None,
                username: None,
                public_key_fingerprint: Some(key.fingerprint_sha256.clone()),
                risk_code: "SSH_KEY_STALE".to_string(),
                severity: if key.age_days >= stale_days * 2 {
                    "HIGH".to_string()
                } else {
                    "MEDIUM".to_string()
                },
                score: if key.age_days >= stale_days * 2 { 70 } else { 50 },
                confidence: "HIGH".to_string(),
                title: "SSH public key has not been rotated recently".to_string(),
                description: format!(
                    "Public key {} has been present for {} days.",
                    key.fingerprint_sha256, key.age_days
                ),
                impact: "Long-lived keys increase blast radius when compromise or employee offboarding is delayed.".to_string(),
                evidence: format!(
                    "first_seen={} last_seen={} host_count={}",
                    key.first_seen, key.last_seen, key.host_count
                ),
                recommendation: "Rotate the key, remove stale authorized_keys entries, and enforce periodic key rotation policy.".to_string(),
            });
        }

        if key.host_count >= 10 && key.age_days >= 180 {
            risks.push(GeneratedRisk {
                host_id: None,
                username: None,
                public_key_fingerprint: Some(key.fingerprint_sha256.clone()),
                risk_code: "SSH_KEY_NEVER_ROTATED".to_string(),
                severity: "HIGH".to_string(),
                score: 75,
                confidence: "MEDIUM".to_string(),
                title: "Widely deployed SSH key shows no rotation history".to_string(),
                description: format!(
                    "Key {} appears on {} hosts and is at least {} days old.",
                    key.fingerprint_sha256, key.host_count, key.age_days
                ),
                impact: "A single long-lived key across many hosts magnifies compromise impact.".to_string(),
                evidence: format!("host_count={} age_days={}", key.host_count, key.age_days),
                recommendation: "Issue per-host or per-role keys and retire shared deployment keys.".to_string(),
            });
        }
    }

    risks
}

pub fn generate_server_host_key_risks(input: &RiskEnrichmentInput<'_>) -> Vec<GeneratedRisk> {
    let mut risks = Vec::new();
    let mut by_host_key_type: BTreeMap<(i64, String), Vec<&HostServerKeyRecord>> = BTreeMap::new();
    let mut by_fingerprint_hosts: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();

    for record in input.server_host_keys {
        by_host_key_type
            .entry((record.host_id, record.key_type.clone()))
            .or_default()
            .push(record);
        by_fingerprint_hosts
            .entry(record.fingerprint_sha256.clone())
            .or_default()
            .insert(record.host_id);
    }

    for ((host_id, key_type), records) in &by_host_key_type {
        if records.len() > 1 {
            let fingerprints = records
                .iter()
                .map(|record| record.fingerprint_sha256.as_str())
                .collect::<BTreeSet<_>>();
            if fingerprints.len() > 1 {
                risks.push(GeneratedRisk {
                    host_id: Some(*host_id),
                    username: None,
                    public_key_fingerprint: None,
                    risk_code: "SSH_SERVER_HOST_KEY_CHANGED".to_string(),
                    severity: "HIGH".to_string(),
                    score: 78,
                    confidence: "HIGH".to_string(),
                    title: "Multiple SSH server host keys recorded for one key type".to_string(),
                    description: format!(
                        "The host has more than one {key_type} server host key fingerprint in inventory."
                    ),
                    impact: "Unexpected host key changes may indicate rebuilds, MITM exposure, or DNS/IP reuse.".to_string(),
                    evidence: format!(
                        "key_type={key_type} fingerprints={}",
                        fingerprints.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                    recommendation: "Verify the change is expected and update client known_hosts trust stores.".to_string(),
                });
            }
        }
    }

    for (fingerprint, host_ids) in by_fingerprint_hosts {
        if host_ids.len() < 2 {
            continue;
        }
        let host_list = host_ids
            .iter()
            .filter_map(|host_id| {
                input
                    .hosts
                    .iter()
                    .find(|host| host.host_id == *host_id)
                    .and_then(|host| host.hostname.clone().or_else(|| host.ip_address.clone()))
            })
            .collect::<Vec<_>>();
        if host_list.len() < 2 {
            continue;
        }
        risks.push(GeneratedRisk {
            host_id: host_ids.iter().next().copied(),
            username: None,
            public_key_fingerprint: None,
            risk_code: "SSH_SERVER_HOST_KEY_CONFLICT".to_string(),
            severity: "HIGH".to_string(),
            score: 72,
            confidence: "MEDIUM".to_string(),
            title: "Same SSH server host key fingerprint appears on multiple hosts".to_string(),
            description: "One server host key fingerprint is associated with multiple inventory hosts.".to_string(),
            impact: "Shared or cloned host keys weaken host authentication and complicate incident response.".to_string(),
            evidence: format!("fingerprint={fingerprint} hosts={}", host_list.join(", ")),
            recommendation: "Regenerate unique SSH host keys per system unless this is an intentional cluster design.".to_string(),
        });
    }

    risks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(host_id: i64, key_type: &str, fingerprint: &str) -> HostServerKeyRecord {
        HostServerKeyRecord {
            host_id,
            key_type: key_type.to_string(),
            fingerprint_sha256: fingerprint.to_string(),
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T00:00:00Z".to_string(),
            source: "test".to_string(),
        }
    }

    fn input<'a>(
        server_host_keys: &'a [HostServerKeyRecord],
        host_banners: &'a BTreeMap<i64, String>,
    ) -> RiskEnrichmentInput<'a> {
        RiskEnrichmentInput {
            hosts: &[],
            host_banners,
            key_ages: &[],
            server_host_keys,
        }
    }

    #[test]
    fn server_host_key_risks_allow_multiple_key_algorithms_for_one_host() {
        let records = vec![
            key(1, "ecdsa-sha2-nistp256", "SHA256:ecdsa"),
            key(1, "ssh-ed25519", "SHA256:ed25519"),
            key(1, "ssh-rsa", "SHA256:rsa"),
        ];
        let host_banners = BTreeMap::new();

        let risks = generate_server_host_key_risks(&input(&records, &host_banners));

        assert!(
            risks
                .iter()
                .all(|risk| risk.risk_code != "SSH_SERVER_HOST_KEY_CHANGED"),
            "{risks:#?}"
        );
    }

    #[test]
    fn server_host_key_risks_flag_multiple_fingerprints_for_same_key_algorithm() {
        let records = vec![
            key(1, "ssh-ed25519", "SHA256:old"),
            key(1, "ssh-ed25519", "SHA256:new"),
        ];
        let host_banners = BTreeMap::new();

        let risks = generate_server_host_key_risks(&input(&records, &host_banners));

        let changed = risks
            .iter()
            .find(|risk| risk.risk_code == "SSH_SERVER_HOST_KEY_CHANGED")
            .expect("same host and key type should produce a host-key-changed risk");
        assert_eq!(changed.host_id, Some(1));
        assert!(changed.evidence.contains("key_type=ssh-ed25519"));
        assert!(changed.evidence.contains("SHA256:old"));
        assert!(changed.evidence.contains("SHA256:new"));
    }
}
