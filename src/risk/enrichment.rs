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
    let mut by_host: BTreeMap<i64, Vec<&HostServerKeyRecord>> = BTreeMap::new();
    let mut by_fingerprint_hosts: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();

    for record in input.server_host_keys {
        by_host.entry(record.host_id).or_default().push(record);
        by_fingerprint_hosts
            .entry(record.fingerprint_sha256.clone())
            .or_default()
            .insert(record.host_id);
    }

    for (host_id, records) in &by_host {
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
                    title: "Multiple SSH server host keys recorded for one host".to_string(),
                    description: "The host has more than one server host key fingerprint in inventory.".to_string(),
                    impact: "Unexpected host key changes may indicate rebuilds, MITM exposure, or DNS/IP reuse.".to_string(),
                    evidence: fingerprints.into_iter().collect::<Vec<_>>().join(", "),
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
