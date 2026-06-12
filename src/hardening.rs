use crate::compliance::{build_compliance_report, compliance_controls};
use crate::models::{HostRecord, RiskRecord};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct HostHardeningScore {
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: String,
    pub score: i64,
    pub risk_count: usize,
    pub critical_risks: usize,
    pub high_risks: usize,
    pub compliance_percent: f64,
}

pub fn compute_host_hardening_score(host: &HostRecord, risks: &[RiskRecord]) -> HostHardeningScore {
    let host_risks = risks
        .iter()
        .filter(|risk| risk.host_id == Some(host.id))
        .collect::<Vec<_>>();
    let critical = host_risks
        .iter()
        .filter(|risk| risk.severity == "CRITICAL")
        .count();
    let high = host_risks
        .iter()
        .filter(|risk| risk.severity == "HIGH")
        .count();
    let medium = host_risks
        .iter()
        .filter(|risk| risk.severity == "MEDIUM")
        .count();
    let low = host_risks
        .iter()
        .filter(|risk| risk.severity == "LOW")
        .count();

    let penalty = critical as i64 * 25 + high as i64 * 12 + medium as i64 * 5 + low as i64 * 2;
    let exposure_bonus = if host.ssh_open { 0 } else { 5 };
    let score = (100 - penalty + exposure_bonus).clamp(0, 100);

    let codes = host_risks
        .iter()
        .map(|risk| risk.risk_code.clone())
        .collect::<Vec<_>>();
    let compliance = build_compliance_report("all", &codes);

    HostHardeningScore {
        host_id: host.id,
        hostname: host.hostname.clone(),
        ip_address: host.ip_address.clone(),
        score,
        risk_count: host_risks.len(),
        critical_risks: critical,
        high_risks: high,
        compliance_percent: compliance.compliance_percent,
    }
}

pub fn compute_inventory_hardening(
    hosts: &[HostRecord],
    risks: &[RiskRecord],
) -> Vec<HostHardeningScore> {
    hosts
        .iter()
        .map(|host| compute_host_hardening_score(host, risks))
        .collect()
}

pub fn hardening_summary(scores: &[HostHardeningScore]) -> BTreeMap<String, usize> {
    let mut buckets = BTreeMap::from([
        ("excellent".to_string(), 0),
        ("good".to_string(), 0),
        ("fair".to_string(), 0),
        ("poor".to_string(), 0),
    ]);
    for score in scores {
        let bucket = if score.score >= 90 {
            "excellent"
        } else if score.score >= 70 {
            "good"
        } else if score.score >= 50 {
            "fair"
        } else {
            "poor"
        };
        *buckets.get_mut(bucket).expect("bucket") += 1;
    }
    buckets
}

pub fn control_count() -> usize {
    compliance_controls().len()
}

#[derive(Debug, Clone, Serialize)]
pub struct HardeningReport {
    pub hosts: Vec<HostHardeningScore>,
    pub summary: BTreeMap<String, usize>,
    pub control_count: usize,
}

pub fn build_hardening_report(hosts: &[HostRecord], risks: &[RiskRecord]) -> HardeningReport {
    let scores = compute_inventory_hardening(hosts, risks);
    HardeningReport {
        summary: hardening_summary(&scores),
        control_count: control_count(),
        hosts: scores,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HostRecord, RiskRecord};

    #[test]
    fn builds_hardening_report_with_summary_and_controls() {
        let hosts = vec![HostRecord {
            id: 1,
            hostname: Some("web01".to_string()),
            fqdn: None,
            ip_address: "10.0.0.10".to_string(),
            port: 22,
            os_family: None,
            os_version: None,
            environment: None,
            criticality: None,
            ssh_open: true,
            ssh_banner: None,
            source: "scan".to_string(),
            first_seen: "2026-01-01".to_string(),
            last_seen: "2026-01-02".to_string(),
            user_count: 1,
            risk_count: 1,
        }];
        let risks = vec![RiskRecord {
            id: 1,
            host_id: Some(1),
            hostname: Some("web01".to_string()),
            ip_address: Some("10.0.0.10".to_string()),
            username: None,
            public_key_fingerprint: None,
            risk_code: "SSH_PASSWORD_AUTH_ENABLED".to_string(),
            severity: "HIGH".to_string(),
            score: 80,
            confidence: "HIGH".to_string(),
            title: "Password auth".to_string(),
            description: None,
            impact: None,
            evidence: None,
            recommendation: None,
            status: "OPEN".to_string(),
            first_seen: "2026-01-01".to_string(),
            last_seen: "2026-01-01".to_string(),
        }];

        let report = build_hardening_report(&hosts, &risks);
        assert_eq!(report.hosts.len(), 1);
        assert!(report.control_count > 0);
        assert_eq!(report.summary.values().sum::<usize>(), 1);
    }
}
