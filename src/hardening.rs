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
