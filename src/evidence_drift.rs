use serde::Serialize;
use std::collections::BTreeMap;

const DRIFT_EVIDENCE_TYPES: &[&str] = &["sshd_config", "authorized_keys", "sudoers"];

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceDriftChange {
    pub evidence_type: String,
    pub from_scan_run_id: i64,
    pub to_scan_run_id: i64,
    pub from_hash: String,
    pub to_hash: String,
    pub added_lines: usize,
    pub removed_lines: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceDriftReport {
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub from_scan_run_id: i64,
    pub to_scan_run_id: i64,
    pub changes: Vec<EvidenceDriftChange>,
}

pub fn diff_evidence_content(from: &str, to: &str) -> (usize, usize) {
    let from_lines = from.lines().collect::<Vec<_>>();
    let to_lines = to.lines().collect::<Vec<_>>();
    let mut added = 0usize;
    let mut removed = 0usize;

    let from_counts = line_counts(&from_lines);
    let to_counts = line_counts(&to_lines);
    for (line, count) in &from_counts {
        let to_count = to_counts.get(line).copied().unwrap_or(0);
        if *count > to_count {
            removed += count - to_count;
        }
    }
    for (line, count) in &to_counts {
        let from_count = from_counts.get(line).copied().unwrap_or(0);
        if *count > from_count {
            added += count - from_count;
        }
    }

    (added, removed)
}

pub fn build_evidence_drift_report(
    host_id: i64,
    hostname: Option<String>,
    ip_address: Option<String>,
    from_scan_run_id: i64,
    to_scan_run_id: i64,
    from_evidence: &[(String, String, String)],
    to_evidence: &[(String, String, String)],
) -> EvidenceDriftReport {
    let from_by_type = evidence_by_type(from_evidence);
    let to_by_type = evidence_by_type(to_evidence);
    let mut changes = Vec::new();

    for evidence_type in DRIFT_EVIDENCE_TYPES {
        let from_entry = from_by_type.get(*evidence_type);
        let to_entry = to_by_type.get(*evidence_type);
        let (from_hash, from_content) = from_entry
            .map(|(hash, content)| (hash.clone(), content.clone()))
            .unwrap_or_default();
        let (to_hash, to_content) = to_entry
            .map(|(hash, content)| (hash.clone(), content.clone()))
            .unwrap_or_default();

        if from_hash == to_hash {
            continue;
        }

        let (added_lines, removed_lines) = diff_evidence_content(&from_content, &to_content);
        changes.push(EvidenceDriftChange {
            evidence_type: (*evidence_type).to_string(),
            from_scan_run_id,
            to_scan_run_id,
            from_hash,
            to_hash,
            added_lines,
            removed_lines,
        });
    }

    EvidenceDriftReport {
        host_id,
        hostname,
        ip_address,
        from_scan_run_id,
        to_scan_run_id,
        changes,
    }
}

fn evidence_by_type(evidence: &[(String, String, String)]) -> BTreeMap<String, (String, String)> {
    let mut grouped = BTreeMap::<String, Vec<String>>::new();
    for (evidence_type, _content_hash, content) in evidence {
        if !DRIFT_EVIDENCE_TYPES.contains(&evidence_type.as_str()) {
            continue;
        }
        grouped
            .entry(evidence_type.clone())
            .or_default()
            .push(content.clone());
    }

    grouped
        .into_iter()
        .map(|(evidence_type, contents)| {
            let merged = contents.join("\n");
            let hash = hash_content(&merged);
            (evidence_type, (hash, merged))
        })
        .collect()
}

fn line_counts(lines: &[&str]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        *counts.entry(trimmed.to_string()).or_default() += 1;
    }
    counts
}

fn hash_content(content: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(content.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_line_changes() {
        let (added, removed) =
            diff_evidence_content("PermitRootLogin yes\n", "PermitRootLogin no\n");
        assert_eq!(added, 1);
        assert_eq!(removed, 1);
    }
}
