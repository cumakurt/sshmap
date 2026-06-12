use crate::compliance::ComplianceReport;
use crate::evidence_drift::EvidenceDriftReport;
use crate::models::{
    BaselineDiffRecord, BaselineRecord, BaselineRiskRecord, DetailedDatabaseStats,
    HostDetailRecord, HostRecord, KeyDetailRecord, KeyLocationRecord, KeySummaryRecord,
    RiskExceptionRecord, RiskRecord, ScanRunDetailRecord, ScanRunRecord, SudoRuleRecord,
    UserDetailRecord, UserSummaryRecord,
};
use std::fmt::Write;

pub fn format_risk_list_text(risks: &[RiskRecord]) -> String {
    let mut output = String::new();

    if risks.is_empty() {
        output.push_str("No risks found.\n");
        return output;
    }

    writeln!(
        output,
        "{:<5} {:<8} {:<5} {:<36} {:<28} TITLE",
        "ID", "SEVERITY", "SCORE", "CODE", "TARGET"
    )
    .expect("writing to String cannot fail");

    for risk in risks {
        writeln!(
            output,
            "{:<5} {:<8} {:<5} {:<36} {:<28} {}",
            risk.id,
            risk.severity,
            risk.score,
            truncate(&risk.risk_code, 36),
            truncate(&format_risk_target(risk), 28),
            risk.title
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_risk_detail_text(risk: &RiskRecord) -> String {
    let mut output = String::new();

    writeln!(output, "ID: {}", risk.id).expect("writing to String cannot fail");
    writeln!(output, "Severity: {}", risk.severity).expect("writing to String cannot fail");
    writeln!(output, "Score: {}", risk.score).expect("writing to String cannot fail");
    writeln!(output, "Confidence: {}", risk.confidence).expect("writing to String cannot fail");
    writeln!(output, "Code: {}", risk.risk_code).expect("writing to String cannot fail");
    writeln!(output, "Title: {}", risk.title).expect("writing to String cannot fail");
    writeln!(output, "Target: {}", format_risk_target(risk))
        .expect("writing to String cannot fail");
    writeln!(output, "Status: {}", risk.status).expect("writing to String cannot fail");

    write_optional_section(&mut output, "Description", risk.description.as_deref());
    write_optional_section(&mut output, "Impact", risk.impact.as_deref());
    write_optional_section(&mut output, "Evidence", risk.evidence.as_deref());
    write_optional_section(
        &mut output,
        "Recommendation",
        risk.recommendation.as_deref(),
    );

    output
}

pub fn format_host_list_text(hosts: &[HostRecord]) -> String {
    let mut output = String::new();
    if hosts.is_empty() {
        output.push_str("No hosts found.\n");
        return output;
    }

    writeln!(
        output,
        "{:<5} {:<28} {:<16} {:<6} {:<5} {:<5} {:<5}",
        "ID", "HOSTNAME", "IP", "PORT", "OPEN", "USERS", "RISKS"
    )
    .expect("writing to String cannot fail");

    for host in hosts {
        writeln!(
            output,
            "{:<5} {:<28} {:<16} {:<6} {:<5} {:<5} {:<5}",
            host.id,
            truncate(host.hostname.as_deref().unwrap_or("-"), 28),
            host.ip_address,
            host.port,
            yes_no(host.ssh_open),
            host.user_count,
            host.risk_count
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_host_detail_text(detail: &HostDetailRecord) -> String {
    let mut output = String::new();
    let host = &detail.host;

    writeln!(output, "ID: {}", host.id).expect("writing to String cannot fail");
    writeln!(
        output,
        "Hostname: {}",
        host.hostname.as_deref().unwrap_or("-")
    )
    .expect("writing to String cannot fail");
    writeln!(output, "IP: {}", host.ip_address).expect("writing to String cannot fail");
    writeln!(output, "Port: {}", host.port).expect("writing to String cannot fail");
    if host.os_family.is_some() || host.os_version.is_some() {
        writeln!(
            output,
            "OS: {} {}",
            host.os_family.as_deref().unwrap_or("-"),
            host.os_version.as_deref().unwrap_or("-")
        )
        .expect("writing to String cannot fail");
    }
    if host.environment.is_some() || host.criticality.is_some() {
        writeln!(
            output,
            "Metadata: environment={} criticality={}",
            host.environment.as_deref().unwrap_or("-"),
            host.criticality.as_deref().unwrap_or("-")
        )
        .expect("writing to String cannot fail");
    }
    writeln!(output, "SSH open: {}", yes_no(host.ssh_open)).expect("writing to String cannot fail");
    write_optional_section(&mut output, "SSH banner", host.ssh_banner.as_deref());

    writeln!(output, "\nUsers: {}", detail.users.len()).expect("writing to String cannot fail");
    for user in &detail.users {
        writeln!(
            output,
            "- {} uid={} shell={}",
            user.username,
            option_i64(user.uid),
            user.shell.as_deref().unwrap_or("-")
        )
        .expect("writing to String cannot fail");
    }

    writeln!(output, "\nRisks: {}", detail.risks.len()).expect("writing to String cannot fail");
    for risk in &detail.risks {
        writeln!(
            output,
            "- [{}] {} {}",
            risk.severity, risk.risk_code, risk.title
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_scan_run_list_text(runs: &[ScanRunRecord]) -> String {
    let mut output = String::new();
    if runs.is_empty() {
        output.push_str("No scan runs found.\n");
        return output;
    }

    writeln!(
        output,
        "{:<5} {:<11} {:<10} {:<24} {:<24} OPERATOR",
        "ID", "MODE", "STATUS", "STARTED", "FINISHED"
    )
    .expect("writing to String cannot fail");

    for run in runs {
        writeln!(
            output,
            "{:<5} {:<11} {:<10} {:<24} {:<24} {}",
            run.id,
            truncate(&run.mode, 11),
            truncate(&run.status, 10),
            truncate(&run.started_at, 24),
            truncate(run.finished_at.as_deref().unwrap_or("-"), 24),
            run.operator.as_deref().unwrap_or("-")
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_scan_run_detail_text(detail: &ScanRunDetailRecord) -> String {
    let mut output = String::new();
    let run = &detail.run;

    writeln!(output, "ID: {}", run.id).expect("writing to String cannot fail");
    writeln!(output, "UUID: {}", run.run_uuid).expect("writing to String cannot fail");
    writeln!(output, "Mode: {}", run.mode).expect("writing to String cannot fail");
    writeln!(output, "Status: {}", run.status).expect("writing to String cannot fail");
    writeln!(output, "Started: {}", run.started_at).expect("writing to String cannot fail");
    writeln!(
        output,
        "Finished: {}",
        run.finished_at.as_deref().unwrap_or("-")
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "Operator: {}",
        run.operator.as_deref().unwrap_or("-")
    )
    .expect("writing to String cannot fail");
    if let Some(sudo_enabled) = run.sudo_enabled {
        writeln!(output, "Sudo enabled: {}", yes_no(sudo_enabled))
            .expect("writing to String cannot fail");
    }
    write_optional_section(&mut output, "Targets", run.targets_json.as_deref());
    write_optional_section(&mut output, "Summary", run.summary_json.as_deref());
    write_optional_section(&mut output, "Error", run.error_message.as_deref());

    writeln!(output, "\nEvents: {}", detail.events.len()).expect("writing to String cannot fail");
    for event in &detail.events {
        writeln!(
            output,
            "- {} {}: {}",
            event.created_at, event.event_type, event.message
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_user_list_text(users: &[UserSummaryRecord]) -> String {
    let mut output = String::new();
    if users.is_empty() {
        output.push_str("No users found.\n");
        return output;
    }

    writeln!(
        output,
        "{:<24} {:<5} {:<5} {:<5} {:<5}",
        "USERNAME", "HOSTS", "KEYS", "SUDO", "RISKS"
    )
    .expect("writing to String cannot fail");

    for user in users {
        writeln!(
            output,
            "{:<24} {:<5} {:<5} {:<5} {:<5}",
            truncate(&user.username, 24),
            user.host_count,
            user.key_count,
            user.sudo_rule_count,
            user.risk_count
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_user_detail_text(detail: &UserDetailRecord) -> String {
    let mut output = String::new();

    writeln!(output, "User: {}", detail.username).expect("writing to String cannot fail");
    writeln!(output, "\nAccounts: {}", detail.accounts.len())
        .expect("writing to String cannot fail");
    for account in &detail.accounts {
        writeln!(
            output,
            "- {}@{} uid={} shell={}",
            account.username,
            account.hostname.as_deref().unwrap_or(&account.ip_address),
            option_i64(account.uid),
            account.shell.as_deref().unwrap_or("-")
        )
        .expect("writing to String cannot fail");
    }

    writeln!(
        output,
        "\nAuthorized keys: {}",
        detail.authorized_keys.len()
    )
    .expect("writing to String cannot fail");
    for location in &detail.authorized_keys {
        write_key_location(&mut output, location);
    }

    writeln!(output, "\nSudo rules: {}", detail.sudo_rules.len())
        .expect("writing to String cannot fail");
    for rule in &detail.sudo_rules {
        write_sudo_rule(&mut output, rule);
    }

    writeln!(output, "\nRisks: {}", detail.risks.len()).expect("writing to String cannot fail");
    for risk in &detail.risks {
        writeln!(
            output,
            "- [{}] {} {}",
            risk.severity, risk.risk_code, risk.title
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_key_list_text(keys: &[KeySummaryRecord]) -> String {
    let mut output = String::new();
    if keys.is_empty() {
        output.push_str("No public keys found.\n");
        return output;
    }

    writeln!(
        output,
        "{:<5} {:<18} {:<46} {:<5} {:<5} {:<5} {:<5}",
        "ID", "TYPE", "FINGERPRINT", "HOSTS", "USERS", "ROOT", "RISKS"
    )
    .expect("writing to String cannot fail");

    for key in keys {
        writeln!(
            output,
            "{:<5} {:<18} {:<46} {:<5} {:<5} {:<5} {:<5}",
            key.id,
            truncate(&key.key_type, 18),
            truncate(&key.fingerprint_sha256, 46),
            key.host_count,
            key.user_count,
            key.root_usage_count,
            key.risk_count
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_key_detail_text(detail: &KeyDetailRecord) -> String {
    let mut output = String::new();
    let key = &detail.key;

    writeln!(output, "ID: {}", key.id).expect("writing to String cannot fail");
    writeln!(output, "Type: {}", key.key_type).expect("writing to String cannot fail");
    writeln!(output, "Fingerprint: {}", key.fingerprint_sha256)
        .expect("writing to String cannot fail");
    write_optional_section(&mut output, "Comment", key.key_comment.as_deref());
    writeln!(output, "Hosts: {}", key.host_count).expect("writing to String cannot fail");
    writeln!(output, "Users: {}", key.user_count).expect("writing to String cannot fail");
    writeln!(output, "Root usages: {}", key.root_usage_count)
        .expect("writing to String cannot fail");

    writeln!(output, "\nLocations: {}", detail.locations.len())
        .expect("writing to String cannot fail");
    for location in &detail.locations {
        write_key_location(&mut output, location);
    }

    writeln!(output, "\nRisks: {}", detail.risks.len()).expect("writing to String cannot fail");
    for risk in &detail.risks {
        writeln!(
            output,
            "- [{}] {} {}",
            risk.severity, risk.risk_code, risk.title
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_exception_list_text(records: &[RiskExceptionRecord]) -> String {
    let mut output = String::new();
    if records.is_empty() {
        output.push_str("No risk exceptions found.\n");
        return output;
    }

    writeln!(
        output,
        "{:<6} {:<32} {:<12} {:<16} REASON",
        "ID", "CODE", "HOST", "USER"
    )
    .expect("writing to String cannot fail");

    for record in records {
        writeln!(
            output,
            "{:<6} {:<32} {:<12} {:<16} {}",
            record.id,
            record.risk_code,
            record
                .host_id
                .map(|host_id| host_id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            record.username.as_deref().unwrap_or("-"),
            record.reason
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_baseline_created_text(baseline: &BaselineRecord) -> String {
    let mut output = String::new();
    writeln!(output, "Baseline created: {}", baseline.name).expect("writing to String cannot fail");
    writeln!(output, "ID: {}", baseline.id).expect("writing to String cannot fail");
    writeln!(output, "Created at: {}", baseline.created_at).expect("writing to String cannot fail");
    write_baseline_summary(&mut output, baseline);
    output
}

pub fn format_baseline_list_text(baselines: &[BaselineRecord]) -> String {
    let mut output = String::new();
    if baselines.is_empty() {
        output.push_str("No baselines found.\n");
        return output;
    }

    writeln!(
        output,
        "{:<5} {:<24} {:<25} {:<6} {:<8} {:<5} {:<5} {:<5}",
        "ID", "NAME", "CREATED", "RISKS", "CRITICAL", "HIGH", "HOSTS", "KEYS"
    )
    .expect("writing to String cannot fail");

    for baseline in baselines {
        writeln!(
            output,
            "{:<5} {:<24} {:<25} {:<6} {:<8} {:<5} {:<5} {:<5}",
            baseline.id,
            truncate(&baseline.name, 24),
            truncate(&baseline.created_at, 25),
            baseline.summary.risks,
            baseline.summary.critical_risks,
            baseline.summary.high_risks,
            baseline.summary.hosts,
            baseline.summary.keys
        )
        .expect("writing to String cannot fail");
    }

    output
}

pub fn format_baseline_diff_text(diff: &BaselineDiffRecord) -> String {
    let mut output = String::new();
    writeln!(output, "Diff from {} to {}", diff.from.name, diff.to.name)
        .expect("writing to String cannot fail");
    writeln!(output, "New risks: {}", diff.new_risks.len()).expect("writing to String cannot fail");
    writeln!(output, "Resolved risks: {}", diff.resolved_risks.len())
        .expect("writing to String cannot fail");
    writeln!(output, "Unchanged risks: {}", diff.unchanged_risks)
        .expect("writing to String cannot fail");

    write_risk_snapshot_section(&mut output, "New risk details", &diff.new_risks);
    write_risk_snapshot_section(&mut output, "Resolved risk details", &diff.resolved_risks);

    output
}

fn format_risk_target(risk: &RiskRecord) -> String {
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

fn write_baseline_summary(output: &mut String, baseline: &BaselineRecord) {
    writeln!(
        output,
        "Snapshot: {} hosts, {} users, {} keys, {} risks (critical: {}, high: {})",
        baseline.summary.hosts,
        baseline.summary.users,
        baseline.summary.keys,
        baseline.summary.risks,
        baseline.summary.critical_risks,
        baseline.summary.high_risks
    )
    .expect("writing to String cannot fail");
}

fn write_risk_snapshot_section(output: &mut String, label: &str, risks: &[BaselineRiskRecord]) {
    if risks.is_empty() {
        return;
    }

    writeln!(output, "\n{label}:").expect("writing to String cannot fail");
    for risk in risks.iter().take(20) {
        writeln!(
            output,
            "- [{}] {} {} - {}",
            risk.severity, risk.risk_code, risk.target, risk.title
        )
        .expect("writing to String cannot fail");
    }
    if risks.len() > 20 {
        writeln!(output, "... {} more", risks.len() - 20).expect("writing to String cannot fail");
    }
}

fn write_key_location(output: &mut String, location: &KeyLocationRecord) {
    writeln!(
        output,
        "- {}@{} {} {}:{}",
        location.username,
        location.hostname.as_deref().unwrap_or(&location.ip_address),
        location.fingerprint_sha256,
        location.source_file.as_deref().unwrap_or("-"),
        option_i64(location.line_number)
    )
    .expect("writing to String cannot fail");
}

fn write_sudo_rule(output: &mut String, rule: &SudoRuleRecord) {
    writeln!(
        output,
        "- {}@{} run_as={} nopasswd={} command={}",
        rule.subject,
        rule.hostname.as_deref().unwrap_or(&rule.ip_address),
        rule.run_as.as_deref().unwrap_or("-"),
        yes_no(rule.nopasswd),
        rule.command.as_deref().unwrap_or("-")
    )
    .expect("writing to String cannot fail");
}

fn write_optional_section(output: &mut String, label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        writeln!(output, "\n{label}:").expect("writing to String cannot fail");
        writeln!(output, "{value}").expect("writing to String cannot fail");
    }
}

pub fn format_detailed_database_stats(stats: &DetailedDatabaseStats) -> String {
    let mut output = String::new();
    writeln!(output, "Schema version: {}", stats.schema_version)
        .expect("writing to String cannot fail");
    writeln!(output, "Hosts: {}", stats.hosts).expect("writing to String cannot fail");
    writeln!(output, "Users: {}", stats.users).expect("writing to String cannot fail");
    writeln!(output, "Public keys: {}", stats.keys).expect("writing to String cannot fail");
    writeln!(output, "Risks: {}", stats.risks).expect("writing to String cannot fail");
    writeln!(output, "Raw evidence: {}", stats.raw_evidence)
        .expect("writing to String cannot fail");
    writeln!(output, "Graph edges: {}", stats.graph_edges).expect("writing to String cannot fail");
    writeln!(output, "Known hosts entries: {}", stats.known_hosts_entries)
        .expect("writing to String cannot fail");
    writeln!(
        output,
        "SSH client config entries: {}",
        stats.ssh_client_config_entries
    )
    .expect("writing to String cannot fail");
    writeln!(output, "Host aliases: {}", stats.host_aliases)
        .expect("writing to String cannot fail");
    writeln!(
        output,
        "Data quality findings: {}",
        stats.data_quality_findings
    )
    .expect("writing to String cannot fail");
    writeln!(output, "Risk exceptions: {}", stats.risk_exceptions)
        .expect("writing to String cannot fail");
    writeln!(output, "Baselines: {}", stats.baselines).expect("writing to String cannot fail");
    if let Some(timestamp) = &stats.last_analysis_finished_at {
        writeln!(output, "Last analysis: {timestamp}").expect("writing to String cannot fail");
    }
    output
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    truncated.push('~');
    truncated
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn option_i64(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

pub fn format_evidence_drift_text(report: &EvidenceDriftReport) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "Evidence drift for host {} (scan runs {} -> {})",
        report
            .hostname
            .as_deref()
            .or(report.ip_address.as_deref())
            .unwrap_or("-"),
        report.from_scan_run_id,
        report.to_scan_run_id
    )
    .expect("writing to String cannot fail");
    if report.changes.is_empty() {
        writeln!(output, "No evidence changes detected.").expect("writing to String cannot fail");
        return output;
    }
    for change in &report.changes {
        writeln!(
            output,
            "- {}: +{} / -{} lines (hash {} -> {})",
            change.evidence_type,
            change.added_lines,
            change.removed_lines,
            change.from_hash,
            change.to_hash
        )
        .expect("writing to String cannot fail");
    }
    output
}

pub fn format_compliance_report_text(report: &ComplianceReport) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "Compliance report ({})",
        report.framework
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "Passing: {}/{} ({:.1}%)",
        report.passing_controls,
        report.total_controls,
        report.compliance_percent
    )
    .expect("writing to String cannot fail");
    for control in &report.controls {
        writeln!(
            output,
            "- [{}] {} {}: {}",
            control.status,
            control.framework,
            control.control_id,
            control.title
        )
        .expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_empty_risk_list() {
        assert_eq!(format_risk_list_text(&[]), "No risks found.\n");
    }

    #[test]
    fn formats_risk_list_row() {
        let output = format_risk_list_text(&[sample_risk()]);

        assert!(output.contains("SSH_ROOT_LOGIN_ENABLED"));
        assert!(output.contains("Root login is enabled"));
    }

    #[test]
    fn formats_risk_detail_sections() {
        let output = format_risk_detail_text(&sample_risk());

        assert!(output.contains("Evidence:"));
        assert!(output.contains("Recommendation:"));
    }

    #[test]
    fn formats_host_list_row() {
        let output = format_host_list_text(&[HostRecord {
            id: 1,
            hostname: Some("web01".to_string()),
            fqdn: None,
            ip_address: "192.0.2.10".to_string(),
            port: 22,
            os_family: None,
            os_version: None,
            environment: None,
            criticality: None,
            ssh_open: true,
            ssh_banner: None,
            source: "test".to_string(),
            first_seen: "2026-06-11T00:00:00Z".to_string(),
            last_seen: "2026-06-11T00:00:00Z".to_string(),
            user_count: 2,
            risk_count: 1,
        }]);

        assert!(output.contains("web01"));
        assert!(output.contains("yes"));
    }

    #[test]
    fn formats_user_list_row() {
        let output = format_user_list_text(&[UserSummaryRecord {
            username: "deploy".to_string(),
            host_count: 2,
            key_count: 1,
            sudo_rule_count: 1,
            risk_count: 1,
        }]);

        assert!(output.contains("deploy"));
    }

    #[test]
    fn formats_key_list_row() {
        let output = format_key_list_text(&[KeySummaryRecord {
            id: 1,
            key_type: "ssh-ed25519".to_string(),
            fingerprint_sha256: "SHA256:test".to_string(),
            key_comment: None,
            host_count: 2,
            user_count: 1,
            root_usage_count: 0,
            risk_count: 1,
        }]);

        assert!(output.contains("ssh-ed25519"));
        assert!(output.contains("SHA256:test"));
    }

    #[test]
    fn formats_baseline_list_row() {
        let output = format_baseline_list_text(&[sample_baseline("2026-q2")]);

        assert!(output.contains("2026-q2"));
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn formats_baseline_diff_summary() {
        let diff = BaselineDiffRecord {
            from: sample_baseline("2026-q2"),
            to: sample_baseline("latest"),
            new_risks: vec![sample_baseline_risk("SUDO_NOPASSWD_ALL")],
            resolved_risks: vec![],
            unchanged_risks: 3,
        };

        let output = format_baseline_diff_text(&diff);

        assert!(output.contains("Diff from 2026-q2 to latest"));
        assert!(output.contains("New risks: 1"));
        assert!(output.contains("SUDO_NOPASSWD_ALL"));
    }

    fn sample_risk() -> RiskRecord {
        RiskRecord {
            id: 1,
            host_id: Some(1),
            hostname: Some("web01".to_string()),
            ip_address: Some("192.0.2.10".to_string()),
            username: None,
            public_key_fingerprint: None,
            risk_code: "SSH_ROOT_LOGIN_ENABLED".to_string(),
            severity: "CRITICAL".to_string(),
            score: 95,
            confidence: "HIGH".to_string(),
            title: "Root login is enabled".to_string(),
            description: Some("Description".to_string()),
            impact: Some("Impact".to_string()),
            evidence: Some("Evidence".to_string()),
            recommendation: Some("Recommendation".to_string()),
            status: "open".to_string(),
            first_seen: "2026-06-11T00:00:00Z".to_string(),
            last_seen: "2026-06-11T00:00:00Z".to_string(),
        }
    }

    fn sample_baseline(name: &str) -> BaselineRecord {
        BaselineRecord {
            id: 1,
            name: name.to_string(),
            created_at: "2026-06-11T00:00:00Z".to_string(),
            summary: crate::models::BaselineSummary {
                hosts: 2,
                users: 4,
                keys: 1,
                risks: 5,
                critical_risks: 1,
                high_risks: 2,
            },
        }
    }

    fn sample_baseline_risk(code: &str) -> BaselineRiskRecord {
        BaselineRiskRecord {
            signature: "signature".to_string(),
            risk_code: code.to_string(),
            severity: "HIGH".to_string(),
            score: 80,
            target: "web01".to_string(),
            title: "Risk title".to_string(),
            evidence: Some("Evidence".to_string()),
            status: "open".to_string(),
        }
    }
}
