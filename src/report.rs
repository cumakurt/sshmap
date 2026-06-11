use crate::db;
use crate::models::{ReportData, ReportSummary, RiskQuery, RiskRecord};
use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs;
use std::path::Path;

const REPORT_LIMIT: usize = 10_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReportFormat {
    Json,
    Html,
    Csv,
}

impl ReportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "html" => Ok(Self::Html),
            "csv" => Ok(Self::Csv),
            other => bail!("unsupported report format: {other}"),
        }
    }
}

pub fn build_report(db_path: &Path) -> Result<ReportData> {
    let stats = db::load_database_stats(db_path)?;
    let hosts = db::list_hosts(db_path, REPORT_LIMIT)?;
    let users = db::list_user_summaries(db_path, REPORT_LIMIT)?;
    let keys = db::list_keys(db_path, REPORT_LIMIT, false)?;
    let reused_keys = db::list_keys(db_path, REPORT_LIMIT, true)?;
    let risks = db::list_risks(
        db_path,
        &RiskQuery {
            severity: None,
            code: None,
            limit: REPORT_LIMIT,
        },
    )?;
    let severity_counts = count_risks_by_severity(&risks);

    Ok(ReportData {
        summary: ReportSummary {
            hosts: stats.hosts,
            users: stats.users,
            keys: stats.keys,
            risks: stats.risks,
            ssh_open_hosts: hosts.iter().filter(|host| host.ssh_open).count(),
            critical_risks: *severity_counts.get("CRITICAL").unwrap_or(&0),
            high_risks: *severity_counts.get("HIGH").unwrap_or(&0),
            reused_keys: reused_keys.len(),
        },
        severity_counts,
        hosts,
        users,
        keys,
        reused_keys,
        risks,
    })
}

pub fn render_report(report: &ReportData, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Json => Ok(serde_json::to_string_pretty(report)?),
        ReportFormat::Html => Ok(render_html_report(report)),
        ReportFormat::Csv => bail!("csv reports must be written with write_csv_report()"),
    }
}

pub fn write_csv_report(
    report: &ReportData,
    output_dir: &Path,
    db_path: &Path,
) -> Result<Vec<String>> {
    fs::create_dir_all(output_dir)?;
    let mut written = Vec::new();
    let edges = db::list_graph_edges(db_path)?;
    let known_hosts = db::list_known_host_entries(db_path, REPORT_LIMIT)?;
    let ssh_client_config = db::list_ssh_client_config_entries(db_path, REPORT_LIMIT)?;

    let files = [
        ("hosts.csv", render_hosts_csv(report)),
        ("users.csv", render_users_csv(report)),
        ("public_keys.csv", render_keys_csv(&report.keys)),
        ("key_reuse.csv", render_keys_csv(&report.reused_keys)),
        ("risks.csv", render_risks_csv(&report.risks)),
        ("graph_edges.csv", render_graph_edges_csv(&edges)),
        ("known_hosts.csv", render_known_hosts_csv(&known_hosts)),
        (
            "ssh_client_config.csv",
            render_ssh_client_config_csv(&ssh_client_config),
        ),
    ];

    for (filename, content) in files {
        let path = output_dir.join(filename);
        fs::write(&path, content)?;
        written.push(path.display().to_string());
    }

    Ok(written)
}

fn render_hosts_csv(report: &ReportData) -> String {
    let mut csv = String::from("id,hostname,fqdn,ip_address,port,ssh_open,user_count,risk_count\n");
    for host in &report.hosts {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{}",
            host.id,
            csv_field(host.hostname.as_deref().unwrap_or("")),
            csv_field(host.fqdn.as_deref().unwrap_or("")),
            csv_field(&host.ip_address),
            host.port,
            yes_no(host.ssh_open),
            host.user_count,
            host.risk_count
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn render_users_csv(report: &ReportData) -> String {
    let mut csv = String::from("username,host_count,key_count,sudo_rule_count,risk_count\n");
    for user in &report.users {
        writeln!(
            csv,
            "{},{},{},{},{}",
            csv_field(&user.username),
            user.host_count,
            user.key_count,
            user.sudo_rule_count,
            user.risk_count
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn render_keys_csv(keys: &[crate::models::KeySummaryRecord]) -> String {
    let mut csv = String::from(
        "id,key_type,fingerprint_sha256,host_count,user_count,root_usage_count,risk_count\n",
    );
    for key in keys {
        writeln!(
            csv,
            "{},{},{},{},{},{},{}",
            key.id,
            csv_field(&key.key_type),
            csv_field(&key.fingerprint_sha256),
            key.host_count,
            key.user_count,
            key.root_usage_count,
            key.risk_count
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn render_risks_csv(risks: &[RiskRecord]) -> String {
    let mut csv = String::from(
        "id,severity,score,code,hostname,ip_address,username,public_key_fingerprint,title,status\n",
    );
    for risk in risks {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{}",
            risk.id,
            csv_field(&risk.severity),
            risk.score,
            csv_field(&risk.risk_code),
            csv_field(risk.hostname.as_deref().unwrap_or("")),
            csv_field(risk.ip_address.as_deref().unwrap_or("")),
            csv_field(risk.username.as_deref().unwrap_or("")),
            csv_field(risk.public_key_fingerprint.as_deref().unwrap_or("")),
            csv_field(&risk.title),
            csv_field(&risk.status)
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn render_graph_edges_csv(edges: &[crate::models::GraphEdgeRecord]) -> String {
    let mut csv = String::from(
        "id,from_type,from_label,to_type,to_label,edge_type,weight,confidence,evidence\n",
    );
    for edge in edges {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{}",
            edge.id,
            csv_field(&edge.from_type),
            csv_field(&edge.from_label),
            csv_field(&edge.to_type),
            csv_field(&edge.to_label),
            csv_field(&edge.edge_type),
            edge.weight,
            csv_field(&edge.confidence),
            csv_field(edge.evidence.as_deref().unwrap_or(""))
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn render_known_hosts_csv(entries: &[crate::models::KnownHostEntryRecord]) -> String {
    let mut csv = String::from(
        "id,host_id,hostname,ip_address,known_host,known_ip,host_key_type,host_key_fingerprint,hashed,source_file,line_number,confidence\n",
    );
    for entry in entries {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            entry.id,
            entry.host_id,
            csv_field(entry.hostname.as_deref().unwrap_or("")),
            csv_field(entry.ip_address.as_deref().unwrap_or("")),
            csv_field(entry.known_host.as_deref().unwrap_or("")),
            csv_field(entry.known_ip.as_deref().unwrap_or("")),
            csv_field(&entry.host_key_type),
            csv_field(entry.host_key_fingerprint.as_deref().unwrap_or("")),
            yes_no(entry.hashed),
            csv_field(entry.source_file.as_deref().unwrap_or("")),
            entry.line_number.unwrap_or(0),
            csv_field(&entry.confidence)
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn render_ssh_client_config_csv(entries: &[crate::models::SshClientConfigEntryRecord]) -> String {
    let mut csv = String::from(
        "id,host_id,hostname,ip_address,host_pattern,config_hostname,ssh_user,port,identity_file,proxy_jump,proxy_command,forward_agent,local_forward,remote_forward,dynamic_forward,strict_host_key_checking,source_file,line_number\n",
    );
    for entry in entries {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            entry.id,
            entry.host_id,
            csv_field(entry.hostname.as_deref().unwrap_or("")),
            csv_field(entry.ip_address.as_deref().unwrap_or("")),
            csv_field(&entry.host_pattern),
            csv_field(entry.config_hostname.as_deref().unwrap_or("")),
            csv_field(entry.ssh_user.as_deref().unwrap_or("")),
            entry.port.unwrap_or(0),
            csv_field(entry.identity_file.as_deref().unwrap_or("")),
            csv_field(entry.proxy_jump.as_deref().unwrap_or("")),
            csv_field(entry.proxy_command.as_deref().unwrap_or("")),
            csv_field(entry.forward_agent.as_deref().unwrap_or("")),
            csv_field(entry.local_forward.as_deref().unwrap_or("")),
            csv_field(entry.remote_forward.as_deref().unwrap_or("")),
            csv_field(entry.dynamic_forward.as_deref().unwrap_or("")),
            csv_field(entry.strict_host_key_checking.as_deref().unwrap_or("")),
            csv_field(entry.source_file.as_deref().unwrap_or("")),
            entry.line_number.unwrap_or(0)
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn count_risks_by_severity(risks: &[RiskRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for risk in risks {
        *counts.entry(risk.severity.clone()).or_insert(0) += 1;
    }
    counts
}

fn render_html_report(report: &ReportData) -> String {
    let mut content = String::new();
    write_metrics(&mut content, report);
    write_risk_table(&mut content, report);
    write_key_table(&mut content, "Reused Public Keys", &report.reused_keys);
    write_host_table(&mut content, report);
    write_user_table(&mut content, report);

    include_str!("../templates/report.html")
        .replace("{{STYLES}}", include_str!("../templates/report.css"))
        .replace("{{CONTENT}}", &content)
}

fn write_metrics(html: &mut String, report: &ReportData) {
    html.push_str("<h2>Executive Summary</h2><div class=\"grid\">");
    metric(html, "Hosts", report.summary.hosts);
    metric(html, "SSH Open Hosts", report.summary.ssh_open_hosts);
    metric(html, "Users", report.summary.users);
    metric(html, "Public Keys", report.summary.keys);
    metric(html, "Risks", report.summary.risks);
    metric(html, "Critical Risks", report.summary.critical_risks);
    metric(html, "High Risks", report.summary.high_risks);
    metric(html, "Reused Keys", report.summary.reused_keys);
    html.push_str("</div>");
}

fn metric(html: &mut String, label: &str, value: usize) {
    write!(
        html,
        "<div class=\"metric\"><span>{}</span><strong>{}</strong></div>",
        escape_html(label),
        value
    )
    .expect("writing to String cannot fail");
}

fn write_risk_table(html: &mut String, report: &ReportData) {
    html.push_str("<h2>Top Risks</h2>");
    html.push_str("<table><thead><tr><th>ID</th><th>Severity</th><th>Score</th><th>Code</th><th>Target</th><th>Title</th></tr></thead><tbody>");
    for risk in report.risks.iter().take(50) {
        write!(
            html,
            "<tr><td>{}</td><td class=\"severity-{}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            risk.id,
            escape_html(&risk.severity),
            escape_html(&risk.severity),
            risk.score,
            escape_html(&risk.risk_code),
            escape_html(&risk_target(risk)),
            escape_html(&risk.title)
        )
        .expect("writing to String cannot fail");
    }
    html.push_str("</tbody></table>");
}

fn write_key_table(html: &mut String, title: &str, keys: &[crate::models::KeySummaryRecord]) {
    html.push_str("<h2>");
    html.push_str(&escape_html(title));
    html.push_str("</h2><table><thead><tr><th>ID</th><th>Type</th><th>Fingerprint</th><th>Hosts</th><th>Users</th><th>Root</th><th>Risks</th></tr></thead><tbody>");
    for key in keys.iter().take(50) {
        write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            key.id,
            escape_html(&key.key_type),
            escape_html(&key.fingerprint_sha256),
            key.host_count,
            key.user_count,
            key.root_usage_count,
            key.risk_count
        )
        .expect("writing to String cannot fail");
    }
    html.push_str("</tbody></table>");
}

fn write_host_table(html: &mut String, report: &ReportData) {
    html.push_str("<h2>Hosts</h2><table><thead><tr><th>ID</th><th>Hostname</th><th>IP</th><th>Port</th><th>Open</th><th>Users</th><th>Risks</th></tr></thead><tbody>");
    for host in report.hosts.iter().take(100) {
        write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            host.id,
            escape_html(host.hostname.as_deref().unwrap_or("-")),
            escape_html(&host.ip_address),
            host.port,
            yes_no(host.ssh_open),
            host.user_count,
            host.risk_count
        )
        .expect("writing to String cannot fail");
    }
    html.push_str("</tbody></table>");
}

fn write_user_table(html: &mut String, report: &ReportData) {
    html.push_str("<h2>Users</h2><table><thead><tr><th>Username</th><th>Hosts</th><th>Keys</th><th>Sudo</th><th>Risks</th></tr></thead><tbody>");
    for user in report.users.iter().take(100) {
        write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&user.username),
            user.host_count,
            user.key_count,
            user.sudo_rule_count,
            user.risk_count
        )
        .expect("writing to String cannot fail");
    }
    html.push_str("</tbody></table>");
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
    risk.hostname
        .clone()
        .or_else(|| risk.ip_address.clone())
        .or_else(|| risk.public_key_fingerprint.clone())
        .unwrap_or_else(|| "global".to_string())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        HostRecord, KeySummaryRecord, ReportData, ReportSummary, RiskRecord, UserSummaryRecord,
    };

    #[test]
    fn parses_report_formats() {
        assert_eq!(ReportFormat::parse("json").unwrap(), ReportFormat::Json);
        assert_eq!(ReportFormat::parse("HTML").unwrap(), ReportFormat::Html);
        assert_eq!(ReportFormat::parse("csv").unwrap(), ReportFormat::Csv);
        assert!(ReportFormat::parse("pdf").is_err());
    }

    #[test]
    fn renders_csv_files() {
        let report = sample_report();
        let temp_dir = std::env::temp_dir().join(format!("sshmap-report-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let db_path = temp_dir.join("test.db");
        crate::db::initialize_database(&db_path).unwrap();
        let written = write_csv_report(&report, &temp_dir, &db_path).unwrap();
        assert_eq!(written.len(), 8);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn renders_json_report() {
        let report = sample_report();
        let rendered = render_report(&report, ReportFormat::Json).unwrap();

        assert!(rendered.contains("\"hosts\""));
    }

    #[test]
    fn renders_html_report_and_escapes_content() {
        let report = sample_report();
        let rendered = render_report(&report, ReportFormat::Html).unwrap();

        assert!(rendered.contains("<!doctype html>"));
        assert!(rendered.contains("&lt;script&gt;"));
    }

    fn sample_report() -> ReportData {
        ReportData {
            summary: ReportSummary {
                hosts: 1,
                users: 1,
                keys: 1,
                risks: 1,
                ssh_open_hosts: 1,
                critical_risks: 1,
                high_risks: 0,
                reused_keys: 0,
            },
            severity_counts: BTreeMap::from([("CRITICAL".to_string(), 1)]),
            hosts: vec![HostRecord {
                id: 1,
                hostname: Some("<script>".to_string()),
                fqdn: None,
                ip_address: "192.0.2.10".to_string(),
                port: 22,
                ssh_open: true,
                ssh_banner: None,
                source: "test".to_string(),
                first_seen: "2026-06-11T00:00:00Z".to_string(),
                last_seen: "2026-06-11T00:00:00Z".to_string(),
                user_count: 1,
                risk_count: 1,
            }],
            users: vec![UserSummaryRecord {
                username: "root".to_string(),
                host_count: 1,
                key_count: 0,
                sudo_rule_count: 0,
                risk_count: 0,
            }],
            keys: vec![KeySummaryRecord {
                id: 1,
                key_type: "ssh-ed25519".to_string(),
                fingerprint_sha256: "SHA256:test".to_string(),
                key_comment: None,
                host_count: 1,
                user_count: 1,
                root_usage_count: 0,
                risk_count: 0,
            }],
            reused_keys: Vec::new(),
            risks: vec![RiskRecord {
                id: 1,
                host_id: Some(1),
                hostname: Some("<script>".to_string()),
                ip_address: Some("192.0.2.10".to_string()),
                username: None,
                public_key_fingerprint: None,
                risk_code: "SSH_ROOT_LOGIN_ENABLED".to_string(),
                severity: "CRITICAL".to_string(),
                score: 95,
                confidence: "HIGH".to_string(),
                title: "Root login".to_string(),
                description: None,
                impact: None,
                evidence: None,
                recommendation: None,
                status: "open".to_string(),
                first_seen: "2026-06-11T00:00:00Z".to_string(),
                last_seen: "2026-06-11T00:00:00Z".to_string(),
            }],
        }
    }
}
