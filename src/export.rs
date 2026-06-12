use crate::db;
use crate::models::{HostRecord, RiskQuery, RiskRecord};
use crate::server::build_api_summary;
use anyhow::{Result, bail};
use std::fmt::Write;
use std::fs;
use std::io::{self, Write as IoWrite};
use std::path::Path;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RiskExportFormat {
    Json,
    Ndjson,
}

impl RiskExportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "ndjson" => Ok(Self::Ndjson),
            other => bail!("unsupported risk export format: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HostExportFormat {
    Json,
    Csv,
}

impl HostExportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            other => bail!("unsupported host export format: {other}"),
        }
    }
}

pub enum KnownHostExportFormat {
    Json,
    Csv,
}

impl KnownHostExportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            other => bail!("unsupported known host export format: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SshConfigExportFormat {
    Json,
    Csv,
}

impl SshConfigExportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            other => bail!("unsupported ssh config export format: {other}"),
        }
    }
}

pub fn export_summary_json(db_path: &Path) -> Result<String> {
    Ok(serde_json::to_string_pretty(&build_api_summary(db_path)?)?)
}

pub fn export_risks(db_path: &Path, format: RiskExportFormat, query: &RiskQuery) -> Result<String> {
    let risks = db::list_risks(db_path, query)?;
    match format {
        RiskExportFormat::Json => Ok(serde_json::to_string_pretty(&risks)?),
        RiskExportFormat::Ndjson => render_risks_ndjson(&risks),
    }
}

pub fn export_hosts(db_path: &Path, format: HostExportFormat, limit: usize) -> Result<String> {
    let hosts = db::list_hosts(db_path, limit)?;
    match format {
        HostExportFormat::Json => Ok(serde_json::to_string_pretty(&hosts)?),
        HostExportFormat::Csv => Ok(render_hosts_monitoring_csv(&hosts, db_path, limit)?),
    }
}

pub fn export_known_hosts(
    db_path: &Path,
    format: KnownHostExportFormat,
    limit: usize,
) -> Result<String> {
    let entries = db::list_known_host_entries(db_path, limit)?;
    match format {
        KnownHostExportFormat::Json => Ok(serde_json::to_string_pretty(&entries)?),
        KnownHostExportFormat::Csv => Ok(render_known_hosts_csv(&entries)),
    }
}

pub fn export_ssh_config(
    db_path: &Path,
    format: SshConfigExportFormat,
    limit: usize,
) -> Result<String> {
    let entries = db::list_ssh_client_config_entries(db_path, limit)?;
    match format {
        SshConfigExportFormat::Json => Ok(serde_json::to_string_pretty(&entries)?),
        SshConfigExportFormat::Csv => Ok(render_ssh_client_config_csv(&entries)),
    }
}

fn render_risks_ndjson(risks: &[RiskRecord]) -> Result<String> {
    let mut output = String::new();
    for risk in risks {
        let line = serde_json::to_string(risk)?;
        writeln!(output, "{line}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn render_hosts_monitoring_csv(
    hosts: &[HostRecord],
    db_path: &Path,
    limit: usize,
) -> Result<String> {
    let risks = db::list_risks(
        db_path,
        &RiskQuery {
            severity: None,
            code: None,
            limit,
        },
    )?;

    let mut critical_by_host = std::collections::BTreeMap::<i64, usize>::new();
    let mut high_by_host = std::collections::BTreeMap::<i64, usize>::new();
    let mut total_by_host = std::collections::BTreeMap::<i64, usize>::new();

    for risk in &risks {
        let Some(host_id) = risk.host_id else {
            continue;
        };
        *total_by_host.entry(host_id).or_insert(0) += 1;
        match risk.severity.as_str() {
            "CRITICAL" => *critical_by_host.entry(host_id).or_insert(0) += 1,
            "HIGH" => *high_by_host.entry(host_id).or_insert(0) += 1,
            _ => {}
        }
    }

    let mut csv = String::from(
        "hostname,ip_address,port,os_family,os_version,environment,criticality,ssh_open,critical_risks,high_risks,total_risks,user_count\n",
    );
    for host in hosts {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            crate::csv::field(host.hostname.as_deref().unwrap_or("")),
            crate::csv::field(&host.ip_address),
            host.port,
            crate::csv::field(host.os_family.as_deref().unwrap_or("")),
            crate::csv::field(host.os_version.as_deref().unwrap_or("")),
            crate::csv::field(host.environment.as_deref().unwrap_or("")),
            crate::csv::field(host.criticality.as_deref().unwrap_or("")),
            yes_no(host.ssh_open),
            critical_by_host.get(&host.id).copied().unwrap_or(0),
            high_by_host.get(&host.id).copied().unwrap_or(0),
            total_by_host.get(&host.id).copied().unwrap_or(0),
            host.user_count
        )
        .expect("writing to String cannot fail");
    }

    Ok(csv)
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
            crate::csv::field(entry.hostname.as_deref().unwrap_or("")),
            crate::csv::field(entry.ip_address.as_deref().unwrap_or("")),
            crate::csv::field(entry.known_host.as_deref().unwrap_or("")),
            crate::csv::field(entry.known_ip.as_deref().unwrap_or("")),
            crate::csv::field(&entry.host_key_type),
            crate::csv::field(entry.host_key_fingerprint.as_deref().unwrap_or("")),
            yes_no(entry.hashed),
            crate::csv::field(entry.source_file.as_deref().unwrap_or("")),
            entry.line_number.unwrap_or(0),
            crate::csv::field(&entry.confidence)
        )
        .expect("writing to String cannot fail");
    }
    csv
}

fn render_ssh_client_config_csv(entries: &[crate::models::SshClientConfigEntryRecord]) -> String {
    let mut csv = String::from(
        "id,host_id,hostname,ip_address,host_pattern,config_hostname,ssh_user,port,identity_file,proxy_jump,proxy_command,forward_agent,local_forward,remote_forward,dynamic_forward,strict_host_key_checking,include_file,source_file,line_number\n",
    );
    for entry in entries {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            entry.id,
            entry.host_id,
            crate::csv::field(entry.hostname.as_deref().unwrap_or("")),
            crate::csv::field(entry.ip_address.as_deref().unwrap_or("")),
            crate::csv::field(&entry.host_pattern),
            crate::csv::field(entry.config_hostname.as_deref().unwrap_or("")),
            crate::csv::field(entry.ssh_user.as_deref().unwrap_or("")),
            entry.port.unwrap_or(0),
            crate::csv::field(entry.identity_file.as_deref().unwrap_or("")),
            crate::csv::field(entry.proxy_jump.as_deref().unwrap_or("")),
            crate::csv::field(entry.proxy_command.as_deref().unwrap_or("")),
            crate::csv::field(entry.forward_agent.as_deref().unwrap_or("")),
            crate::csv::field(entry.local_forward.as_deref().unwrap_or("")),
            crate::csv::field(entry.remote_forward.as_deref().unwrap_or("")),
            crate::csv::field(entry.dynamic_forward.as_deref().unwrap_or("")),
            crate::csv::field(entry.strict_host_key_checking.as_deref().unwrap_or("")),
            crate::csv::field(entry.include_file.as_deref().unwrap_or("")),
            crate::csv::field(entry.source_file.as_deref().unwrap_or("")),
            entry.line_number.unwrap_or(0)
        )
        .expect("writing to String cannot fail");
    }
    csv
}

pub fn write_output(content: &str, output: Option<&Path>) -> Result<()> {
    match output {
        Some(path) => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, content)?;
            println!("Wrote {}", path.display());
        }
        None => {
            io::stdout().write_all(content.as_bytes())?;
        }
    }
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RiskRecord;

    #[test]
    fn parses_export_formats() {
        assert_eq!(
            RiskExportFormat::parse("ndjson").unwrap(),
            RiskExportFormat::Ndjson
        );
        assert_eq!(
            HostExportFormat::parse("csv").unwrap(),
            HostExportFormat::Csv
        );
    }

    #[test]
    fn renders_ndjson_lines() {
        let risks = vec![RiskRecord {
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
            title: "Root login".to_string(),
            description: None,
            impact: None,
            evidence: None,
            recommendation: None,
            status: "open".to_string(),
            first_seen: "2026-06-11T00:00:00Z".to_string(),
            last_seen: "2026-06-11T00:00:00Z".to_string(),
        }];

        let rendered = render_risks_ndjson(&risks).expect("ndjson");
        assert!(rendered.contains("\"risk_code\":\"SSH_ROOT_LOGIN_ENABLED\""));
        assert!(rendered.ends_with('\n'));
    }
}
