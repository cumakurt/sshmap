pub mod ansible;
pub mod csv;
pub mod evidence;
pub mod hosts_file;
pub mod known_hosts;
pub mod nmap;

use crate::db;
use crate::models::ImportSummary;
use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum ImportKind {
    Auto,
    Bundle,
    Ansible,
    Nmap,
    Csv,
    KnownHosts,
    HostsFile,
    SshConfig,
    SshdConfig,
    AuthorizedKeys,
    Sudoers,
    Json,
}

pub struct ImportRequest {
    pub kind: ImportKind,
    pub file: PathBuf,
    pub db_path: PathBuf,
    pub host: Option<String>,
    pub username: Option<String>,
    pub mapping: Option<PathBuf>,
}

pub fn run_import(request: ImportRequest) -> Result<ImportSummary> {
    match request.kind {
        ImportKind::Auto => evidence::import_auto(
            &request.file,
            request.host.as_deref(),
            request.username.as_deref(),
            &request.db_path,
        ),
        ImportKind::Bundle => evidence::import_bundle(
            &request.file,
            request.host.as_deref(),
            request.username.as_deref(),
            &request.db_path,
        ),
        ImportKind::Ansible => ansible::import_ansible_inventory(&request.file, &request.db_path),
        ImportKind::Nmap => nmap::import_nmap_xml(&request.file, &request.db_path),
        ImportKind::Csv => {
            csv::import_csv_inventory(&request.file, request.mapping.as_deref(), &request.db_path)
        }
        ImportKind::KnownHosts => known_hosts::import_known_hosts(&request.file, &request.db_path),
        ImportKind::HostsFile => hosts_file::import_hosts_file(&request.file, &request.db_path),
        ImportKind::SshConfig => evidence::import_file_evidence(
            "ssh_config",
            "ssh_config",
            &request.file,
            require_host(&request.host)?,
            None,
            &request.db_path,
        ),
        ImportKind::SshdConfig => evidence::import_file_evidence(
            "sshd_config",
            "sshd_config",
            &request.file,
            require_host(&request.host)?,
            None,
            &request.db_path,
        ),
        ImportKind::AuthorizedKeys => evidence::import_file_evidence(
            "authorized_keys",
            "authorized_keys",
            &request.file,
            require_host(&request.host)?,
            request.username.as_deref(),
            &request.db_path,
        ),
        ImportKind::Sudoers => evidence::import_file_evidence(
            "sudoers",
            "sudoers",
            &request.file,
            require_host(&request.host)?,
            None,
            &request.db_path,
        ),
        ImportKind::Json => evidence::import_json_report(&request.file, &request.db_path),
    }
}

fn require_host(host: &Option<String>) -> Result<&str> {
    host.as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("--host is required for this import type"))
}

pub fn store_hosts(
    path: &Path,
    source: &str,
    hosts: &[crate::models::ImportedHost],
) -> Result<ImportSummary> {
    db::store_imported_hosts(path, source, hosts)
}
