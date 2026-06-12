use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub label: String,
    pub status: String,
}

pub fn run_checks(
    db: Option<&Path>,
    config: Option<&Path>,
    scope: Option<&Path>,
) -> anyhow::Result<Vec<CheckResult>> {
    let mut checks = vec![
        CheckResult {
            label: "ssh binary".to_string(),
            status: binary_availability("ssh"),
        },
        CheckResult {
            label: "ssh-keygen binary".to_string(),
            status: binary_availability("ssh-keygen"),
        },
        CheckResult {
            label: "scan transport openssh".to_string(),
            status: openssh_transport_status(),
        },
        CheckResult {
            label: "scan transport native".to_string(),
            status: native_transport_status(),
        },
        CheckResult {
            label: "scan command manifest".to_string(),
            status: scan_command_manifest_status(),
        },
        openssh_connection_reuse_check(),
        control_socket_directory_check(),
        known_hosts_writability_check(config),
        ssh_agent_check(config),
        CheckResult {
            label: "sqlite storage".to_string(),
            status: "embedded rusqlite (WAL mode)".to_string(),
        },
        template_check("templates/report.html"),
        template_check("templates/report.css"),
    ];

    if let Some(config_path) = config {
        checks.push(config_check(config_path)?);
    }

    if let Some(scope_path) = scope {
        checks.push(scope_check(scope_path));
    }

    if let Some(db_path) = db {
        checks.push(database_check(db_path));
    }

    Ok(checks)
}

pub fn openssh_connection_reuse_check() -> CheckResult {
    CheckResult {
        label: "openssh connection reuse".to_string(),
        status: probe_openssh_multiplexing_support(),
    }
}

pub fn control_socket_directory_check() -> CheckResult {
    CheckResult {
        label: "control socket directory".to_string(),
        status: probe_control_socket_directory(),
    }
}

pub fn known_hosts_writability_check(config_path: Option<&Path>) -> CheckResult {
    let (known_hosts_path, strict_host_key) = resolve_scan_host_key_settings(config_path);
    CheckResult {
        label: format!("known hosts file {}", known_hosts_path.display()),
        status: probe_known_hosts_writability(&known_hosts_path, &strict_host_key),
    }
}

fn resolve_scan_host_key_settings(config_path: Option<&Path>) -> (PathBuf, String) {
    let Some(config_path) = config_path else {
        return (
            crate::transport::resolve_known_hosts_file(None, None),
            "accept-new".to_string(),
        );
    };

    match crate::config::load_optional(Some(config_path)) {
        Ok(config) => {
            let strict_host_key = config
                .scan
                .as_ref()
                .and_then(|scan| scan.strict_host_key_checking.clone())
                .unwrap_or_else(|| "accept-new".to_string());
            let known_hosts_path = crate::transport::resolve_known_hosts_file(
                config
                    .scan
                    .as_ref()
                    .and_then(|scan| scan.known_hosts.as_deref()),
                None,
            );
            (known_hosts_path, strict_host_key)
        }
        Err(_) => (
            crate::transport::resolve_known_hosts_file(None, None),
            "accept-new".to_string(),
        ),
    }
}

pub fn probe_known_hosts_writability(path: &Path, strict_host_key: &str) -> String {
    if matches!(
        strict_host_key.to_ascii_lowercase().as_str(),
        "no" | "off" | "false"
    ) {
        return format!("skipped (strict-host-key {strict_host_key})");
    }

    let parent = path
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if !parent.exists() {
        match std::fs::create_dir_all(parent) {
            Ok(()) => {
                let _ = std::fs::remove_dir(parent);
                return format!("ok (directory can be created at {})", parent.display());
            }
            Err(error) => {
                return format!(
                    "not writable (cannot create {} for accept-new: {error})",
                    parent.display()
                );
            }
        }
    }

    if path.exists() {
        match std::fs::OpenOptions::new().append(true).open(path) {
            Ok(_) => format!("ok (appendable, strict-host-key {strict_host_key})"),
            Err(error) => {
                format!("not writable ({error}; accept-new cannot persist new host keys)")
            }
        }
    } else if parent.is_dir() {
        match write_probe_file(parent) {
            Ok(probe_path) => {
                let _ = std::fs::remove_file(probe_path);
                "ok (missing file, parent writable for accept-new)".to_string()
            }
            Err(error) => format!(
                "not writable ({error}; accept-new cannot create {})",
                path.display()
            ),
        }
    } else {
        format!(
            "not writable (parent {} is not a directory)",
            parent.display()
        )
    }
}

pub fn ssh_agent_check(config_path: Option<&Path>) -> CheckResult {
    let (use_agent, agent_socket) = resolve_scan_agent_settings(config_path);
    CheckResult {
        label: "ssh agent".to_string(),
        status: probe_ssh_agent(use_agent, agent_socket.as_deref()),
    }
}

fn resolve_scan_agent_settings(config_path: Option<&Path>) -> (bool, Option<PathBuf>) {
    let Some(config_path) = config_path else {
        return (false, crate::transport::auth::resolve_agent_socket(None));
    };

    match crate::config::load_optional(Some(config_path)) {
        Ok(config) => {
            let use_agent = config
                .scan
                .as_ref()
                .and_then(|scan| scan.use_agent)
                .unwrap_or(false);
            let agent_socket = config
                .scan
                .as_ref()
                .and_then(|scan| scan.identity_agent.clone())
                .or_else(|| crate::transport::auth::resolve_agent_socket(None));
            (use_agent, agent_socket)
        }
        Err(_) => (false, None),
    }
}

pub fn probe_ssh_agent(use_agent: bool, agent_socket: Option<&Path>) -> String {
    if !use_agent {
        return "skipped (scan.use_agent / --agent not enabled)".to_string();
    }

    #[cfg(unix)]
    {
        let socket_path = agent_socket
            .map(Path::to_path_buf)
            .or_else(|| crate::transport::auth::resolve_agent_socket(None))
            .unwrap_or_else(|| PathBuf::from("$SSH_AUTH_SOCK"));

        match std::os::unix::net::UnixStream::connect(&socket_path) {
            Ok(_) => format!("ok ({})", socket_path.display()),
            Err(error) => format!(
                "unavailable ({}; set --identity-agent or SSH_AUTH_SOCK)",
                error
            ),
        }
    }

    #[cfg(not(unix))]
    {
        let _ = agent_socket;
        "unsupported on this platform".to_string()
    }
}

pub fn parse_openssh_multiplexing_dump(output: &str) -> bool {
    let mut control_master = None;
    let mut control_path = None;

    for line in output.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };

        match key.to_ascii_lowercase().as_str() {
            "controlmaster" => control_master = Some(value),
            "controlpath" => control_path = Some(value),
            _ => {}
        }
    }

    control_master == Some("auto") && control_path.is_some_and(|value| !value.is_empty())
}

fn openssh_transport_status() -> String {
    if binary_exists("ssh") {
        "ok (default; recommended for production scans)".to_string()
    } else {
        "missing (required for --transport openssh)".to_string()
    }
}

fn native_transport_status() -> String {
    "ok (in-process russh via --transport native; requires --key; see SECURITY.md for dependency advisory)"
        .to_string()
}

fn scan_command_manifest_status() -> String {
    match crate::collector::commands::validate_read_only_command_manifest() {
        Ok(()) => "ok".to_string(),
        Err(error) => format!("invalid ({error})"),
    }
}

fn probe_openssh_multiplexing_support() -> String {
    if !binary_exists("ssh") {
        return "skipped (ssh not found)".to_string();
    }

    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPath=sshmap-doctor-%r@%h:%p",
            "-G",
            "localhost",
        ])
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if parse_openssh_multiplexing_dump(&stdout) {
                "ok (ControlMaster auto supported)".to_string()
            } else {
                "unsupported (ssh -G missing ControlMaster directives; use --no-connection-reuse)"
                    .to_string()
            }
        }
        Ok(output) => format!(
            "error (ssh -G failed: {})",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => format!("error ({error})"),
    }
}

fn probe_control_socket_directory() -> String {
    let directory = std::env::temp_dir();
    match write_probe_file(&directory) {
        Ok(path) => {
            let _ = std::fs::remove_file(path);
            format!("ok ({})", directory.display())
        }
        Err(error) => format!(
            "not writable ({}; use --no-connection-reuse or fix permissions)",
            error
        ),
    }
}

fn write_probe_file(directory: &Path) -> Result<PathBuf, String> {
    let path = directory.join(format!(".sshmap-doctor-{}", std::process::id()));
    std::fs::write(&path, b"probe").map_err(|error| error.to_string())?;
    Ok(path)
}

fn config_check(config_path: &Path) -> anyhow::Result<CheckResult> {
    match crate::config::load_optional(Some(config_path)) {
        Ok(config) => {
            let mut status = "ok".to_string();
            if let Some(scan) = config.scan.as_ref() {
                let reuse = crate::config::resolve_connection_reuse(&config, false);
                let transport = scan.transport.as_deref().unwrap_or("openssh");
                let strict_host_key = scan
                    .strict_host_key_checking
                    .as_deref()
                    .unwrap_or("accept-new");
                let known_hosts =
                    crate::transport::resolve_known_hosts_file(scan.known_hosts.as_deref(), None);
                status = if let Some(proxy_jump) = scan.proxy_jump.as_deref() {
                    format!(
                        "ok (transport {transport}, connection reuse {}, strict-host-key {strict_host_key}, known_hosts {}, proxy_jump {proxy_jump}{})",
                        if reuse { "enabled" } else { "disabled" },
                        known_hosts.display(),
                        if scan.use_agent.unwrap_or(false) {
                            ", use_agent enabled"
                        } else {
                            ""
                        }
                    )
                } else {
                    format!(
                        "ok (transport {transport}, connection reuse {}, strict-host-key {strict_host_key}, known_hosts {}{})",
                        if reuse { "enabled" } else { "disabled" },
                        known_hosts.display(),
                        if scan.use_agent.unwrap_or(false) {
                            ", use_agent enabled"
                        } else {
                            ""
                        }
                    )
                };
            }
            Ok(CheckResult {
                label: format!("config {}", config_path.display()),
                status,
            })
        }
        Err(error) => Ok(CheckResult {
            label: format!("config {}", config_path.display()),
            status: format!("error ({error})"),
        }),
    }
}

fn scope_check(scope_path: &Path) -> CheckResult {
    match crate::scope::load_target_endpoints(None, Some(scope_path), "22") {
        Ok(targets) => CheckResult {
            label: format!("scope file {}", scope_path.display()),
            status: format!("ok ({} endpoints on port 22)", targets.len()),
        },
        Err(error) => CheckResult {
            label: format!("scope file {}", scope_path.display()),
            status: format!("error ({error})"),
        },
    }
}

fn database_check(db_path: &Path) -> CheckResult {
    match crate::db::migration_version(db_path) {
        Ok(version) => CheckResult {
            label: format!("database {}", db_path.display()),
            status: format!("ok (schema version {version})"),
        },
        Err(error) => CheckResult {
            label: format!("database {}", db_path.display()),
            status: format!("error ({error})"),
        },
    }
}

fn template_check(path: &str) -> CheckResult {
    let status = if Path::new(path).exists() {
        "ok".to_string()
    } else {
        "missing".to_string()
    };

    CheckResult {
        label: format!("template {path}"),
        status,
    }
}

fn binary_availability(binary_name: &str) -> String {
    if binary_exists(binary_name) {
        "ok".to_string()
    } else {
        "missing".to_string()
    }
}

fn binary_exists(binary_name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };

    std::env::split_paths(&paths).any(|path| {
        let candidate = path.join(binary_name);
        is_executable_file(&candidate)
    })
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_multiplexing_dump() {
        let dump = "host localhost\ncontrolmaster auto\ncontrolpath /tmp/ssh-%r@%h:%p\n";
        assert!(parse_openssh_multiplexing_dump(dump));
    }

    #[test]
    fn rejects_dump_without_control_path() {
        let dump = "host localhost\ncontrolmaster auto\n";
        assert!(!parse_openssh_multiplexing_dump(dump));
    }

    #[test]
    fn rejects_disabled_control_master() {
        let dump = "controlmaster false\ncontrolpath /tmp/ssh-%r@%h:%p\n";
        assert!(!parse_openssh_multiplexing_dump(dump));
    }

    #[test]
    fn scan_command_manifest_is_valid() {
        assert_eq!(scan_command_manifest_status(), "ok");
    }

    #[test]
    fn control_socket_directory_is_writable() {
        assert!(probe_control_socket_directory().starts_with("ok ("));
    }

    #[test]
    fn known_hosts_writability_accepts_missing_file_in_writable_directory() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("known_hosts");

        assert!(probe_known_hosts_writability(&path, "accept-new").starts_with("ok ("));
    }

    #[test]
    fn known_hosts_writability_skips_when_host_key_checks_disabled() {
        let path = Path::new("/tmp/sshmap-known-hosts-doctor");
        assert!(probe_known_hosts_writability(path, "no").contains("skipped"));
    }

    #[test]
    fn known_hosts_writability_reports_existing_file_permissions() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("known_hosts");
        std::fs::write(&path, b"example.com ssh-ed25519 AAAAB3NzaC1yc2E=\n").expect("write file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
            permissions.set_mode(0o444);
            std::fs::set_permissions(&path, permissions).expect("set permissions");

            let status = probe_known_hosts_writability(&path, "accept-new");
            if std::fs::OpenOptions::new().append(true).open(&path).is_ok() {
                assert!(status.starts_with("ok ("));
            } else {
                assert!(status.starts_with("not writable"));
            }
        }

        #[cfg(not(unix))]
        {
            assert!(probe_known_hosts_writability(&path, "accept-new").starts_with("ok ("));
        }
    }
}
