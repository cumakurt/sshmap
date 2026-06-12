use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

fn sshmap_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sshmap"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run_sshmap(args: &[&str]) -> Command {
    let mut command = Command::new(sshmap_bin());
    command.args(args);
    command
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn seed_analyzed_database(db_path: &std::path::Path) {
    assert_success(
        &run_sshmap(&["init", "--db"])
            .arg(db_path)
            .output()
            .expect("init"),
    );
    assert_success(
        &run_sshmap(&[
            "import",
            "sshd-config",
            "--file",
            fixture("sshd_config").to_str().expect("fixture"),
            "--host",
            "web01",
            "--db",
        ])
        .arg(db_path)
        .output()
        .expect("import sshd"),
    );
    assert_success(
        &run_sshmap(&[
            "import",
            "authorized-keys",
            "--file",
            fixture("authorized_keys").to_str().expect("fixture"),
            "--host",
            "web01",
            "--user",
            "deploy",
            "--db",
        ])
        .arg(db_path)
        .output()
        .expect("import keys"),
    );
    assert_success(
        &run_sshmap(&["analyze", "--db"])
            .arg(db_path)
            .output()
            .expect("analyze"),
    );
}

#[test]
fn core_host_user_key_and_graph_commands() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("core.db");
    seed_analyzed_database(&db_path);

    let hosts = run_sshmap(&["host", "list", "--json", "--db"])
        .arg(&db_path)
        .output()
        .expect("host list");
    assert_success(&hosts);
    assert!(String::from_utf8_lossy(&hosts.stdout).contains("web01"));

    let users = run_sshmap(&["user", "list", "--json", "--db"])
        .arg(&db_path)
        .output()
        .expect("user list");
    assert_success(&users);
    assert!(String::from_utf8_lossy(&users.stdout).contains("deploy"));

    let keys = run_sshmap(&["keys", "list", "--json", "--db"])
        .arg(&db_path)
        .output()
        .expect("keys list");
    assert_success(&keys);

    let graph_export = temp_dir.path().join("graph.json");
    assert_success(
        &run_sshmap(&[
            "graph",
            "export",
            "--format",
            "json",
            "--output",
            graph_export.to_str().expect("graph path"),
            "--db",
        ])
        .arg(&db_path)
        .output()
        .expect("graph export"),
    );
    let graph_content = fs::read_to_string(&graph_export).expect("graph file");
    assert!(graph_content.contains("elements") || graph_content.contains("from_type"));

    assert_success(
        &run_sshmap(&["doctor", "--db"])
            .arg(&db_path)
            .output()
            .expect("doctor"),
    );
}

#[test]
fn rejects_invalid_risk_severity_on_cli() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("severity.db");
    seed_analyzed_database(&db_path);

    let output = run_sshmap(&["risks", "list", "--severity", "URGENT", "--db"])
        .arg(&db_path)
        .output()
        .expect("risks list");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("severity must be one of"));
}

#[test]
fn rejects_invalid_exception_expiry() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("exception.db");
    seed_analyzed_database(&db_path);

    let output = run_sshmap(&[
        "exceptions",
        "add",
        "--code",
        "SSH_PASSWORD_AUTH_ENABLED",
        "--reason",
        "accepted",
        "--expires-at",
        "not-a-date",
        "--db",
    ])
    .arg(&db_path)
    .output()
    .expect("exceptions add");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expires_at"));
}

#[test]
fn rejects_invalid_exception_username_on_cli() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("exception-user.db");
    seed_analyzed_database(&db_path);

    let output = run_sshmap(&[
        "exceptions",
        "add",
        "--code",
        "SSH_PASSWORD_AUTH_ENABLED",
        "--reason",
        "accepted",
        "--username",
        "bad user",
        "--db",
    ])
    .arg(&db_path)
    .output()
    .expect("exceptions add");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("username"));
}

#[test]
fn imports_bracketed_ipv6_host_target() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("ipv6.db");
    assert_success(
        &run_sshmap(&["init", "--db"])
            .arg(&db_path)
            .output()
            .expect("init"),
    );
    assert_success(
        &run_sshmap(&[
            "import",
            "sshd-config",
            "--file",
            fixture("sshd_config").to_str().expect("fixture"),
            "--host",
            "[2001:db8::1]:2222",
            "--db",
        ])
        .arg(&db_path)
        .output()
        .expect("import ipv6 host"),
    );

    let stats = run_sshmap(&["db", "stats", "--json", "--db"])
        .arg(&db_path)
        .output()
        .expect("stats");
    assert_success(&stats);
    assert!(String::from_utf8_lossy(&stats.stdout).contains("\"hosts\": 1"));
}

#[test]
fn serve_api_requires_token_and_returns_summary() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("serve.db");
    seed_analyzed_database(&db_path);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let listen = format!("127.0.0.1:{port}");
    let mut server = Command::new(sshmap_bin())
        .args([
            "serve",
            "--read-only",
            "--listen",
            &listen,
            "--token",
            "smoke-token",
        ])
        .arg("--db")
        .arg(&db_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");

    thread::sleep(Duration::from_millis(750));

    let health = Command::new("curl")
        .args(["-sf", &format!("http://{listen}/health")])
        .output()
        .expect("curl health");
    assert_success(&health);
    assert_eq!(String::from_utf8_lossy(&health.stdout).trim(), "ok");

    let unauthorized = Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("http://{listen}/api/summary"),
        ])
        .output()
        .expect("curl summary without token");
    assert_success(&unauthorized);
    assert_eq!(String::from_utf8_lossy(&unauthorized.stdout), "401");

    let summary = Command::new("curl")
        .args([
            "-sf",
            "-H",
            "X-SSHMap-Token: smoke-token",
            &format!("http://{listen}/api/summary"),
        ])
        .output()
        .expect("curl summary with token");
    assert_success(&summary);
    assert!(String::from_utf8_lossy(&summary.stdout).contains("critical_risks"));

    let _ = server.kill();
    let _ = server.wait();
}

#[test]
fn report_html_and_csv_exports_work() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("report.db");
    seed_analyzed_database(&db_path);

    let html_path = temp_dir.path().join("report.html");
    assert_success(
        &run_sshmap(&[
            "report",
            "create",
            "--format",
            "html",
            "--output",
            html_path.to_str().expect("html path"),
            "--db",
        ])
        .arg(&db_path)
        .output()
        .expect("html report"),
    );
    let html = fs::read_to_string(&html_path).expect("html");
    assert!(html.contains("<html"));

    let csv_dir = temp_dir.path().join("csv");
    fs::create_dir_all(&csv_dir).expect("csv dir");
    assert_success(
        &run_sshmap(&[
            "report",
            "create",
            "--format",
            "csv",
            "--output",
            csv_dir.to_str().expect("csv dir"),
            "--db",
        ])
        .arg(&db_path)
        .output()
        .expect("csv report"),
    );
    assert!(csv_dir.read_dir().expect("csv dir read").next().is_some());
}
