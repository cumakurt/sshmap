use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn offline_import_analyze_and_report_workflow() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("workflow.db");
    let report_path = temp_dir.path().join("report.json");

    let init_output = run_sshmap(&["init", "--db"])
        .arg(&db_path)
        .output()
        .expect("run init");
    assert_success(&init_output);

    let import_sshd_output = run_sshmap(&[
        "import",
        "sshd-config",
        "--file",
        fixture("sshd_config").to_str().expect("fixture path"),
        "--host",
        "web01",
        "--db",
    ])
    .arg(&db_path)
    .output()
    .expect("run import sshd-config");
    assert_success(&import_sshd_output);

    let import_keys_output = run_sshmap(&[
        "import",
        "authorized-keys",
        "--file",
        fixture("authorized_keys").to_str().expect("fixture path"),
        "--host",
        "web01",
        "--user",
        "deploy",
        "--db",
    ])
    .arg(&db_path)
    .output()
    .expect("run import authorized-keys");
    assert_success(&import_keys_output);

    let analyze_output = run_sshmap(&["analyze", "--db"])
        .arg(&db_path)
        .output()
        .expect("run analyze");
    assert_success(&analyze_output);
    let analyze_text = String::from_utf8(analyze_output.stdout).expect("utf8 stdout");
    assert!(analyze_text.contains("Risks generated:"));
    assert!(!analyze_text.contains("Risks generated: 0"));

    let incremental_output = run_sshmap(&["analyze", "--incremental", "--only", "graph", "--db"])
        .arg(&db_path)
        .output()
        .expect("run incremental analyze");
    assert_success(&incremental_output);
    let incremental_text = String::from_utf8(incremental_output.stdout).expect("utf8 stdout");
    assert!(incremental_text.contains("No new evidence since last analysis"));

    let stats_output = run_sshmap(&["db", "stats", "--db"])
        .arg(&db_path)
        .output()
        .expect("run db stats");
    assert_success(&stats_output);
    let stats_text = String::from_utf8(stats_output.stdout).expect("utf8 stdout");
    assert!(stats_text.contains("Hosts: 1"));
    assert!(stats_text.contains("Risks:"));

    let report_output = run_sshmap(&["report", "create", "--format", "json", "--output"])
        .arg(&report_path)
        .arg("--db")
        .arg(&db_path)
        .output()
        .expect("run report create");
    assert_success(&report_output);

    let report_content = fs::read_to_string(&report_path).expect("report file");
    assert!(report_content.contains("\"hosts\""));
    assert!(report_content.contains("\"risks\""));

    let export_path = temp_dir.path().join("summary.json");
    assert_success(
        &run_sshmap(&["export", "summary", "--db"])
            .arg(&db_path)
            .arg("--output")
            .arg(&export_path)
            .output()
            .expect("run export summary"),
    );
    let export_content = fs::read_to_string(&export_path).expect("summary export");
    assert!(export_content.contains("\"stats\""));
    assert!(export_content.contains("\"critical_risks\""));
}

#[test]
fn bench_command_runs_on_seeded_database() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("bench.db");

    let output = run_sshmap(&[
        "bench",
        "--seed",
        "--hosts",
        "5",
        "--iterations",
        "1",
        "--json",
    ])
    .arg("--db")
    .arg(&db_path)
    .output()
    .expect("run bench");
    assert_success(&output);

    let text = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(text.contains("\"timings\""));
    assert!(text.contains("\"analyze\""));
}

#[test]
fn bench_threshold_validation_fails_when_limits_exceeded() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("bench-threshold.db");
    let thresholds_path = temp_dir.path().join("thresholds.json");
    fs::write(
        &thresholds_path,
        r#"{
  "profile": "test",
  "hosts": 5,
  "limits": {
    "analyze": { "max_avg_ms": 0 }
  }
}"#,
    )
    .expect("write thresholds");

    let output = run_sshmap(&[
        "bench",
        "--seed",
        "--hosts",
        "5",
        "--iterations",
        "1",
        "--thresholds",
        thresholds_path.to_str().expect("threshold path"),
    ])
    .arg("--db")
    .arg(&db_path)
    .output()
    .expect("run bench with thresholds");

    assert!(
        !output.status.success(),
        "expected threshold validation failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("benchmark thresholds exceeded"));
}

#[test]
fn bench_trend_validation_fails_when_regressions_exceed_baseline() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("bench-trend.db");
    let baseline_path = temp_dir.path().join("baseline.json");
    fs::write(
        &baseline_path,
        r#"{
  "database": "baseline.db",
  "hosts_seeded": 5,
  "raw_evidence_items": 15,
  "timings": [
    {
      "name": "analyze",
      "iterations": 1,
      "total_ms": 1,
      "avg_ms": 1,
      "min_ms": 1,
      "max_ms": 1
    },
    {
      "name": "report_build",
      "iterations": 1,
      "total_ms": 1,
      "avg_ms": 1,
      "min_ms": 1,
      "max_ms": 1
    },
    {
      "name": "graph_export_dot",
      "iterations": 1,
      "total_ms": 0,
      "avg_ms": 0,
      "min_ms": 0,
      "max_ms": 0
    },
    {
      "name": "incremental_analyze_skip",
      "iterations": 1,
      "total_ms": 0,
      "avg_ms": 0,
      "min_ms": 0,
      "max_ms": 0
    }
  ]
}"#,
    )
    .expect("write baseline");

    let thresholds_path = temp_dir.path().join("thresholds.json");
    fs::write(
        &thresholds_path,
        r#"{
  "profile": "trend-test",
  "hosts": 5,
  "limits": {
    "analyze": { "max_avg_ms": 60000 },
    "report_build": { "max_avg_ms": 60000 },
    "graph_export_dot": { "max_avg_ms": 60000 },
    "incremental_analyze_skip": { "max_avg_ms": 60000 }
  },
  "trend": {
    "baseline": "baseline.json",
    "max_regression_ratio": 1.01,
    "max_regression_ms": 0
  }
}"#,
    )
    .expect("write thresholds");

    let output = run_sshmap(&[
        "bench",
        "--seed",
        "--hosts",
        "5",
        "--iterations",
        "1",
        "--thresholds",
        thresholds_path.to_str().expect("threshold path"),
    ])
    .arg("--db")
    .arg(&db_path)
    .output()
    .expect("run bench with trend thresholds");

    assert!(
        !output.status.success(),
        "expected trend validation failure, stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("benchmark trend regression"));
}

#[test]
fn db_migrate_reports_schema_version() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("migrate.db");

    let init_output = run_sshmap(&["init", "--db"])
        .arg(&db_path)
        .output()
        .expect("run init");
    assert_success(&init_output);

    let output = run_sshmap(&["db", "migrate", "--db"])
        .arg(&db_path)
        .output()
        .expect("run db migrate");
    assert_success(&output);
    let text = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(text.contains("Schema version: 8"));
}

#[test]
fn risk_policy_can_disable_rules() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let db_path = temp_dir.path().join("policy.db");
    let policy_path = fixture("disable-root-login-policy.yaml");

    let init_output = run_sshmap(&["init", "--db"])
        .arg(&db_path)
        .output()
        .expect("run init");
    assert_success(&init_output);

    let import_output = run_sshmap(&[
        "import",
        "sshd-config",
        "--file",
        fixture("sshd_config").to_str().expect("fixture path"),
        "--host",
        "web01",
        "--db",
    ])
    .arg(&db_path)
    .output()
    .expect("run import sshd-config");
    assert_success(&import_output);

    let analyze_output = run_sshmap(&["analyze", "--db"])
        .arg(&db_path)
        .arg("--risk-policy")
        .arg(&policy_path)
        .output()
        .expect("run analyze with policy");
    assert_success(&analyze_output);

    let risks_output = run_sshmap(&["risks", "list", "--json", "--db"])
        .arg(&db_path)
        .output()
        .expect("run risks list");
    assert_success(&risks_output);
    let risks_text = String::from_utf8(risks_output.stdout).expect("utf8 stdout");
    assert!(!risks_text.contains("SSH_ROOT_LOGIN_ENABLED"));
}
