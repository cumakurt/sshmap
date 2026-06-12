use crate::analyzer;
use crate::db;
use crate::graph::{self, GraphExportFormat};
use crate::models::{AnalyzeScope, RawEvidenceRecord};
use crate::report;
use crate::risk::RiskPolicy;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

const DEFAULT_HOST_COUNT: usize = 25;
const DEFAULT_ITERATIONS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkTiming {
    pub name: String,
    pub iterations: u32,
    pub total_ms: u128,
    pub avg_ms: u128,
    pub min_ms: u128,
    pub max_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub database: String,
    pub hosts_seeded: usize,
    pub raw_evidence_items: usize,
    pub timings: Vec<BenchmarkTiming>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkThresholds {
    pub profile: String,
    pub hosts: Option<usize>,
    pub iterations: Option<u32>,
    pub limits: BTreeMap<String, BenchmarkLimit>,
    pub trend: Option<BenchmarkTrendLimits>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkLimit {
    pub max_avg_ms: u128,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BenchmarkTrendLimits {
    pub max_regression_ratio: f64,
    #[serde(default = "default_max_regression_ms")]
    pub max_regression_ms: u128,
    pub baseline: Option<String>,
}

pub fn default_trend_limits() -> BenchmarkTrendLimits {
    BenchmarkTrendLimits {
        max_regression_ratio: 1.25,
        max_regression_ms: default_max_regression_ms(),
        baseline: None,
    }
}

fn default_max_regression_ms() -> u128 {
    100
}

#[derive(Debug, Clone)]
pub struct BenchmarkTrendComparison {
    pub baseline_path: String,
    pub regressions: Vec<BenchmarkTrendDelta>,
    pub improvements: Vec<BenchmarkTrendDelta>,
    pub unchanged: Vec<BenchmarkTrendDelta>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkTrendDelta {
    pub name: String,
    pub baseline_avg_ms: u128,
    pub current_avg_ms: u128,
    pub delta_ms: i128,
    pub delta_ratio: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkRequest {
    pub db_path: std::path::PathBuf,
    pub hosts: usize,
    pub iterations: u32,
    pub seed: bool,
}

pub fn run_benchmarks(request: BenchmarkRequest) -> Result<BenchmarkReport> {
    let host_count = request.hosts.max(1);
    let iterations = request.iterations.max(1);

    if request.seed && request.db_path.exists() {
        std::fs::remove_file(&request.db_path).with_context(|| {
            format!(
                "failed to remove existing benchmark database {}",
                request.db_path.display()
            )
        })?;
    }

    db::initialize_database(&request.db_path)?;
    let hosts_seeded = if request.seed || should_seed_database(&request.db_path)? {
        seed_benchmark_database(&request.db_path, host_count)?
    } else {
        db::load_database_stats(&request.db_path)?.hosts
    };

    let raw_evidence_items = db::load_detailed_database_stats(&request.db_path)?.raw_evidence;
    if raw_evidence_items == 0 {
        bail!("benchmark database has no raw evidence; rerun with --seed or import evidence first");
    }

    let policy = RiskPolicy::default();
    let mut timings = Vec::new();

    timings.push(time_iterations("analyze", iterations, || {
        analyzer::run_analysis(&request.db_path, AnalyzeScope::All, &policy, false, false)
            .map(|_| ())
    })?);

    timings.push(time_iterations("report_build", iterations, || {
        report::build_report(&request.db_path).map(|_| ())
    })?);

    timings.push(time_iterations("graph_export_dot", iterations, || {
        let edges = db::list_graph_edges(&request.db_path)?;
        graph::render_graph_export(&edges, GraphExportFormat::Dot).map(|_| ())
    })?);

    timings.push(time_iterations(
        "incremental_analyze_skip",
        iterations,
        || {
            analyzer::run_analysis(&request.db_path, AnalyzeScope::All, &policy, true, false)
                .map(|_| ())
        },
    )?);

    Ok(BenchmarkReport {
        database: request.db_path.display().to_string(),
        hosts_seeded,
        raw_evidence_items,
        timings,
    })
}

pub fn seed_benchmark_database(path: &Path, host_count: usize) -> Result<usize> {
    db::initialize_database(path)?;

    for index in 0..host_count {
        let host_label = format!("bench-host-{index:04}");
        let ip_address = benchmark_host_ip(index);
        let target = format!("{ip_address}:22");

        db::store_imported_evidence(
            path,
            "bench",
            &target,
            RawEvidenceRecord {
                evidence_type: "sshd_config".to_string(),
                source: "sshd_config".to_string(),
                command: "bench seed".to_string(),
                content: benchmark_sshd_config(index),
                stderr: String::new(),
                exit_code: Some(0),
                redacted: false,
            },
        )?;

        let mut authorized_keys = format!(
            "\n--- SSHMAP_FILE:/home/deploy/.ssh/authorized_keys ---\n{}",
            benchmark_authorized_key(index)
        );
        if index.is_multiple_of(7) {
            authorized_keys.push('\n');
            authorized_keys.push_str(&benchmark_authorized_key(index + 10_000));
        }

        db::store_imported_evidence(
            path,
            "bench",
            &target,
            RawEvidenceRecord {
                evidence_type: "authorized_keys".to_string(),
                source: "authorized_keys".to_string(),
                command: "bench seed".to_string(),
                content: authorized_keys,
                stderr: String::new(),
                exit_code: Some(0),
                redacted: false,
            },
        )?;

        db::store_imported_evidence(
            path,
            "bench",
            &target,
            RawEvidenceRecord {
                evidence_type: "passwd".to_string(),
                source: "passwd".to_string(),
                command: "bench seed".to_string(),
                content: benchmark_passwd(&host_label),
                stderr: String::new(),
                exit_code: Some(0),
                redacted: false,
            },
        )?;
    }

    Ok(host_count)
}

pub fn format_benchmark_report(report: &BenchmarkReport) -> String {
    let mut output = String::new();
    output.push_str("SSHMap benchmark report\n");
    output.push_str(&format!("Database: {}\n", report.database));
    output.push_str(&format!("Hosts seeded: {}\n", report.hosts_seeded));
    output.push_str(&format!(
        "Raw evidence items: {}\n\n",
        report.raw_evidence_items
    ));

    for timing in &report.timings {
        output.push_str(&format!(
            "{}: avg {} ms (min {}, max {}, total {}, iterations {})\n",
            timing.name,
            timing.avg_ms,
            timing.min_ms,
            timing.max_ms,
            timing.total_ms,
            timing.iterations
        ));
    }

    output
}

pub fn load_benchmark_thresholds(path: &Path) -> Result<BenchmarkThresholds> {
    let content = crate::security::read_text_file_limited(
        path,
        crate::security::MAX_BENCHMARK_FILE_BYTES,
        "benchmark thresholds",
    )?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse benchmark thresholds {}", path.display()))
}

pub fn load_benchmark_report(path: &Path) -> Result<BenchmarkReport> {
    let content = crate::security::read_text_file_limited(
        path,
        crate::security::MAX_BENCHMARK_FILE_BYTES,
        "benchmark report",
    )?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse benchmark report {}", path.display()))
}

pub fn resolve_baseline_path(
    thresholds_path: Option<&Path>,
    thresholds: Option<&BenchmarkThresholds>,
    cli_baseline: Option<&Path>,
) -> Result<Option<std::path::PathBuf>> {
    if let Some(path) = cli_baseline {
        return Ok(Some(path.to_path_buf()));
    }

    let Some(relative_baseline) = thresholds
        .and_then(|thresholds| thresholds.trend.as_ref())
        .and_then(|trend| trend.baseline.as_deref())
    else {
        return Ok(None);
    };

    let base_dir = thresholds_path
        .and_then(|path| path.parent())
        .unwrap_or_else(|| Path::new("."));

    Ok(Some(base_dir.join(relative_baseline)))
}

pub fn validate_benchmark_report(
    report: &BenchmarkReport,
    thresholds: &BenchmarkThresholds,
) -> Result<()> {
    if let Some(expected_hosts) = thresholds.hosts
        && report.hosts_seeded != expected_hosts
    {
        bail!(
            "benchmark host count {} does not match threshold profile {} (expected {})",
            report.hosts_seeded,
            thresholds.profile,
            expected_hosts
        );
    }

    if let Some(expected_iterations) = thresholds.iterations {
        let actual_iterations = report
            .timings
            .first()
            .map(|timing| timing.iterations)
            .unwrap_or(0);
        if actual_iterations != expected_iterations {
            bail!(
                "benchmark iteration count {} does not match threshold profile {} (expected {})",
                actual_iterations,
                thresholds.profile,
                expected_iterations
            );
        }
    }

    let mut violations = Vec::new();
    for (name, limit) in &thresholds.limits {
        let Some(timing) = report.timings.iter().find(|timing| timing.name == *name) else {
            violations.push(format!("missing benchmark result: {name}"));
            continue;
        };

        if timing.avg_ms > limit.max_avg_ms {
            violations.push(format!(
                "{name}: avg {} ms exceeds max {} ms",
                timing.avg_ms, limit.max_avg_ms
            ));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        bail!(
            "benchmark thresholds exceeded for profile {}:\n- {}",
            thresholds.profile,
            violations.join("\n- ")
        )
    }
}

pub fn compare_benchmark_trend(
    report: &BenchmarkReport,
    baseline: &BenchmarkReport,
    baseline_path: &Path,
) -> BenchmarkTrendComparison {
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut unchanged = Vec::new();

    for timing in &report.timings {
        let Some(baseline_timing) = baseline
            .timings
            .iter()
            .find(|entry| entry.name == timing.name)
        else {
            continue;
        };

        let delta = BenchmarkTrendDelta {
            name: timing.name.clone(),
            baseline_avg_ms: baseline_timing.avg_ms,
            current_avg_ms: timing.avg_ms,
            delta_ms: timing.avg_ms as i128 - baseline_timing.avg_ms as i128,
            delta_ratio: ratio_for(baseline_timing.avg_ms, timing.avg_ms),
        };

        if delta.delta_ms > 0 {
            regressions.push(delta);
        } else if delta.delta_ms < 0 {
            improvements.push(delta);
        } else {
            unchanged.push(delta);
        }
    }

    BenchmarkTrendComparison {
        baseline_path: baseline_path.display().to_string(),
        regressions,
        improvements,
        unchanged,
    }
}

pub fn validate_benchmark_trend(
    report: &BenchmarkReport,
    baseline: &BenchmarkReport,
    baseline_path: &Path,
    limits: &BenchmarkTrendLimits,
) -> Result<BenchmarkTrendComparison> {
    if report.hosts_seeded != baseline.hosts_seeded {
        bail!(
            "benchmark host count {} does not match baseline {} (expected {})",
            report.hosts_seeded,
            baseline_path.display(),
            baseline.hosts_seeded
        );
    }

    let comparison = compare_benchmark_trend(report, baseline, baseline_path);
    let mut violations = Vec::new();

    for delta in &comparison.regressions {
        if exceeds_trend_limit(
            delta.baseline_avg_ms,
            delta.current_avg_ms,
            limits.max_regression_ratio,
            limits.max_regression_ms,
        ) {
            violations.push(format_trend_violation(delta, limits));
        }
    }

    if violations.is_empty() {
        Ok(comparison)
    } else {
        bail!(
            "benchmark trend regression vs {}:\n- {}",
            baseline_path.display(),
            violations.join("\n- ")
        )
    }
}

pub fn format_benchmark_trend_report(comparison: &BenchmarkTrendComparison) -> String {
    let mut output = String::new();
    output.push_str(&format!("Trend baseline: {}\n", comparison.baseline_path));

    append_trend_section(&mut output, "Regressions", &comparison.regressions);
    append_trend_section(&mut output, "Improvements", &comparison.improvements);
    append_trend_section(&mut output, "Unchanged", &comparison.unchanged);

    output
}

fn append_trend_section(output: &mut String, title: &str, deltas: &[BenchmarkTrendDelta]) {
    output.push('\n');
    output.push_str(title);
    output.push_str(":\n");
    if deltas.is_empty() {
        output.push_str("  (none)\n");
        return;
    }

    for delta in deltas {
        output.push_str(&format!(
            "  {}: {} ms -> {} ms ({}{})\n",
            delta.name,
            delta.baseline_avg_ms,
            delta.current_avg_ms,
            format_signed_delta(delta.delta_ms),
            format_optional_ratio(delta.delta_ratio)
        ));
    }
}

fn format_signed_delta(delta_ms: i128) -> String {
    if delta_ms > 0 {
        format!("+{delta_ms} ms")
    } else {
        format!("{delta_ms} ms")
    }
}

fn format_optional_ratio(delta_ratio: Option<f64>) -> String {
    match delta_ratio {
        Some(ratio) => format!(", {ratio:.2}x"),
        None => String::new(),
    }
}

fn exceeds_trend_limit(
    baseline_avg_ms: u128,
    current_avg_ms: u128,
    max_regression_ratio: f64,
    max_regression_ms: u128,
) -> bool {
    if current_avg_ms <= baseline_avg_ms {
        return false;
    }

    if baseline_avg_ms == 0 {
        return current_avg_ms > max_regression_ms;
    }

    let ratio = current_avg_ms as f64 / baseline_avg_ms as f64;
    ratio > max_regression_ratio
        || current_avg_ms.saturating_sub(baseline_avg_ms) > max_regression_ms
}

fn format_trend_violation(delta: &BenchmarkTrendDelta, limits: &BenchmarkTrendLimits) -> String {
    match delta.delta_ratio {
        Some(ratio) => format!(
            "{}: avg {} ms regressed from baseline {} ms ({:.2}x > {:.2}x or +{} ms > +{} ms)",
            delta.name,
            delta.current_avg_ms,
            delta.baseline_avg_ms,
            ratio,
            limits.max_regression_ratio,
            delta.delta_ms,
            limits.max_regression_ms
        ),
        None => format!(
            "{}: avg {} ms regressed from baseline 0 ms (+{} ms > +{} ms)",
            delta.name, delta.current_avg_ms, delta.delta_ms, limits.max_regression_ms
        ),
    }
}

fn ratio_for(baseline_avg_ms: u128, current_avg_ms: u128) -> Option<f64> {
    if baseline_avg_ms == 0 {
        None
    } else {
        Some(current_avg_ms as f64 / baseline_avg_ms as f64)
    }
}

fn should_seed_database(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(true);
    }

    Ok(db::load_detailed_database_stats(path)?.raw_evidence == 0)
}

fn time_iterations<F>(name: &str, iterations: u32, mut operation: F) -> Result<BenchmarkTiming>
where
    F: FnMut() -> Result<()>,
{
    let mut samples = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let started = Instant::now();
        operation()?;
        samples.push(duration_to_ms(started.elapsed()));
    }

    let total_ms = samples.iter().sum::<u128>();
    let min_ms = *samples.iter().min().unwrap_or(&0);
    let max_ms = *samples.iter().max().unwrap_or(&0);
    let avg_ms = total_ms / u128::from(iterations);

    Ok(BenchmarkTiming {
        name: name.to_string(),
        iterations,
        total_ms,
        avg_ms,
        min_ms,
        max_ms,
    })
}

fn duration_to_ms(duration: Duration) -> u128 {
    duration.as_millis()
}

fn benchmark_host_ip(index: usize) -> String {
    let octet = (index % 250) + 1;
    let third_octet = index / 250;
    format!("10.{third_octet}.{octet}")
}

fn benchmark_sshd_config(index: usize) -> String {
    let root_login = if index.is_multiple_of(5) { "yes" } else { "no" };
    format!(
        "PermitRootLogin {root_login}\nPasswordAuthentication yes\nAllowTcpForwarding yes\nPort 22\n"
    )
}

fn benchmark_authorized_key(index: usize) -> String {
    format!("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDhA+example deploy@bench-host-{index:04}")
}

fn benchmark_passwd(host_label: &str) -> String {
    format!(
        "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000:Deploy User:/home/deploy:/bin/bash\nservice:x:999:999:{host_label}:/var/lib/service:/usr/sbin/nologin\n"
    )
}

pub fn default_host_count() -> usize {
    DEFAULT_HOST_COUNT
}

pub fn default_iterations() -> u32 {
    DEFAULT_ITERATIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_expected_host_count() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("bench.db");

        let seeded = seed_benchmark_database(&db_path, 5).expect("seed database");
        assert_eq!(seeded, 5);

        let stats = db::load_detailed_database_stats(&db_path).expect("stats");
        assert_eq!(stats.hosts, 5);
        assert_eq!(stats.raw_evidence, 15);
    }

    #[test]
    fn runs_benchmark_suite_on_seeded_database() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let db_path = temp_dir.path().join("bench-run.db");

        let report = run_benchmarks(BenchmarkRequest {
            db_path: db_path.clone(),
            hosts: 3,
            iterations: 1,
            seed: true,
        })
        .expect("benchmark report");

        assert_eq!(report.hosts_seeded, 3);
        assert_eq!(report.timings.len(), 4);
        assert!(format_benchmark_report(&report).contains("analyze:"));
    }

    #[test]
    fn validates_benchmark_report_against_thresholds() {
        let report = BenchmarkReport {
            database: "bench.db".to_string(),
            hosts_seeded: 25,
            raw_evidence_items: 75,
            timings: vec![BenchmarkTiming {
                name: "analyze".to_string(),
                iterations: 1,
                total_ms: 100,
                avg_ms: 100,
                min_ms: 100,
                max_ms: 100,
            }],
        };
        let thresholds = BenchmarkThresholds {
            profile: "test".to_string(),
            hosts: Some(25),
            iterations: None,
            limits: BTreeMap::from([("analyze".to_string(), BenchmarkLimit { max_avg_ms: 50 })]),
            trend: None,
        };

        let error = validate_benchmark_report(&report, &thresholds).expect_err("threshold");
        assert!(
            error
                .to_string()
                .contains("analyze: avg 100 ms exceeds max 50 ms")
        );
    }

    #[test]
    fn loads_ci_threshold_profile() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/ci-thresholds.json");
        let thresholds = load_benchmark_thresholds(&path).expect("load thresholds");
        assert_eq!(thresholds.profile, "ci-ubuntu-release");
        assert!(thresholds.limits.contains_key("analyze"));
        assert_eq!(
            thresholds
                .trend
                .as_ref()
                .and_then(|trend| trend.baseline.as_deref()),
            Some("ci-baseline.json")
        );
    }

    #[test]
    fn detects_trend_regression_against_baseline() {
        let baseline = BenchmarkReport {
            database: "baseline.db".to_string(),
            hosts_seeded: 25,
            raw_evidence_items: 75,
            timings: vec![BenchmarkTiming {
                name: "analyze".to_string(),
                iterations: 3,
                total_ms: 12,
                avg_ms: 4,
                min_ms: 4,
                max_ms: 4,
            }],
        };
        let report = BenchmarkReport {
            database: "current.db".to_string(),
            hosts_seeded: 25,
            raw_evidence_items: 75,
            timings: vec![BenchmarkTiming {
                name: "analyze".to_string(),
                iterations: 3,
                total_ms: 30,
                avg_ms: 10,
                min_ms: 10,
                max_ms: 10,
            }],
        };
        let limits = BenchmarkTrendLimits {
            max_regression_ratio: 1.25,
            max_regression_ms: 100,
            baseline: None,
        };

        let error =
            validate_benchmark_trend(&report, &baseline, Path::new("baseline.json"), &limits)
                .expect_err("trend regression");
        assert!(error.to_string().contains("benchmark trend regression"));
    }

    #[test]
    fn allows_improvements_without_failing_trend_check() {
        let baseline = BenchmarkReport {
            database: "baseline.db".to_string(),
            hosts_seeded: 25,
            raw_evidence_items: 75,
            timings: vec![BenchmarkTiming {
                name: "analyze".to_string(),
                iterations: 3,
                total_ms: 30,
                avg_ms: 10,
                min_ms: 10,
                max_ms: 10,
            }],
        };
        let report = BenchmarkReport {
            database: "current.db".to_string(),
            hosts_seeded: 25,
            raw_evidence_items: 75,
            timings: vec![BenchmarkTiming {
                name: "analyze".to_string(),
                iterations: 3,
                total_ms: 12,
                avg_ms: 4,
                min_ms: 4,
                max_ms: 4,
            }],
        };
        let limits = default_trend_limits();

        validate_benchmark_trend(&report, &baseline, Path::new("baseline.json"), &limits)
            .expect("improved benchmark should pass trend check");
    }

    #[test]
    fn resolves_baseline_relative_to_thresholds_file() {
        let thresholds_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/ci-thresholds.json");
        let thresholds = load_benchmark_thresholds(&thresholds_path).expect("load thresholds");
        let baseline_path = resolve_baseline_path(Some(&thresholds_path), Some(&thresholds), None)
            .expect("resolve baseline")
            .expect("baseline path");

        assert!(baseline_path.ends_with("benchmarks/ci-baseline.json"));
    }
}
