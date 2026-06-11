# Benchmarks

SSHMap includes a built-in benchmark command for local performance checks on analyze, reporting, and graph export paths.

## Basic Usage

Seed a synthetic workload and run the default benchmark suite:

```bash
sshmap bench --seed --db bench.db
```

Return machine-readable timings:

```bash
sshmap bench --seed --hosts 50 --iterations 5 --json --db bench.db
```

## Options

| Flag | Purpose |
|------|---------|
| `--db` | SQLite database path |
| `--hosts` | Host count for synthetic seeding (default 25) |
| `--iterations` | Repeat count per benchmark (default 3) |
| `--seed` | Delete and recreate the database before seeding |
| `--json` | Print JSON output |
| `--thresholds` | Validate results against a JSON threshold profile |
| `--baseline` | Compare results against a previous JSON benchmark report |

If the database already contains raw evidence and `--seed` is not passed, benchmarks run against the existing data.

## CI Regression Profile

GitHub Actions runs a release benchmark job against `benchmarks/ci-thresholds.json` and the committed baseline in `benchmarks/ci-baseline.json`:

```bash
cargo build --release
./target/release/sshmap bench \
  --seed \
  --hosts 25 \
  --iterations 3 \
  --db bench.db \
  --thresholds benchmarks/ci-thresholds.json \
  --json
```

The threshold profile includes:

- **Absolute limits** (`limits.max_avg_ms`) for hard upper bounds
- **Trend limits** (`trend.max_regression_ratio`, `trend.max_regression_ms`) compared to the baseline report

When performance improves intentionally, refresh the baseline:

```bash
./target/release/sshmap bench \
  --seed \
  --hosts 25 \
  --iterations 3 \
  --db /tmp/sshmap-bench.db \
  --json > benchmarks/ci-baseline.json
```

Adjust `max_avg_ms` values in the threshold file when intentional performance changes require new absolute ceilings.

## Measured Operations

| Benchmark | Description |
|-----------|-------------|
| `analyze` | Full analysis pipeline |
| `report_build` | Aggregate report data load |
| `graph_export_dot` | Graph edge export to DOT |
| `incremental_analyze_skip` | Incremental analyze short-circuit after a full run |

## Interpreting Results

Benchmark output reports average, minimum, maximum, and total milliseconds per operation. Use the same host count, iteration count, and hardware when comparing runs over time.

Non-JSON runs print a trend section when a baseline is configured, listing regressions, improvements, and unchanged timings relative to the saved baseline.

Synthetic seed data is intended for regression tracking on a developer machine or CI runner. It does not replace end-to-end timing on production-sized inventories collected through `discover`, `scan`, or import workflows.
