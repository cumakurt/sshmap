mod about;
mod analyzer;
mod baseline;
mod bench;
mod cli;
mod cli_help;
mod collector;
mod config;
mod db;
mod discovery;
mod doctor;
mod error;
mod exceptions;
mod export;
mod graph;
mod importer;
mod models;
mod output;
mod parser;
mod progress;
mod report;
mod risk;
mod scope;
mod server;
mod target;
mod transport;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().len() == 1 {
        use clap::CommandFactory;
        let mut command = Cli::command();
        command.print_long_help()?;
        return Ok(());
    }

    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let app_config = config::load_optional(cli.config.as_deref())?;

    match cli.command {
        Command::Init(args) => {
            db::initialize_database(&args.db)?;
            println!("Initialized database: {}", args.db.display());
        }
        Command::Doctor(args) => {
            let config_path = args.config.as_deref().or(cli.config.as_deref());
            cli::run_doctor(args.db.as_deref(), config_path, args.scope.as_deref())?;
        }
        Command::Db { command } => match command {
            cli::DbCommand::Stats(args) => {
                let stats = db::load_detailed_database_stats(&args.db)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&stats)?);
                } else {
                    print!("{}", output::format_detailed_database_stats(&stats));
                }
            }
            cli::DbCommand::Migrate(args) => {
                let version = db::migration_version(&args.db)?;
                println!("Database migrated: {}", args.db.display());
                println!("Schema version: {version}");
            }
        },
        Command::Discover(args) => {
            cli::print_authorization_notice();
            let db_path = config::resolve_database(&app_config, &args.db);
            let discover = config::discover_config(&app_config);
            let runtime = config::runtime_config(&app_config);
            let ports = discover
                .ports
                .as_ref()
                .map(|ports| config::format_ports(ports))
                .unwrap_or(args.ports);
            let concurrency = discover
                .concurrency
                .or(runtime.concurrency)
                .unwrap_or(args.concurrency)
                .max(1);
            let timeout = discover
                .timeout_seconds
                .or(runtime.timeout_seconds)
                .unwrap_or(args.timeout);
            let max_targets = config::resolve_max_targets(&app_config, args.max_targets);
            db::initialize_database(&db_path)?;
            let targets = scope::enforce_max_targets(
                scope::load_target_endpoints(
                    args.targets.as_deref(),
                    args.file.as_deref(),
                    &ports,
                )?,
                max_targets,
            )?;

            let summary = discovery::run_discovery(
                targets,
                concurrency,
                std::time::Duration::from_secs(timeout),
                &db_path,
                args.progress,
            )
            .await?;

            println!("Targets scanned: {}", summary.targets_scanned);
            println!("SSH open: {}", summary.ssh_open);
            println!("Closed or unreachable: {}", summary.closed_or_unreachable);
            println!("Database: {}", db_path.display());
        }
        Command::Scan(args) => {
            cli::print_authorization_notice();
            let scan = config::scan_config(&app_config);
            let runtime = config::runtime_config(&app_config);
            let db_path = config::resolve_database(&app_config, &args.db);
            let username = args.user.or(scan.user).ok_or_else(|| {
                anyhow::anyhow!("scan user is required; set --user or scan.user in config")
            })?;
            let cli_identities_only = if args.identities_only {
                Some(true)
            } else if args.no_identities_only {
                Some(false)
            } else {
                None
            };
            let auth = config::resolve_scan_auth(
                &app_config,
                args.key.or(scan.key),
                args.agent,
                args.identity_agent.as_deref(),
                cli_identities_only,
            )?;
            let use_sudo = args.sudo || scan.sudo.unwrap_or(false);
            let ports = scan
                .ports
                .as_ref()
                .map(|ports| config::format_ports(ports))
                .unwrap_or(args.ports);
            let concurrency = scan
                .concurrency
                .or(runtime.concurrency)
                .unwrap_or(args.concurrency)
                .max(1);
            let timeout = scan
                .timeout_seconds
                .or(runtime.timeout_seconds)
                .unwrap_or(args.timeout);
            let max_targets = config::resolve_max_targets(&app_config, args.max_targets);
            let transport = config::resolve_scan_transport(&app_config, Some(&args.transport))?;
            let host_key_policy = config::resolve_strict_host_key_policy(
                &app_config,
                Some(&args.strict_host_key),
                args.known_hosts.as_deref(),
            )?;
            let connection_reuse =
                config::resolve_connection_reuse(&app_config, args.no_connection_reuse);
            let proxy_jump = config::resolve_proxy_jump(&app_config, args.proxy_jump.as_deref())?;
            db::initialize_database(&db_path)?;
            let targets = scope::enforce_max_targets(
                scope::load_target_endpoints(
                    args.targets.as_deref(),
                    args.file.as_deref(),
                    &ports,
                )?,
                max_targets,
            )?;

            let request = collector::remote::RemoteScanRequest {
                targets,
                username,
                auth,
                use_sudo,
                concurrency,
                timeout: std::time::Duration::from_secs(timeout),
                db_path,
                show_progress: args.progress,
                transport,
                host_key_policy,
                connection_reuse,
                proxy_jump,
            };

            let summary = collector::remote::run_remote_scan(request).await?;

            println!("Targets scanned: {}", summary.targets_scanned);
            println!("Hosts succeeded: {}", summary.hosts_succeeded);
            println!("Hosts failed: {}", summary.hosts_failed);
            println!("Evidence items: {}", summary.evidence_items);
        }
        Command::LocalScan(args) => {
            cli::print_authorization_notice();
            db::initialize_database(&args.db)?;
            let summary = collector::local::run_local_scan(collector::local::LocalScanRequest {
                use_sudo: args.sudo,
                db_path: args.db.clone(),
            })?;

            println!("Local host scanned: 1");
            println!("Evidence items: {}", summary.evidence_items);
            println!("Database: {}", args.db.display());
        }
        Command::Analyze(args) => {
            let db_path = config::resolve_database(&app_config, &args.db);
            db::initialize_database(&db_path)?;
            let config_policy_path = config::risk_policy_path(&app_config);
            let policy_path = cli.risk_policy.as_deref().or(config_policy_path.as_deref());
            let policy = risk::load_risk_policy(policy_path)?;
            let summary = analyzer::run_analysis(
                &db_path,
                cli::analyze_scope(args.only),
                &policy,
                args.incremental,
            )?;

            if summary.skipped {
                println!(
                    "No new evidence since last analysis. Risks unchanged: {}",
                    summary.risks
                );
            } else {
                println!("Raw evidence items: {}", summary.raw_evidence_items);
                println!("Users parsed: {}", summary.users);
                println!("Groups parsed: {}", summary.groups);
                println!("Public keys parsed: {}", summary.public_keys);
                println!("Authorized keys parsed: {}", summary.authorized_keys);
                println!(
                    "SSHD config entries parsed: {}",
                    summary.sshd_config_entries
                );
                println!("Sudo rules parsed: {}", summary.sudo_rules);
                println!(
                    "Known hosts entries parsed: {}",
                    summary.known_hosts_entries
                );
                println!(
                    "SSH client config entries parsed: {}",
                    summary.ssh_client_config_entries
                );
                println!("Risks generated: {}", summary.risks);
            }
        }
        Command::Risks { command } => match command {
            cli::RisksCommand::List(args) => {
                let severity = args
                    .severity
                    .map(|value| value.to_ascii_uppercase())
                    .filter(|value| !value.is_empty());
                if let Some(severity) = &severity {
                    risk::validate_risk_severity(severity)?;
                }
                let query = models::RiskQuery {
                    severity,
                    code: args.code.map(|value| value.to_ascii_uppercase()),
                    limit: args.limit,
                };
                let risks = db::list_risks(&args.db, &query)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&risks)?);
                } else {
                    print!("{}", output::format_risk_list_text(&risks));
                }
            }
            cli::RisksCommand::Show(args) => {
                let Some(risk) = db::get_risk(&args.db, args.id)? else {
                    anyhow::bail!("risk {} was not found", args.id);
                };
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&risk)?);
                } else {
                    print!("{}", output::format_risk_detail_text(&risk));
                }
            }
        },
        Command::Host { command } => match command {
            cli::HostCommand::List(args) => {
                let hosts = db::list_hosts(&args.db, args.limit)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&hosts)?);
                } else {
                    print!("{}", output::format_host_list_text(&hosts));
                }
            }
            cli::HostCommand::Show(args) => {
                let Some(host) = db::get_host_detail(&args.db, &args.target)? else {
                    anyhow::bail!("host {} was not found", args.target);
                };
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&host)?);
                } else {
                    print!("{}", output::format_host_detail_text(&host));
                }
            }
        },
        Command::User { command } => match command {
            cli::UserCommand::List(args) => {
                let users = db::list_user_summaries(&args.db, args.limit)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&users)?);
                } else {
                    print!("{}", output::format_user_list_text(&users));
                }
            }
            cli::UserCommand::Show(args) => {
                let Some(user) = db::get_user_detail(&args.db, &args.username)? else {
                    anyhow::bail!("user {} was not found", args.username);
                };
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&user)?);
                } else {
                    print!("{}", output::format_user_detail_text(&user));
                }
            }
        },
        Command::Keys { command } => match command {
            cli::KeysCommand::List(args) => {
                let keys = db::list_keys(&args.db, args.limit, false)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&keys)?);
                } else {
                    print!("{}", output::format_key_list_text(&keys));
                }
            }
            cli::KeysCommand::Reuse(args) => {
                let keys = db::list_keys(&args.db, args.limit, true)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&keys)?);
                } else {
                    print!("{}", output::format_key_list_text(&keys));
                }
            }
            cli::KeysCommand::Show(args) => {
                let Some(key) = db::get_key_detail(&args.db, &args.target)? else {
                    anyhow::bail!("key {} was not found", args.target);
                };
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&key)?);
                } else {
                    print!("{}", output::format_key_detail_text(&key));
                }
            }
        },
        Command::Report { command } => match command {
            cli::ReportCommand::Create(args) => {
                let report_cfg = config::report_config(&app_config);
                let format_name = if args.format == "html" {
                    report_cfg.default_format.as_deref().unwrap_or(&args.format)
                } else {
                    &args.format
                };
                let format = report::ReportFormat::parse(format_name)?;
                let db_path = config::resolve_database(&app_config, &args.db);
                let report = report::build_report(&db_path)?;
                if format == report::ReportFormat::Csv {
                    let written = report::write_csv_report(&report, &args.output, &db_path)?;
                    println!("CSV report written to {}", args.output.display());
                    for path in written {
                        println!("- {path}");
                    }
                } else {
                    let content = report::render_report(&report, format)?;
                    std::fs::write(&args.output, content)?;
                    println!("Report written: {}", args.output.display());
                }
            }
        },
        Command::Baseline { command } => match command {
            cli::BaselineCommand::Create(args) => {
                let baseline = db::create_baseline(&args.db, &args.name)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&baseline)?);
                } else {
                    print!("{}", output::format_baseline_created_text(&baseline));
                }
            }
            cli::BaselineCommand::List(args) => {
                let baselines = db::list_baselines(&args.db)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&baselines)?);
                } else {
                    print!("{}", output::format_baseline_list_text(&baselines));
                }
            }
        },
        Command::Diff(args) => {
            let diff = db::diff_baselines(&args.db, &args.from, &args.to)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&diff)?);
            } else {
                print!("{}", output::format_baseline_diff_text(&diff));
            }
        }
        Command::Graph { command } => match command {
            cli::GraphCommand::Export(args) => {
                let edges = db::list_graph_edges(&args.db)?;
                let format = graph::GraphExportFormat::parse(&args.format)?;
                let content = graph::render_graph_export(&edges, format)?;
                std::fs::write(&args.output, content)?;
                println!("Graph written: {}", args.output.display());
            }
        },
        Command::Path(args) => {
            let Some(start) = db::resolve_graph_node_ref(&args.db, &args.from)? else {
                anyhow::bail!("graph node {} was not found", args.from);
            };
            let Some(end) = db::resolve_graph_node_ref(&args.db, &args.to)? else {
                anyhow::bail!("graph node {} was not found", args.to);
            };
            let edges = db::list_graph_edges_for_analysis(&args.db)?;
            let path = graph::find_path(&edges, start, end);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&path)?);
            } else {
                print!("{}", graph::format_path_text(&path));
            }
        }
        Command::BlastRadius(args) => {
            let entry_points = db::list_user_nodes_by_username(&args.db, &args.user)?;
            if entry_points.is_empty() {
                anyhow::bail!("user {} was not found in the analyzed inventory", args.user);
            }
            let edges = db::list_graph_edges_for_analysis(&args.db)?;
            let blast_radius = graph::compute_blast_radius(&edges, &entry_points, &args.user);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&blast_radius)?);
            } else {
                print!("{}", graph::format_blast_radius_text(&blast_radius));
            }
        }
        Command::Import { command } => {
            use cli::{
                ImportAuthorizedKeysArgs, ImportCommand, ImportCsvArgs, ImportFileArgs,
                ImportHostFileArgs,
            };
            use importer::{ImportKind, ImportRequest};

            let request = match command {
                ImportCommand::Ansible(ImportFileArgs { file, db }) => ImportRequest {
                    kind: ImportKind::Ansible,
                    file,
                    db_path: db,
                    host: None,
                    username: None,
                    mapping: None,
                },
                ImportCommand::Nmap(ImportFileArgs { file, db }) => ImportRequest {
                    kind: ImportKind::Nmap,
                    file,
                    db_path: db,
                    host: None,
                    username: None,
                    mapping: None,
                },
                ImportCommand::Csv(ImportCsvArgs { file, mapping, db }) => ImportRequest {
                    kind: ImportKind::Csv,
                    file,
                    db_path: db,
                    host: None,
                    username: None,
                    mapping,
                },
                ImportCommand::KnownHosts(ImportFileArgs { file, db }) => ImportRequest {
                    kind: ImportKind::KnownHosts,
                    file,
                    db_path: db,
                    host: None,
                    username: None,
                    mapping: None,
                },
                ImportCommand::SshConfig(ImportHostFileArgs { file, host, db }) => ImportRequest {
                    kind: ImportKind::SshConfig,
                    file,
                    db_path: db,
                    host: Some(host),
                    username: None,
                    mapping: None,
                },
                ImportCommand::SshdConfig(ImportHostFileArgs { file, host, db }) => ImportRequest {
                    kind: ImportKind::SshdConfig,
                    file,
                    db_path: db,
                    host: Some(host),
                    username: None,
                    mapping: None,
                },
                ImportCommand::AuthorizedKeys(ImportAuthorizedKeysArgs {
                    file,
                    host,
                    user,
                    db,
                }) => ImportRequest {
                    kind: ImportKind::AuthorizedKeys,
                    file,
                    db_path: db,
                    host: Some(host),
                    username: Some(user),
                    mapping: None,
                },
                ImportCommand::Sudoers(ImportHostFileArgs { file, host, db }) => ImportRequest {
                    kind: ImportKind::Sudoers,
                    file,
                    db_path: db,
                    host: Some(host),
                    username: None,
                    mapping: None,
                },
                ImportCommand::Json(ImportFileArgs { file, db }) => ImportRequest {
                    kind: ImportKind::Json,
                    file,
                    db_path: db,
                    host: None,
                    username: None,
                    mapping: None,
                },
            };

            db::initialize_database(&request.db_path)?;
            let summary = importer::run_import(request)?;
            println!("Imported records: {}", summary.imported);
        }
        Command::Serve(args) => {
            let serve = config::serve_config(&app_config);
            let db_path = config::resolve_database(&app_config, &args.db);
            let listen = serve
                .listen
                .unwrap_or(args.listen)
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid listen address: {error}"))?;
            let dashboard_dir =
                config::resolve_dashboard_dir(&app_config, args.dashboard.as_deref());
            server::run_server(server::ServerConfig {
                db_path,
                listen,
                read_only: serve.read_only.unwrap_or(args.read_only),
                token: args.token.or(serve.token),
                dashboard_dir,
            })
            .await?;
        }
        Command::Exceptions { command } => match command {
            cli::ExceptionsCommand::List(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                let records = db::list_risk_exceptions(&db_path)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&records)?);
                } else {
                    print!("{}", output::format_exception_list_text(&records));
                }
            }
            cli::ExceptionsCommand::Add(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                let record = db::add_risk_exception(
                    &db_path,
                    &models::NewRiskException {
                        risk_code: args.code.to_ascii_uppercase(),
                        host_id: args.host_id,
                        username: args.username,
                        public_key_fingerprint: args.fingerprint,
                        reason: args.reason,
                        expires_at: args.expires_at,
                    },
                )?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&record)?);
                } else {
                    println!("Added exception {} for {}", record.id, record.risk_code);
                }
            }
            cli::ExceptionsCommand::Remove(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                if db::remove_risk_exception(&db_path, args.id)? {
                    println!("Removed exception {}", args.id);
                } else {
                    anyhow::bail!("exception {} was not found", args.id);
                }
            }
        },
        Command::Bench(args) => {
            let db_path = config::resolve_database(&app_config, &args.db);
            let report = bench::run_benchmarks(bench::BenchmarkRequest {
                db_path,
                hosts: args.hosts,
                iterations: args.iterations,
                seed: args.seed,
            })?;

            let thresholds = if let Some(thresholds_path) = &args.thresholds {
                Some(bench::load_benchmark_thresholds(thresholds_path)?)
            } else {
                None
            };

            if let Some(thresholds) = thresholds.as_ref() {
                bench::validate_benchmark_report(&report, thresholds)?;
            }

            let baseline_path = bench::resolve_baseline_path(
                args.thresholds.as_deref(),
                thresholds.as_ref(),
                args.baseline.as_deref(),
            )?;
            let trend_comparison = if let Some(baseline_path) = baseline_path {
                let baseline = bench::load_benchmark_report(&baseline_path)?;
                let trend_limits = thresholds
                    .as_ref()
                    .and_then(|profile| profile.trend.as_ref())
                    .cloned()
                    .unwrap_or_else(bench::default_trend_limits);
                Some(bench::validate_benchmark_trend(
                    &report,
                    &baseline,
                    &baseline_path,
                    &trend_limits,
                )?)
            } else {
                None
            };

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", bench::format_benchmark_report(&report));
                if let Some(comparison) = trend_comparison.as_ref() {
                    print!("\n{}", bench::format_benchmark_trend_report(comparison));
                }
            }
        }
        Command::Completion(args) => cli::run_completion(args.shell),
        Command::Export { command } => match command {
            cli::ExportCommand::Summary(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let content = export::export_summary_json(&db_path)?;
                export::write_output(&content, args.output.as_deref())?;
            }
            cli::ExportCommand::Risks(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let format = export::RiskExportFormat::parse(&args.format)?;
                let query = models::RiskQuery {
                    severity: args.severity.map(|value| value.to_ascii_uppercase()),
                    code: args.code.map(|value| value.to_ascii_uppercase()),
                    limit: args.limit,
                };
                let content = export::export_risks(&db_path, format, &query)?;
                export::write_output(&content, args.output.as_deref())?;
            }
            cli::ExportCommand::Hosts(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let format = export::HostExportFormat::parse(&args.format)?;
                let content = export::export_hosts(&db_path, format, args.limit)?;
                export::write_output(&content, args.output.as_deref())?;
            }
            cli::ExportCommand::KnownHosts(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let format = export::KnownHostExportFormat::parse(&args.format)?;
                let content = export::export_known_hosts(&db_path, format, args.limit)?;
                export::write_output(&content, args.output.as_deref())?;
            }
            cli::ExportCommand::SshConfig(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let format = export::SshConfigExportFormat::parse(&args.format)?;
                let content = export::export_ssh_config(&db_path, format, args.limit)?;
                export::write_output(&content, args.output.as_deref())?;
            }
        },
    }

    Ok(())
}

fn init_tracing(verbose: bool) {
    let default_filter = if verbose { "sshmap=debug" } else { "warn" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    fmt().with_env_filter(filter).without_time().init();
}
