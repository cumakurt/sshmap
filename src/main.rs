mod about;
mod analyzer;
mod baseline;
mod bench;
mod cli;
mod cli_help;
mod collector;
mod compliance;
mod config;
mod csv;
mod db;
mod discovery;
mod doctor;
mod enrich;
mod error;
mod evidence_drift;
mod exceptions;
mod export;
mod graph;
mod host_context;
mod host_key_scan;
mod importer;
mod merge;
mod models;
mod output;
mod parser;
mod progress;
mod report;
mod risk;
mod scope;
mod server;
mod ssh_version;
mod target;
mod transport;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};
use std::path::{Path, PathBuf};
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
            let summary = run_scan_phase(
                &app_config,
                ScanPhaseOptions {
                    targets: args.targets,
                    file: args.file,
                    user: args.user,
                    users_file: args.users_file,
                    key: args.key,
                    agent: args.agent,
                    identity_agent: args.identity_agent,
                    identities_only: args.identities_only,
                    no_identities_only: args.no_identities_only,
                    sudo: args.sudo,
                    ports: args.ports,
                    concurrency: args.concurrency,
                    timeout: args.timeout,
                    progress: args.progress,
                    max_targets: args.max_targets,
                    transport: args.transport,
                    strict_host_key: args.strict_host_key,
                    known_hosts: args.known_hosts,
                    no_connection_reuse: args.no_connection_reuse,
                    proxy_jump: args.proxy_jump,
                    db: args.db,
                },
            )
            .await?;

            println!("Targets scanned: {}", summary.targets_scanned);
            println!("Hosts succeeded: {}", summary.hosts_succeeded);
            println!("Hosts failed: {}", summary.hosts_failed);
            println!("Evidence items: {}", summary.evidence_items);
        }
        Command::Workflow { command } => match command {
            cli::WorkflowCommand::Run(args) => {
                cli::print_authorization_notice();
                let iterations = args.repeat_count.max(1);
                for iteration in 0..iterations {
                    if iterations > 1 {
                        println!("Workflow iteration {}/{}", iteration + 1, iterations);
                    }
                    run_workflow_once(&app_config, cli.risk_policy.as_deref(), &args).await?;
                    if iteration + 1 < iterations
                        && let Some(seconds) = args.repeat_every_seconds
                    {
                        tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                    }
                }
            }
        },
        Command::ScanRuns { command } => match command {
            cli::ScanRunsCommand::List(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                let runs = db::list_scan_runs(&db_path, args.limit)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&runs)?);
                } else {
                    print!("{}", output::format_scan_run_list_text(&runs));
                }
            }
            cli::ScanRunsCommand::Show(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                let Some(run) = db::get_scan_run(&db_path, &args.id)? else {
                    anyhow::bail!("scan run {} was not found", args.id);
                };
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&run)?);
                } else {
                    print!("{}", output::format_scan_run_detail_text(&run));
                }
            }
        },
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
                println!("Host aliases parsed: {}", summary.host_aliases);
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
            if args.evidence {
                let host_id = if let Some(host) = &args.host {
                    let Some(host_detail) = db::get_host_detail(&args.db, host)? else {
                        anyhow::bail!("host {host} was not found");
                    };
                    Some(host_detail.host.id)
                } else {
                    None
                };
                let (from_run, to_run) = match (args.from_scan_run, args.to_scan_run) {
                    (Some(from), Some(to)) => (from, to),
                    _ => {
                        let runs = db::list_recent_scan_run_ids(&args.db, 2)?;
                        if runs.len() < 2 {
                            anyhow::bail!("at least two completed scan runs are required for evidence drift");
                        }
                        (runs[1], runs[0])
                    }
                };
                let from_evidence =
                    db::load_raw_evidence_for_scan_run(&args.db, from_run, host_id)?;
                let to_evidence = db::load_raw_evidence_for_scan_run(&args.db, to_run, host_id)?;
                let (hostname, ip_address) = if let Some(host_target) = &args.host {
                    let host = db::get_host_detail(&args.db, host_target)?;
                    (
                        host.as_ref().and_then(|detail| detail.host.hostname.clone()),
                        host.map(|detail| detail.host.ip_address),
                    )
                } else {
                    (None, None)
                };
                let map_evidence = |rows: &[(i64, String, String, String)]| {
                    rows.iter()
                        .map(|(_, evidence_type, hash, content)| {
                            (evidence_type.clone(), hash.clone(), content.clone())
                        })
                        .collect::<Vec<_>>()
                };
                let report = evidence_drift::build_evidence_drift_report(
                    host_id.unwrap_or(0),
                    hostname,
                    ip_address,
                    from_run,
                    to_run,
                    &map_evidence(&from_evidence),
                    &map_evidence(&to_evidence),
                );
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", output::format_evidence_drift_text(&report));
                }
            } else {
                let from = args
                    .from
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--from is required for baseline diff"))?;
                let to = args.to.as_deref().unwrap_or("latest");
                let diff = db::diff_baselines(&args.db, from, to)?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&diff)?);
                } else {
                    print!("{}", output::format_baseline_diff_text(&diff));
                }
            }
        }
        Command::Merge(args) => {
            let sources = args.from.iter().map(|path| path.as_path()).collect::<Vec<_>>();
            let summary = merge::merge_databases(&sources, &args.output)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("Merged {} source databases into {}", summary.source_databases, args.output.display());
                println!("Hosts imported: {}", summary.hosts_imported);
                println!("Risks imported: {}", summary.risks_imported);
                println!("Graph edges imported: {}", summary.graph_edges_imported);
            }
        }
        Command::Compliance { command } => match command {
            cli::ComplianceCommand::Report(args) => {
                let risk_codes = db::list_active_risk_codes(&args.db)?;
                let report = compliance::build_compliance_report(&args.framework, &risk_codes);
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", output::format_compliance_report_text(&report));
                }
            }
        },
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
            let path = if args.weighted {
                graph::find_weighted_path(&edges, start, end)
            } else {
                graph::find_path(&edges, start, end)
            };
            if args.json {
                println!("{}", serde_json::to_string_pretty(&path)?);
            } else {
                print!("{}", graph::format_path_text(&path));
            }
        }
        Command::Paths(args) => {
            let Some(start) = db::resolve_graph_node_ref(&args.db, &args.from)? else {
                anyhow::bail!("graph node {} was not found", args.from);
            };
            let Some(end) = db::resolve_graph_node_ref(&args.db, &args.to)? else {
                anyhow::bail!("graph node {} was not found", args.to);
            };
            let edges = db::list_graph_edges_for_analysis(&args.db)?;
            let paths = graph::find_all_paths(&edges, start, end, args.limit.max(1));
            if args.json {
                println!("{}", serde_json::to_string_pretty(&paths)?);
            } else {
                print!("{}", graph::format_paths_text(&paths));
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
        Command::KeyBlastRadius(args) => {
            let fingerprint = args
                .fingerprint
                .strip_prefix("key:")
                .unwrap_or(&args.fingerprint)
                .to_string();
            let entry_points =
                db::list_public_key_nodes_by_fingerprint(&args.db, &fingerprint)?;
            if entry_points.is_empty() {
                anyhow::bail!("public key {fingerprint} was not found in the analyzed inventory");
            }
            let edges = db::list_graph_edges_for_analysis(&args.db)?;
            let blast_radius =
                graph::compute_key_compromise_blast_radius(&edges, &fingerprint, &entry_points);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&blast_radius)?);
            } else {
                print!("{}", graph::format_key_blast_radius_text(&blast_radius));
            }
        }
        Command::Import { command } => {
            use cli::{
                ImportAuthorizedKeysArgs, ImportAutoArgs, ImportBundleArgs, ImportCommand,
                ImportCsvArgs, ImportFileArgs, ImportHostFileArgs,
            };
            use importer::{ImportKind, ImportRequest};

            let request = match command {
                ImportCommand::Auto(ImportAutoArgs {
                    file,
                    host,
                    user,
                    db,
                }) => ImportRequest {
                    kind: ImportKind::Auto,
                    file,
                    db_path: db,
                    host,
                    username: user,
                    mapping: None,
                },
                ImportCommand::Bundle(ImportBundleArgs {
                    dir,
                    host,
                    user,
                    db,
                }) => ImportRequest {
                    kind: ImportKind::Bundle,
                    file: dir,
                    db_path: db,
                    host,
                    username: user,
                    mapping: None,
                },
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
                ImportCommand::HostsFile(ImportFileArgs { file, db }) => ImportRequest {
                    kind: ImportKind::HostsFile,
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
        Command::Enrich { command } => match command {
            cli::EnrichCommand::Dns(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                let summary = enrich::enrich_dns(&db_path, args.limit, args.reverse)?;
                println!("Enriched aliases: {}", summary.imported);
            }
        },
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
                allow_write_api: args.allow_write_api || serve.allow_write_api.unwrap_or(false),
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

struct ScanPhaseOptions {
    targets: Option<String>,
    file: Option<PathBuf>,
    user: Option<String>,
    users_file: Option<PathBuf>,
    key: Option<PathBuf>,
    agent: bool,
    identity_agent: Option<PathBuf>,
    identities_only: bool,
    no_identities_only: bool,
    sudo: bool,
    ports: String,
    concurrency: usize,
    timeout: u64,
    progress: bool,
    max_targets: Option<usize>,
    transport: String,
    strict_host_key: String,
    known_hosts: Option<PathBuf>,
    no_connection_reuse: bool,
    proxy_jump: Option<String>,
    db: PathBuf,
}

async fn run_workflow_once(
    app_config: &config::SshMapConfig,
    cli_risk_policy: Option<&Path>,
    args: &cli::WorkflowRunArgs,
) -> Result<()> {
    let db_path = config::resolve_database(app_config, &args.db);
    db::initialize_database(&db_path)?;

    let discover = config::discover_config(app_config);
    let runtime = config::runtime_config(app_config);
    let ports = discover
        .ports
        .as_ref()
        .map(|ports| config::format_ports(ports))
        .unwrap_or_else(|| args.ports.clone());
    let discover_concurrency = discover
        .concurrency
        .or(runtime.concurrency)
        .unwrap_or(args.discover_concurrency)
        .max(1);
    let timeout = discover
        .timeout_seconds
        .or(runtime.timeout_seconds)
        .unwrap_or(args.timeout);
    let max_targets = config::resolve_max_targets(app_config, args.max_targets);
    let targets = scope::enforce_max_targets(
        scope::load_target_endpoints(args.targets.as_deref(), args.file.as_deref(), &ports)?,
        max_targets,
    )?;

    let discovery_summary = discovery::run_discovery(
        targets,
        discover_concurrency,
        std::time::Duration::from_secs(timeout),
        &db_path,
        args.progress,
    )
    .await?;
    println!(
        "Discovery targets scanned: {}",
        discovery_summary.targets_scanned
    );
    println!("Discovery SSH open: {}", discovery_summary.ssh_open);

    let scan_summary = run_scan_phase(
        app_config,
        ScanPhaseOptions {
            targets: args.targets.clone(),
            file: args.file.clone(),
            user: args.user.clone(),
            users_file: args.users_file.clone(),
            key: args.key.clone(),
            agent: args.agent,
            identity_agent: args.identity_agent.clone(),
            identities_only: args.identities_only,
            no_identities_only: args.no_identities_only,
            sudo: args.sudo,
            ports: args.ports.clone(),
            concurrency: args.scan_concurrency,
            timeout: args.timeout,
            progress: args.progress,
            max_targets: args.max_targets,
            transport: args.transport.clone(),
            strict_host_key: args.strict_host_key.clone(),
            known_hosts: args.known_hosts.clone(),
            no_connection_reuse: args.no_connection_reuse,
            proxy_jump: args.proxy_jump.clone(),
            db: args.db.clone(),
        },
    )
    .await?;
    println!("Scan targets scanned: {}", scan_summary.targets_scanned);
    println!("Scan hosts succeeded: {}", scan_summary.hosts_succeeded);
    println!("Scan hosts failed: {}", scan_summary.hosts_failed);
    println!("Scan evidence items: {}", scan_summary.evidence_items);

    let config_policy_path = config::risk_policy_path(app_config);
    let policy_path = cli_risk_policy.or(config_policy_path.as_deref());
    let policy = risk::load_risk_policy(policy_path)?;
    let analysis_summary =
        analyzer::run_analysis(&db_path, models::AnalyzeScope::All, &policy, false)?;
    println!("Analysis risks generated: {}", analysis_summary.risks);
    println!(
        "Analysis host aliases parsed: {}",
        analysis_summary.host_aliases
    );

    if args.enrich_dns {
        let enrich_summary = enrich::enrich_dns(&db_path, 1000, args.reverse_dns)?;
        println!("DNS aliases enriched: {}", enrich_summary.imported);
    }

    println!("Workflow database: {}", db_path.display());
    Ok(())
}

async fn run_scan_phase(
    app_config: &config::SshMapConfig,
    options: ScanPhaseOptions,
) -> Result<models::RemoteScanSummary> {
    let scan = config::scan_config(app_config);
    let runtime = config::runtime_config(app_config);
    let db_path = config::resolve_database(app_config, &options.db);
    let usernames =
        resolve_scan_usernames(options.user.or(scan.user), options.users_file.as_deref())?;
    let cli_identities_only = if options.identities_only {
        Some(true)
    } else if options.no_identities_only {
        Some(false)
    } else {
        None
    };
    let auth = config::resolve_scan_auth(
        app_config,
        options.key.or(scan.key),
        options.agent,
        options.identity_agent.as_deref(),
        cli_identities_only,
    )?;
    let use_sudo = options.sudo || scan.sudo.unwrap_or(false);
    let ports = scan
        .ports
        .as_ref()
        .map(|ports| config::format_ports(ports))
        .unwrap_or(options.ports);
    let concurrency = scan
        .concurrency
        .or(runtime.concurrency)
        .unwrap_or(options.concurrency)
        .max(1);
    let timeout = scan
        .timeout_seconds
        .or(runtime.timeout_seconds)
        .unwrap_or(options.timeout);
    let max_targets = config::resolve_max_targets(app_config, options.max_targets);
    let transport = config::resolve_scan_transport(app_config, Some(&options.transport))?;
    let host_key_policy = config::resolve_strict_host_key_policy(
        app_config,
        Some(&options.strict_host_key),
        options.known_hosts.as_deref(),
    )?;
    let connection_reuse =
        config::resolve_connection_reuse(app_config, options.no_connection_reuse);
    let proxy_jump = config::resolve_proxy_jump(app_config, options.proxy_jump.as_deref())?;
    db::initialize_database(&db_path)?;
    let targets = scope::enforce_max_targets(
        scope::load_target_endpoints(options.targets.as_deref(), options.file.as_deref(), &ports)?,
        max_targets,
    )?;

    let mut summary = models::RemoteScanSummary {
        targets_scanned: 0,
        hosts_succeeded: 0,
        hosts_failed: 0,
        evidence_items: 0,
    };

    for username in usernames {
        let user_summary =
            collector::remote::run_remote_scan(collector::remote::RemoteScanRequest {
                targets: targets.clone(),
                username,
                auth: auth.clone(),
                use_sudo,
                concurrency,
                timeout: std::time::Duration::from_secs(timeout),
                db_path: db_path.clone(),
                show_progress: options.progress,
                transport,
                host_key_policy: host_key_policy.clone(),
                connection_reuse,
                proxy_jump: proxy_jump.clone(),
            })
            .await?;
        summary.targets_scanned += user_summary.targets_scanned;
        summary.hosts_succeeded += user_summary.hosts_succeeded;
        summary.hosts_failed += user_summary.hosts_failed;
        summary.evidence_items += user_summary.evidence_items;
    }

    Ok(summary)
}

fn resolve_scan_usernames(
    configured_user: Option<String>,
    users_file: Option<&Path>,
) -> Result<Vec<String>> {
    let mut usernames = Vec::new();
    if let Some(username) = configured_user.filter(|value| !value.trim().is_empty()) {
        usernames.push(username);
    }
    if let Some(path) = users_file {
        let content = std::fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!("failed to read users file {}: {error}", path.display())
        })?;
        for line in content.lines() {
            let username = line.split('#').next().unwrap_or("").trim();
            if !username.is_empty() && !usernames.iter().any(|existing| existing == username) {
                usernames.push(username.to_string());
            }
        }
    }
    if usernames.is_empty() {
        anyhow::bail!("scan user is required; set --user, --users-file, or scan.user in config");
    }
    Ok(usernames)
}
