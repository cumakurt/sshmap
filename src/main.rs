mod about;
mod analyzer;
mod baseline;
mod bench;
mod bundle_export;
mod cli;
mod cli_help;
mod cloud_enrich;
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
mod hardening;
mod host_context;
mod host_key_scan;
mod importer;
mod merge;
mod models;
mod output;
mod parser;
mod progress;
mod remediation_export;
mod report;
mod risk;
mod sarif;
mod scope;
mod security;
mod server;
mod ssh_version;
mod target;
mod transport;
mod watch;
mod webhook;

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
    let no_progress = cli.no_progress;
    init_tracing(cli.verbose);
    let app_config = config::load_optional(cli.config.as_deref())?;

    if cli.all {
        if cli.command.is_some() {
            anyhow::bail!("-a/--all cannot be combined with a subcommand");
        }
        cli::print_authorization_notice();
        run_all_quick_workflow(
            &app_config,
            cli.risk_policy.as_deref(),
            AllQuickOptions {
                targets: cli.all_targets.clone(),
                file: cli.all_file.clone(),
                user: cli.all_user.clone(),
                key: cli.all_key.clone(),
                sudo: cli.all_sudo,
                reports_dir: cli.reports_dir.clone(),
                session: cli.session.clone(),
                timeout_seconds: cli.all_timeout,
                concurrency: cli.all_concurrency,
                max_targets: cli.all_max_targets,
                serve_listen: cli.all_serve_listen.clone(),
                show_progress: progress::resolve_show_progress(false, no_progress),
            },
        )
        .await?;
        return Ok(());
    }

    if quick_all_arguments_supplied(&cli) {
        anyhow::bail!("quick workflow target options require -a/--all");
    }

    let Some(command) = cli.command else {
        use clap::CommandFactory;
        let mut command = Cli::command();
        command.print_long_help()?;
        return Ok(());
    };

    match command {
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
                progress::resolve_show_progress(args.progress, no_progress),
            )
            .await?;

            println!("Targets scanned: {}", summary.targets_scanned);
            println!("SSH open: {}", summary.ssh_open);
            println!("Closed or unreachable: {}", summary.closed_or_unreachable);
            println!("Database: {}", db_path.display());
        }
        Command::Scan(args) => {
            cli::print_authorization_notice();
            if args.dry_run {
                run_scan_dry_run(&app_config, &args)?;
            } else {
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
                        progress: progress::resolve_show_progress(args.progress, no_progress),
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
        }
        Command::Workflow { command } => match command {
            cli::WorkflowCommand::Run(args) => {
                cli::print_authorization_notice();
                let iterations = args.repeat_count.max(1);
                for iteration in 0..iterations {
                    if iterations > 1 {
                        println!("Workflow iteration {}/{}", iteration + 1, iterations);
                    }
                    run_workflow_once(
                        &app_config,
                        cli.risk_policy.as_deref(),
                        &args,
                        progress::resolve_show_progress(args.progress, no_progress),
                    )
                    .await?;
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
                show_progress: progress::resolve_show_progress(false, no_progress),
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
                progress::resolve_show_progress(false, no_progress),
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
                            anyhow::bail!(
                                "at least two completed scan runs are required for evidence drift"
                            );
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
                        host.as_ref()
                            .and_then(|detail| detail.host.hostname.clone()),
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
            let sources = args
                .from
                .iter()
                .map(|path| path.as_path())
                .collect::<Vec<_>>();
            let summary = merge::merge_databases(&sources, &args.output)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "Merged {} source databases into {}",
                    summary.source_databases,
                    args.output.display()
                );
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
            security::validate_graph_node_reference(&args.from)?;
            security::validate_graph_node_reference(&args.to)?;
            let Some(start) = db::resolve_graph_node_ref(&args.db, &args.from)? else {
                anyhow::bail!("graph node {} was not found", args.from);
            };
            let Some(end) = db::resolve_graph_node_ref(&args.db, &args.to)? else {
                anyhow::bail!("graph node {} was not found", args.to);
            };
            let slice = db::load_graph_edges_for_analysis(&args.db, args.full_graph)?;
            let mut path = if args.weighted {
                graph::find_weighted_path(&slice.edges, start, end)
            } else {
                graph::find_path(&slice.edges, start, end)
            };
            path.edges_truncated = slice.truncated;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&path)?);
            } else {
                print!("{}", graph::format_path_text(&path));
            }
        }
        Command::Paths(args) => {
            security::validate_graph_node_reference(&args.from)?;
            security::validate_graph_node_reference(&args.to)?;
            let Some(start) = db::resolve_graph_node_ref(&args.db, &args.from)? else {
                anyhow::bail!("graph node {} was not found", args.from);
            };
            let Some(end) = db::resolve_graph_node_ref(&args.db, &args.to)? else {
                anyhow::bail!("graph node {} was not found", args.to);
            };
            let slice = db::load_graph_edges_for_analysis(&args.db, args.full_graph)?;
            let paths =
                graph::find_all_paths(&slice.edges, start, end, args.limit.max(1), slice.truncated);
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
            let slice = db::load_graph_edges_for_analysis(&args.db, args.full_graph)?;
            let mut blast_radius =
                graph::compute_blast_radius(&slice.edges, &entry_points, &args.user);
            blast_radius.edges_truncated = slice.truncated;
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
            let entry_points = db::list_public_key_nodes_by_fingerprint(&args.db, &fingerprint)?;
            if entry_points.is_empty() {
                anyhow::bail!("public key {fingerprint} was not found in the analyzed inventory");
            }
            let slice = db::load_graph_edges_for_analysis(&args.db, args.full_graph)?;
            let mut blast_radius = graph::compute_key_compromise_blast_radius(
                &slice.edges,
                &fingerprint,
                &entry_points,
            );
            blast_radius.edges_truncated = slice.truncated;
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
                ImportCommand::SshAudit(ImportAutoArgs { file, host, db, .. }) => ImportRequest {
                    kind: ImportKind::SshAudit,
                    file,
                    db_path: db,
                    host,
                    username: None,
                    mapping: None,
                },
                ImportCommand::Lynis(ImportAutoArgs { file, host, db, .. }) => ImportRequest {
                    kind: ImportKind::Lynis,
                    file,
                    db_path: db,
                    host,
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
            cli::EnrichCommand::Cloud(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                let summary = cloud_enrich::enrich_from_tags_file(&db_path, &args.file)?;
                println!("Cloud-enriched hosts: {}", summary.imported);
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
            let tokens = server::resolve_api_tokens(
                args.token.or(serve.token),
                args.read_token.or(serve.read_token),
                args.write_token.or(serve.write_token),
            )?;
            server::run_server(server::ServerConfig {
                db_path,
                listen,
                read_only: serve.read_only.unwrap_or(args.read_only),
                allow_write_api: args.allow_write_api || serve.allow_write_api.unwrap_or(false),
                require_token: args.require_token || server::require_token_from_env(),
                read_token: tokens.read_token.clone(),
                write_token: tokens.write_token.clone(),
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
        Command::Watch(args) => {
            let db_path = config::resolve_database(&app_config, &args.db);
            if let Some(url) = &args.webhook_url {
                security::validate_webhook_url(url)?;
            }
            if let Some(name) = &args.baseline {
                security::validate_baseline_name(name, false)?;
            }
            let config = watch::WatchConfig {
                db_path: db_path.clone(),
                interval_seconds: args.interval,
                webhook_url: args.webhook_url.clone(),
                baseline_name: args.baseline.clone(),
            };
            let config_policy_path = config::risk_policy_path(&app_config);
            let policy_path = cli.risk_policy.as_deref().or(config_policy_path.as_deref());
            let policy = risk::load_risk_policy(policy_path)?;
            let show_progress = progress::resolve_show_progress(false, no_progress);
            watch::run_watch(config, move || {
                let db_path = db_path.clone();
                let policy = policy.clone();
                let json = args.json;
                let show_progress = show_progress;
                async move {
                    db::initialize_database(&db_path)?;
                    let summary = analyzer::run_analysis(
                        &db_path,
                        models::AnalyzeScope::All,
                        &policy,
                        false,
                        show_progress,
                    )?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&summary)?);
                    } else {
                        println!(
                            "Watch cycle: {} risks across {} evidence items",
                            summary.risks, summary.raw_evidence_items
                        );
                    }
                    Ok(())
                }
            })
            .await?;
        }
        Command::Hardening { command } => match command {
            cli::HardeningCommand::Report(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let hosts = db::list_hosts(&db_path, 10_000)?;
                let risks = db::list_risks(
                    &db_path,
                    &models::RiskQuery {
                        severity: None,
                        code: None,
                        limit: 10_000,
                    },
                )?;
                let report = hardening::build_hardening_report(&hosts, &risks);
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!(
                        "Hardening summary: {} controls, buckets {:?}",
                        report.control_count, report.summary
                    );
                    for score in report.hosts {
                        println!(
                            "{} ({}) score={} risks={}",
                            score.hostname.as_deref().unwrap_or("-"),
                            score.ip_address,
                            score.score,
                            score.risk_count
                        );
                    }
                }
            }
        },
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
            cli::ExportCommand::Sarif(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let risks = db::list_risks(
                    &db_path,
                    &models::RiskQuery {
                        severity: None,
                        code: None,
                        limit: args.limit,
                    },
                )?;
                let content = sarif::export_risks_sarif(&risks, env!("CARGO_PKG_VERSION"));
                export::write_output(&content, args.output.as_deref())?;
            }
            cli::ExportCommand::Remediation(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                db::initialize_database(&db_path)?;
                let risks = db::list_risks(
                    &db_path,
                    &models::RiskQuery {
                        severity: None,
                        code: None,
                        limit: args.limit,
                    },
                )?;
                let format = remediation_export::RemediationExportFormat::parse(&args.format)?;
                let content = remediation_export::export_remediation(&risks, format);
                export::write_output(&content, args.output.as_deref())?;
            }
            cli::ExportCommand::Bundle(args) => {
                let db_path = config::resolve_database(&app_config, &args.db);
                let output =
                    bundle_export::export_evidence_bundle(bundle_export::EvidenceBundleOptions {
                        db_path: &db_path,
                        output: &args.output,
                        host: args.host.as_deref(),
                        include_raw_evidence: args.include_raw_evidence,
                    })?;
                println!("Wrote {}", output.display());
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

fn run_scan_dry_run(app_config: &config::SshMapConfig, args: &cli::ScanArgs) -> Result<()> {
    let scan = config::scan_config(app_config);
    let runtime = config::runtime_config(app_config);
    let ports = scan
        .ports
        .as_ref()
        .map(|ports| config::format_ports(ports))
        .unwrap_or(args.ports.clone());
    let max_targets = config::resolve_max_targets(app_config, args.max_targets);
    let targets = scope::enforce_max_targets(
        scope::load_target_endpoints(args.targets.as_deref(), args.file.as_deref(), &ports)?,
        max_targets,
    )?;
    let use_sudo = args.sudo || scan.sudo.unwrap_or(false);
    let commands = collector::commands::default_remote_commands();
    println!("Dry-run scan plan ({} targets)", targets.len());
    for target in targets {
        println!("Target {}:{}", target.host, target.port);
        for command in &commands {
            if let Some(rendered) = command.render(use_sudo) {
                println!("  [{}] {}", command.evidence_type, rendered);
            } else {
                println!("  [{}] skipped (requires --sudo)", command.evidence_type);
            }
        }
    }
    let concurrency = scan
        .concurrency
        .or(runtime.concurrency)
        .unwrap_or(args.concurrency);
    println!("Concurrency: {concurrency}");
    Ok(())
}

struct AllQuickOptions {
    targets: Option<String>,
    file: Option<PathBuf>,
    user: Option<String>,
    key: Option<PathBuf>,
    sudo: bool,
    reports_dir: PathBuf,
    session: Option<String>,
    timeout_seconds: u64,
    concurrency: usize,
    max_targets: Option<usize>,
    serve_listen: String,
    show_progress: bool,
}

struct AllQuickArtifacts {
    session_name: String,
    session_dir: PathBuf,
    db_path: PathBuf,
    written_files: Vec<PathBuf>,
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

fn quick_all_arguments_supplied(cli: &Cli) -> bool {
    cli.all_targets.is_some()
        || cli.all_file.is_some()
        || cli.all_user.is_some()
        || cli.all_key.is_some()
        || cli.all_sudo
        || cli.session.is_some()
        || cli.all_max_targets.is_some()
}

async fn run_all_quick_workflow(
    app_config: &config::SshMapConfig,
    cli_risk_policy: Option<&Path>,
    options: AllQuickOptions,
) -> Result<()> {
    if options.targets.is_none() && options.file.is_none() {
        anyhow::bail!("-a/--all requires -t/--target or -f/--file");
    }

    let session_name = build_quick_session_name(&options);
    let session_dir = options.reports_dir.join(&session_name);
    let db_path = session_dir.join("sshmap.db");
    std::fs::create_dir_all(&session_dir)?;
    db::initialize_database(&db_path)?;

    let scan = config::scan_config(app_config);
    let discover = config::discover_config(app_config);
    let runtime = config::runtime_config(app_config);
    let concurrency = discover
        .concurrency
        .or(scan.concurrency)
        .or(runtime.concurrency)
        .unwrap_or(options.concurrency)
        .max(1);
    let timeout = discover
        .timeout_seconds
        .or(scan.timeout_seconds)
        .or(runtime.timeout_seconds)
        .unwrap_or(options.timeout_seconds)
        .max(1);
    let max_targets = config::resolve_max_targets(app_config, options.max_targets);
    let targets = scope::enforce_max_targets(
        scope::load_target_endpoints(options.targets.as_deref(), options.file.as_deref(), "22")?,
        max_targets,
    )?;

    println!("Quick all session: {session_name}");
    println!("Output directory: {}", session_dir.display());
    println!("Database: {}", db_path.display());
    println!("Targets expanded: {}", targets.len());

    let discovery_summary = discovery::run_discovery(
        targets,
        concurrency,
        std::time::Duration::from_secs(timeout),
        &db_path,
        options.show_progress,
    )
    .await?;
    println!(
        "Discovery complete: {} targets, {} SSH open",
        discovery_summary.targets_scanned, discovery_summary.ssh_open
    );

    let open_hosts = db::list_hosts_with_query(
        &db_path,
        &models::HostQuery {
            ssh_open: Some(true),
            limit: max_targets,
            ..models::HostQuery::default()
        },
    )?;
    let scan_targets = open_hosts
        .iter()
        .filter_map(|host| {
            let port = u16::try_from(host.port).ok()?;
            Some(scope::TargetEndpoint {
                host: host.ip_address.clone(),
                port,
            })
        })
        .collect::<Vec<_>>();

    if scan_targets.is_empty() {
        println!("Authenticated scan skipped: no SSH services were discovered.");
    } else {
        let username = resolve_quick_scan_username(&options, &scan)?;
        let identity_file = options.key.clone().or_else(|| scan.key.clone());
        if let Some(path) = identity_file.as_deref()
            && !path.exists()
        {
            anyhow::bail!("identity file not found: {}", path.display());
        }
        let use_sudo = options.sudo || scan.sudo.unwrap_or(false);
        let auth = transport::ScanAuth {
            identity_file,
            use_agent: scan
                .use_agent
                .unwrap_or_else(|| std::env::var_os("SSH_AUTH_SOCK").is_some()),
            agent_socket: scan.identity_agent.clone(),
            identities_only: false,
        };
        let host_key_policy = config::resolve_strict_host_key_policy(app_config, None, None)?;
        let connection_reuse = config::resolve_connection_reuse(app_config, false);
        let proxy_jump = config::resolve_proxy_jump(app_config, None)?;

        println!(
            "Authenticated OpenSSH scan: {} hosts as {}",
            scan_targets.len(),
            username
        );
        let scan_summary =
            collector::remote::run_remote_scan(collector::remote::RemoteScanRequest {
                targets: scan_targets,
                username,
                auth,
                use_sudo,
                concurrency,
                timeout: std::time::Duration::from_secs(timeout),
                db_path: db_path.clone(),
                show_progress: options.show_progress,
                transport: transport::TransportKind::OpenSsh,
                host_key_policy,
                connection_reuse,
                proxy_jump,
            })
            .await?;
        println!(
            "Authenticated scan complete: {} succeeded, {} failed, {} evidence items",
            scan_summary.hosts_succeeded, scan_summary.hosts_failed, scan_summary.evidence_items
        );
    }

    let config_policy_path = config::risk_policy_path(app_config);
    let policy_path = cli_risk_policy.or(config_policy_path.as_deref());
    let policy = risk::load_risk_policy(policy_path)?;
    let analysis_summary = analyzer::run_analysis(
        &db_path,
        models::AnalyzeScope::All,
        &policy,
        false,
        options.show_progress,
    )?;
    let stats = db::load_detailed_database_stats(&db_path)?;
    println!(
        "Analysis complete: {} risks, {} graph edges",
        analysis_summary.risks, stats.graph_edges
    );

    match enrich::enrich_dns(&db_path, 10_000, true) {
        Ok(summary) => println!("DNS enrichment complete: {} aliases", summary.imported),
        Err(error) => eprintln!("Warning: DNS enrichment skipped: {error}"),
    }

    let baseline = db::create_baseline(&db_path, &session_name)?;
    println!("Baseline created: {}", baseline.name);

    let artifacts = write_all_quick_artifacts(&session_name, &session_dir, &db_path)?;
    println!("Artifacts written:");
    for path in &artifacts.written_files {
        println!("- {}", path.display());
    }

    println!();
    println!("Interactive dashboard command:");
    println!(
        "{} serve --read-only --db {} --listen {}",
        shell_quote(&binary_name()),
        shell_quote_path(&artifacts.db_path),
        shell_quote(&options.serve_listen)
    );
    println!("Session: {}", artifacts.session_name);
    println!("Report directory: {}", artifacts.session_dir.display());

    Ok(())
}

fn resolve_quick_scan_username(
    options: &AllQuickOptions,
    scan: &config::ScanConfig,
) -> Result<String> {
    let username = options
        .user
        .clone()
        .or_else(|| scan.user.clone())
        .or_else(current_os_username)
        .ok_or_else(|| anyhow::anyhow!("could not determine current OS user; pass --user"))?;
    transport::auth::validate_ssh_username(&username)?;
    Ok(username)
}

fn current_os_username() -> Option<String> {
    std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("USERNAME").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn build_quick_session_name(options: &AllQuickOptions) -> String {
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let source = options
        .session
        .as_deref()
        .or(options.targets.as_deref())
        .or_else(|| {
            options
                .file
                .as_deref()
                .and_then(|path| path.file_stem())
                .and_then(|stem| stem.to_str())
        })
        .unwrap_or("all");
    format!("{timestamp}-{}", sanitize_session_component(source))
}

fn sanitize_session_component(value: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;

    for character in value.chars() {
        let mapped = if character.is_ascii_alphanumeric() {
            Some(character.to_ascii_lowercase())
        } else if matches!(character, '-' | '_' | '.') {
            Some(character)
        } else {
            Some('-')
        };
        let Some(character) = mapped else {
            continue;
        };
        if character == '-' {
            if last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        output.push(character);
        if output.len() >= 64 {
            break;
        }
    }

    let output = output.trim_matches('-').to_string();
    if output.is_empty() {
        "all".to_string()
    } else {
        output
    }
}

fn write_all_quick_artifacts(
    session_name: &str,
    session_dir: &Path,
    db_path: &Path,
) -> Result<AllQuickArtifacts> {
    let mut written_files = vec![db_path.to_path_buf()];
    let report_data = report::build_report(db_path)?;
    write_artifact(
        &session_dir.join("report.html"),
        &report::render_report(&report_data, report::ReportFormat::Html)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("report.json"),
        &report::render_report(&report_data, report::ReportFormat::Json)?,
        &mut written_files,
    )?;

    let csv_dir = session_dir.join("csv");
    for path in report::write_csv_report(&report_data, &csv_dir, db_path)? {
        written_files.push(PathBuf::from(path));
    }

    let edges = db::list_graph_edges(db_path)?;
    write_artifact(
        &session_dir.join("graph.json"),
        &graph::render_graph_export(&edges, graph::GraphExportFormat::Json)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("graph.dot"),
        &graph::render_graph_export(&edges, graph::GraphExportFormat::Dot)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("graph-cytoscape.json"),
        &graph::render_graph_export(&edges, graph::GraphExportFormat::Cytoscape)?,
        &mut written_files,
    )?;

    let risks = db::list_risks(
        db_path,
        &models::RiskQuery {
            severity: None,
            code: None,
            limit: 10_000,
        },
    )?;
    write_artifact(
        &session_dir.join("summary.json"),
        &export::export_summary_json(db_path)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("risks.json"),
        &export::export_risks(
            db_path,
            export::RiskExportFormat::Json,
            &models::RiskQuery {
                severity: None,
                code: None,
                limit: 10_000,
            },
        )?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("risks.ndjson"),
        &export::export_risks(
            db_path,
            export::RiskExportFormat::Ndjson,
            &models::RiskQuery {
                severity: None,
                code: None,
                limit: 10_000,
            },
        )?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("hosts.json"),
        &export::export_hosts(db_path, export::HostExportFormat::Json, 10_000)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("hosts.csv"),
        &export::export_hosts(db_path, export::HostExportFormat::Csv, 10_000)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("known-hosts.json"),
        &export::export_known_hosts(db_path, export::KnownHostExportFormat::Json, 10_000)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("known-hosts.csv"),
        &export::export_known_hosts(db_path, export::KnownHostExportFormat::Csv, 10_000)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("ssh-config.json"),
        &export::export_ssh_config(db_path, export::SshConfigExportFormat::Json, 10_000)?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("ssh-config.csv"),
        &export::export_ssh_config(db_path, export::SshConfigExportFormat::Csv, 10_000)?,
        &mut written_files,
    )?;

    let risk_codes = db::list_active_risk_codes(db_path)?;
    write_artifact(
        &session_dir.join("compliance.json"),
        &serde_json::to_string_pretty(&compliance::build_compliance_report("all", &risk_codes))?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("hardening.json"),
        &serde_json::to_string_pretty(&hardening::build_hardening_report(
            &db::list_hosts(db_path, 10_000)?,
            &risks,
        ))?,
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("risks.sarif.json"),
        &sarif::export_risks_sarif(&risks, env!("CARGO_PKG_VERSION")),
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("remediation.sh"),
        &remediation_export::export_remediation(
            &risks,
            remediation_export::RemediationExportFormat::Shell,
        ),
        &mut written_files,
    )?;
    write_artifact(
        &session_dir.join("remediation.yml"),
        &remediation_export::export_remediation(
            &risks,
            remediation_export::RemediationExportFormat::Ansible,
        ),
        &mut written_files,
    )?;

    let bundle_path =
        bundle_export::export_evidence_bundle(bundle_export::EvidenceBundleOptions {
            db_path,
            output: &session_dir.join("evidence-bundle.zip"),
            host: None,
            include_raw_evidence: true,
        })?;
    written_files.push(bundle_path);

    Ok(AllQuickArtifacts {
        session_name: session_name.to_string(),
        session_dir: session_dir.to_path_buf(),
        db_path: db_path.to_path_buf(),
        written_files,
    })
}

fn write_artifact(path: &Path, content: &str, written_files: &mut Vec<PathBuf>) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    written_files.push(path.to_path_buf());
    Ok(())
}

fn binary_name() -> String {
    std::env::args()
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "sshmap".to_string())
}

fn shell_quote_path(path: &Path) -> String {
    shell_quote(&path.display().to_string())
}

fn shell_quote(value: &str) -> String {
    if value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '/' | '.' | '_' | '-' | ':')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

async fn run_workflow_once(
    app_config: &config::SshMapConfig,
    cli_risk_policy: Option<&Path>,
    args: &cli::WorkflowRunArgs,
    show_progress: bool,
) -> Result<()> {
    let db_path = config::resolve_database(app_config, &args.db);
    db::initialize_database(&db_path)?;
    let phases = progress::PhaseReporter::new("workflow", show_progress);

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

    phases.start("discovery");
    let discovery_summary = discovery::run_discovery(
        targets,
        discover_concurrency,
        std::time::Duration::from_secs(timeout),
        &db_path,
        show_progress,
    )
    .await?;
    phases.done(
        "discovery",
        &format!(
            "{} targets, {} SSH open",
            discovery_summary.targets_scanned, discovery_summary.ssh_open
        ),
    );
    println!(
        "Discovery targets scanned: {}",
        discovery_summary.targets_scanned
    );
    println!("Discovery SSH open: {}", discovery_summary.ssh_open);

    phases.start("scan");
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
            progress: show_progress,
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
    phases.done(
        "scan",
        &format!(
            "{} succeeded, {} evidence items",
            scan_summary.hosts_succeeded, scan_summary.evidence_items
        ),
    );
    println!("Scan targets scanned: {}", scan_summary.targets_scanned);
    println!("Scan hosts succeeded: {}", scan_summary.hosts_succeeded);
    println!("Scan hosts failed: {}", scan_summary.hosts_failed);
    println!("Scan evidence items: {}", scan_summary.evidence_items);

    phases.start("analyze");
    let config_policy_path = config::risk_policy_path(app_config);
    let policy_path = cli_risk_policy.or(config_policy_path.as_deref());
    let policy = risk::load_risk_policy(policy_path)?;
    let analysis_summary = analyzer::run_analysis(
        &db_path,
        models::AnalyzeScope::All,
        &policy,
        false,
        show_progress,
    )?;
    phases.done(
        "analyze",
        &format!("{} risks generated", analysis_summary.risks),
    );
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
        let content =
            security::read_text_file_limited(path, security::MAX_CONFIG_FILE_BYTES, "users file")?;
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
