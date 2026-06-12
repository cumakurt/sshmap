use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum AnalyzeOnlyScope {
    /// Parse evidence, generate risks, and rebuild the graph (default)
    #[default]
    All,
    /// Regenerate risk findings only (skip graph rebuild)
    Risks,
    /// Rebuild access graph edges only (skip risk regeneration)
    Graph,
}

#[derive(Debug, Parser)]
#[command(
    name = "sshmap",
    about = "Agentless SSH exposure management and access graph CLI",
    long_about = crate::about::LONG_ABOUT,
    after_help = crate::cli_help::ROOT_AFTER_HELP,
    author = "Cuma Kurt <cumakurt@gmail.com>",
    version,
    arg_required_else_help = true,
    subcommand_help_heading = "COMMANDS",
    disable_help_subcommand = false
)]
pub struct Cli {
    /// Enable verbose logging (RUST_LOG-style diagnostics on stderr)
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// YAML configuration file (scan, discover, serve, and database defaults)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// YAML risk policy file (disable rules or tune severity thresholds)
    #[arg(long, global = true, value_name = "PATH")]
    pub risk_policy: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new SQLite inventory database
    #[command(long_about = crate::cli_help::INIT_LONG)]
    Init(InitArgs),

    /// Validate local runtime requirements before scans
    #[command(long_about = crate::cli_help::DOCTOR_LONG)]
    Doctor(DoctorArgs),

    /// Database statistics and schema migrations
    #[command(long_about = crate::cli_help::DB_LONG)]
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },

    /// TCP SSH discovery without authentication
    #[command(long_about = crate::cli_help::DISCOVER_LONG)]
    Discover(DiscoverArgs),

    /// Authenticated read-only remote evidence collection
    #[command(long_about = crate::cli_help::SCAN_LONG)]
    Scan(ScanArgs),

    /// Run discover, scan, analyze, and optional enrichment as one workflow
    #[command(long_about = crate::cli_help::WORKFLOW_LONG)]
    Workflow {
        #[command(subcommand)]
        command: WorkflowCommand,
    },

    /// List and inspect recorded scan/import runs
    #[command(long_about = crate::cli_help::SCAN_RUNS_LONG)]
    ScanRuns {
        #[command(subcommand)]
        command: ScanRunsCommand,
    },

    /// Read-only audit of the local host (no SSH)
    #[command(long_about = crate::cli_help::LOCAL_SCAN_LONG)]
    LocalScan(LocalScanArgs),

    /// Parse evidence, generate risks, and rebuild the graph
    #[command(long_about = crate::cli_help::ANALYZE_LONG)]
    Analyze(AnalyzeArgs),

    /// List and inspect SSH exposure findings
    #[command(long_about = crate::cli_help::RISKS_LONG)]
    Risks {
        #[command(subcommand)]
        command: RisksCommand,
    },

    /// Browse host inventory and host-scoped details
    #[command(long_about = crate::cli_help::HOST_LONG)]
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },

    /// Browse SSH user identities across hosts
    #[command(long_about = crate::cli_help::USER_LONG)]
    User {
        #[command(subcommand)]
        command: UserCommand,
    },

    /// Browse public keys and key reuse patterns
    #[command(long_about = crate::cli_help::KEYS_LONG)]
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },

    /// Generate HTML, JSON, or CSV assessment reports
    #[command(long_about = crate::cli_help::REPORT_LONG)]
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },

    /// Snapshot current risks for drift tracking
    #[command(long_about = crate::cli_help::BASELINE_LONG)]
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },

    /// Compare baselines, current risks, or raw evidence drift
    #[command(long_about = crate::cli_help::DIFF_LONG)]
    Diff(DiffArgs),

    /// Merge multiple SQLite inventories into one database
    #[command(long_about = "Merge hosts, risks, and graph edges from multiple sshmap.db files.")]
    Merge(MergeArgs),

    /// Compliance framework mapping and reporting
    Compliance {
        #[command(subcommand)]
        command: ComplianceCommand,
    },

    /// Export the SSH access graph
    #[command(long_about = crate::cli_help::GRAPH_LONG)]
    Graph {
        #[command(subcommand)]
        command: GraphCommand,
    },

    /// Find shortest directed path between graph nodes
    #[command(long_about = crate::cli_help::PATH_LONG)]
    Path(PathArgs),

    /// Find multiple directed paths between graph nodes
    #[command(long_about = "Enumerate multiple directed access paths with optional weighted ranking.")]
    Paths(PathsArgs),

    /// Measure lateral reach from a username
    #[command(long_about = crate::cli_help::BLAST_RADIUS_LONG)]
    BlastRadius(BlastRadiusArgs),

    /// Measure compromise reach from a public key fingerprint
    #[command(long_about = "Simulate lateral movement starting from a compromised SSH public key.")]
    KeyBlastRadius(KeyBlastRadiusArgs),

    /// Import inventory or evidence files offline
    #[command(long_about = crate::cli_help::IMPORT_LONG)]
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },

    /// Enrich inventory with resolver-derived metadata
    Enrich {
        #[command(subcommand)]
        command: EnrichCommand,
    },

    /// Read-only REST API and web dashboard
    #[command(long_about = crate::cli_help::SERVE_LONG)]
    Serve(ServeArgs),

    /// Suppress accepted findings during analysis
    #[command(long_about = crate::cli_help::EXCEPTIONS_LONG)]
    Exceptions {
        #[command(subcommand)]
        command: ExceptionsCommand,
    },

    /// Export JSON or CSV slices for automation
    #[command(long_about = crate::cli_help::EXPORT_LONG)]
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },

    /// Performance benchmarks and CI regression checks
    #[command(long_about = crate::cli_help::BENCH_LONG)]
    Bench(BenchArgs),

    /// Generate bash or zsh shell completion scripts
    #[command(long_about = crate::cli_help::COMPLETION_LONG)]
    Completion(CompletionArgs),

    /// Periodic analysis and optional webhook alerting
    #[command(long_about = "Run analyze on an interval and optionally POST summary webhooks.")]
    Watch(WatchArgs),

    /// Host hardening score reporting
    Hardening {
        #[command(subcommand)]
        command: HardeningCommand,
    },
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// SQLite database path to create
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Optional database path to include database-specific checks
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Optional YAML config to validate scan and transport settings
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Optional target scope file to verify readability
    #[arg(long, value_name = "PATH")]
    pub scope: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Print row counts and schema metadata
    Stats(DbStatsArgs),
    /// Apply pending schema migrations
    Migrate(DbMigrateArgs),
}

#[derive(Debug, Args)]
pub struct DbStatsArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    /// Output statistics as JSON instead of plain text
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DbMigrateArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    /// Comma-separated targets: IPs, CIDRs, or hostnames
    #[arg(long, conflicts_with = "file", help = "Inline target list")]
    pub targets: Option<String>,

    /// File with one target per line (comments with # supported)
    #[arg(long, value_name = "PATH", conflicts_with = "targets")]
    pub file: Option<PathBuf>,

    /// Comma-separated TCP ports to probe (default: 22)
    #[arg(long, default_value = "22")]
    pub ports: String,

    /// Maximum concurrent TCP probes
    #[arg(long, default_value_t = 100)]
    pub concurrency: usize,

    /// Per-target TCP timeout in seconds
    #[arg(long, default_value_t = 3)]
    pub timeout: u64,

    /// Print progress while discovery runs
    #[arg(long)]
    pub progress: bool,

    /// Maximum number of expanded targets allowed (safety cap)
    #[arg(long)]
    pub max_targets: Option<usize>,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Comma-separated targets: IPs, CIDRs, or hostnames
    #[arg(long, conflicts_with = "file", help = "Inline target list")]
    pub targets: Option<String>,

    /// File with one target per line
    #[arg(long, value_name = "PATH", conflicts_with = "targets")]
    pub file: Option<PathBuf>,

    /// SSH username for authenticated collection
    #[arg(long, help = "Remote SSH username (required unless set in config)")]
    pub user: Option<String>,

    /// File containing one SSH username per line for multi-perspective scans
    #[arg(long, value_name = "PATH")]
    pub users_file: Option<PathBuf>,

    /// Path to SSH private key used for authentication
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Authenticate with keys loaded in the local SSH agent
    #[arg(long)]
    pub agent: bool,

    /// SSH agent socket path (default: SSH_AUTH_SOCK environment variable)
    #[arg(long, value_name = "PATH")]
    pub identity_agent: Option<PathBuf>,

    /// Restrict authentication to --key only (OpenSSH IdentitiesOnly=yes)
    #[arg(long)]
    pub identities_only: bool,

    /// Allow SSH agent keys in addition to --key when both are configured
    #[arg(long, conflicts_with = "identities_only")]
    pub no_identities_only: bool,

    /// Prefix root-readable commands with non-interactive sudo
    #[arg(long, help = "Use sudo for commands that read protected system files")]
    pub sudo: bool,

    /// Comma-separated SSH ports (default: 22)
    #[arg(long, default_value = "22")]
    pub ports: String,

    /// Maximum concurrent host scans
    #[arg(long, default_value_t = 20)]
    pub concurrency: usize,

    /// Per-host operation timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Print progress while the scan runs
    #[arg(long)]
    pub progress: bool,

    /// Maximum number of expanded targets allowed
    #[arg(long)]
    pub max_targets: Option<usize>,

    /// SSH client backend: openssh (system ssh) or native (in-process russh)
    #[arg(long, default_value = "openssh", value_name = "openssh|native")]
    pub transport: String,

    /// Host key verification policy: yes, no, or accept-new
    #[arg(long, value_name = "yes|no|accept-new", default_value = "accept-new")]
    pub strict_host_key: String,

    /// Known hosts file for strict host key checking
    #[arg(long, value_name = "PATH")]
    pub known_hosts: Option<PathBuf>,

    /// Disable OpenSSH ControlMaster connection reuse (one session per command)
    #[arg(long)]
    pub no_connection_reuse: bool,

    /// Bastion chain for OpenSSH ProxyJump (-J); comma-separated for multiple hops
    #[arg(long, short = 'J', value_name = "HOST")]
    pub proxy_jump: Option<String>,

    /// Print planned remote commands without connecting or writing evidence
    #[arg(long)]
    pub dry_run: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum WorkflowCommand {
    /// Run discover -> scan -> analyze and optional DNS enrichment
    Run(WorkflowRunArgs),
}

#[derive(Debug, Args)]
pub struct WorkflowRunArgs {
    /// Comma-separated targets: IPs, CIDRs, or hostnames
    #[arg(long, conflicts_with = "file", help = "Inline target list")]
    pub targets: Option<String>,

    /// File with one target per line
    #[arg(long, value_name = "PATH", conflicts_with = "targets")]
    pub file: Option<PathBuf>,

    /// SSH username for authenticated collection
    #[arg(long)]
    pub user: Option<String>,

    /// File containing one SSH username per line
    #[arg(long, value_name = "PATH")]
    pub users_file: Option<PathBuf>,

    /// Path to SSH private key used for authentication
    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Authenticate with keys loaded in the local SSH agent
    #[arg(long)]
    pub agent: bool,

    /// SSH agent socket path (default: SSH_AUTH_SOCK environment variable)
    #[arg(long, value_name = "PATH")]
    pub identity_agent: Option<PathBuf>,

    /// Restrict authentication to --key only
    #[arg(long)]
    pub identities_only: bool,

    /// Allow SSH agent keys in addition to --key when both are configured
    #[arg(long, conflicts_with = "identities_only")]
    pub no_identities_only: bool,

    /// Prefix root-readable commands with non-interactive sudo
    #[arg(long)]
    pub sudo: bool,

    /// Comma-separated SSH ports
    #[arg(long, default_value = "22")]
    pub ports: String,

    /// Maximum concurrent TCP probes
    #[arg(long, default_value_t = 100)]
    pub discover_concurrency: usize,

    /// Maximum concurrent host scans
    #[arg(long, default_value_t = 20)]
    pub scan_concurrency: usize,

    /// Per-target timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Print progress while phases run
    #[arg(long)]
    pub progress: bool,

    /// Maximum number of expanded targets allowed
    #[arg(long)]
    pub max_targets: Option<usize>,

    /// SSH client backend: openssh or native
    #[arg(long, default_value = "openssh", value_name = "openssh|native")]
    pub transport: String,

    /// Host key verification policy: yes, no, or accept-new
    #[arg(long, value_name = "yes|no|accept-new", default_value = "accept-new")]
    pub strict_host_key: String,

    /// Known hosts file for strict host key checking
    #[arg(long, value_name = "PATH")]
    pub known_hosts: Option<PathBuf>,

    /// Disable OpenSSH ControlMaster connection reuse
    #[arg(long)]
    pub no_connection_reuse: bool,

    /// Bastion chain for OpenSSH ProxyJump (-J)
    #[arg(long, short = 'J', value_name = "HOST")]
    pub proxy_jump: Option<String>,

    /// Run DNS enrichment after analysis
    #[arg(long)]
    pub enrich_dns: bool,

    /// Include reverse DNS enrichment when --enrich-dns is set
    #[arg(long)]
    pub reverse_dns: bool,

    /// Repeat workflow every N seconds for lightweight scheduled audits
    #[arg(long)]
    pub repeat_every_seconds: Option<u64>,

    /// Number of workflow iterations when --repeat-every-seconds is used
    #[arg(long, default_value_t = 1)]
    pub repeat_count: usize,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ScanRunsCommand {
    /// List scan, discovery, local-scan, and import runs
    List(ScanRunListArgs),
    /// Show one run and its audit events
    Show(ScanRunShowArgs),
}

#[derive(Debug, Args)]
pub struct ScanRunListArgs {
    /// Maximum number of rows to return
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ScanRunShowArgs {
    /// Numeric scan run ID or run UUID
    pub id: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct LocalScanArgs {
    /// Prefix root-readable commands with non-interactive sudo
    #[arg(long, help = "Use sudo for commands that read protected system files")]
    pub sudo: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    /// Limit analysis to risks only, graph only, or both (default: all)
    #[arg(long, value_enum, default_value_t = AnalyzeOnlyScope::All)]
    pub only: AnalyzeOnlyScope,

    /// Skip graph rebuild when no new evidence exists since the last run (use with --only graph)
    #[arg(
        long,
        help = "Skip analysis when no new raw evidence exists (graph scope only)"
    )]
    pub incremental: bool,
}

#[derive(Debug, Subcommand)]
pub enum RisksCommand {
    /// List findings with optional severity or code filters
    List(RiskListArgs),
    /// Show one finding with evidence and remediation text
    Show(RiskShowArgs),
}

#[derive(Debug, Args)]
pub struct RiskListArgs {
    /// Filter by severity: CRITICAL, HIGH, MEDIUM, or LOW
    #[arg(long, value_name = "LEVEL")]
    pub severity: Option<String>,

    /// Filter by exact risk code (e.g. SSH_PASSWORD_AUTH_ENABLED)
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,

    /// Maximum number of rows to return
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    /// Output findings as JSON
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct RiskShowArgs {
    /// Numeric risk ID from risks list
    pub id: i64,

    /// Output finding detail as JSON
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum HostCommand {
    /// List hosts with SSH state and risk counts
    List(InventoryListArgs),
    /// Show one host with users and linked risks
    Show(InventoryShowArgs),
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// List usernames with host and key counts
    List(InventoryListArgs),
    /// Show accounts, keys, sudo rules, and risks for one username
    Show(UserShowArgs),
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// List public keys with usage counts
    List(KeyListArgs),
    /// List keys reused across multiple hosts or users
    Reuse(KeyReuseArgs),
    /// Show key locations and linked risks
    Show(KeyShowArgs),
}

#[derive(Debug, Args)]
pub struct InventoryListArgs {
    /// Maximum number of rows to return
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct InventoryShowArgs {
    /// Host ID, hostname, FQDN, or IP address
    pub target: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct UserShowArgs {
    /// Username to inspect across all hosts
    pub username: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyListArgs {
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyReuseArgs {
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyShowArgs {
    /// Numeric key ID or SHA256 fingerprint (key:SHA256:...)
    pub target: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    /// Write a report file in the selected format
    Create(ReportCreateArgs),
}

#[derive(Debug, Args)]
pub struct ReportCreateArgs {
    /// Output format: json, html, or csv
    #[arg(long, default_value = "html")]
    pub format: String,

    /// Output file path (directory for csv format)
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum BaselineCommand {
    /// Save a named risk snapshot
    Create(BaselineCreateArgs),
    /// List saved baselines
    List(BaselineListArgs),
}

#[derive(Debug, Args)]
pub struct BaselineCreateArgs {
    /// Unique baseline name (e.g. 2026-q1-audit)
    #[arg(long)]
    pub name: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct BaselineListArgs {
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Source baseline name
    #[arg(long, required_unless_present = "evidence")]
    pub from: Option<String>,

    /// Destination baseline name or 'latest' for current risks
    #[arg(long, default_value = "latest", required_unless_present = "evidence")]
    pub to: Option<String>,

    /// Compare raw evidence drift instead of risk baselines
    #[arg(long)]
    pub evidence: bool,

    /// Host ID, hostname, or IP for evidence drift comparison
    #[arg(long, requires = "evidence")]
    pub host: Option<String>,

    /// Source scan run ID for evidence drift
    #[arg(long, requires = "evidence")]
    pub from_scan_run: Option<i64>,

    /// Destination scan run ID for evidence drift
    #[arg(long, requires = "evidence")]
    pub to_scan_run: Option<i64>,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct MergeArgs {
    /// Source SQLite databases to merge
    #[arg(long = "from", value_name = "PATH", required = true)]
    pub from: Vec<PathBuf>,

    /// Output SQLite database path
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ComplianceCommand {
    /// Show CIS/STIG compliance summary for active risks
    Report(ComplianceReportArgs),
}

#[derive(Debug, Args)]
pub struct ComplianceReportArgs {
    /// Framework name: CIS, STIG, or all
    #[arg(long, default_value = "all")]
    pub framework: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum GraphCommand {
    /// Write graph edges to a file
    Export(GraphExportArgs),
}

#[derive(Debug, Args)]
pub struct GraphExportArgs {
    /// Export format: json, dot, or cytoscape
    #[arg(long, default_value = "json")]
    pub format: String,

    /// Output file path
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct PathArgs {
    /// Source graph node (e.g. user:deploy@web01, key:SHA256:...)
    #[arg(long)]
    pub from: String,

    /// Destination graph node (e.g. host:web02)
    #[arg(long)]
    pub to: String,

    /// Use weighted edge costs instead of hop count
    #[arg(long)]
    pub weighted: bool,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct PathsArgs {
    #[arg(long)]
    pub from: String,

    #[arg(long)]
    pub to: String,

    /// Maximum number of paths to return
    #[arg(long, default_value_t = 10)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct BlastRadiusArgs {
    /// Username to measure reach for across all host-local accounts
    #[arg(long)]
    pub user: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyBlastRadiusArgs {
    /// Public key fingerprint (key:SHA256:... or SHA256:...)
    #[arg(long)]
    pub fingerprint: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    /// Auto-detect a supported evidence or inventory file
    Auto(ImportAutoArgs),
    /// Import all supported evidence files under a directory
    Bundle(ImportBundleArgs),
    /// Import hosts from an Ansible INI inventory file
    Ansible(ImportFileArgs),
    /// Import SSH hosts from Nmap XML output
    Nmap(ImportFileArgs),
    /// Import hosts from a CSV file with optional column mapping
    Csv(ImportCsvArgs),
    /// Import known_hosts trust relationships
    KnownHosts(ImportFileArgs),
    /// Import host/IP aliases from an /etc/hosts style file
    HostsFile(ImportFileArgs),
    /// Import SSH client config evidence for a host
    SshConfig(ImportHostFileArgs),
    /// Import sshd_config evidence for a host
    SshdConfig(ImportHostFileArgs),
    /// Import authorized_keys evidence for a user on a host
    AuthorizedKeys(ImportAuthorizedKeysArgs),
    /// Import sudoers evidence for a host
    Sudoers(ImportHostFileArgs),
    /// Import host inventory from a prior SSHMap JSON report
    Json(ImportFileArgs),
    /// Import findings from an ssh-audit JSON report
    SshAudit(ImportAutoArgs),
    /// Import findings from a Lynis dat/report file
    Lynis(ImportAutoArgs),
}

#[derive(Debug, Args)]
pub struct ImportAutoArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Input file to auto-detect and import"
    )]
    pub file: PathBuf,

    /// Target host identifier for host-scoped evidence
    #[arg(long)]
    pub host: Option<String>,

    /// Unix username for authorized_keys files when it cannot be inferred
    #[arg(long)]
    pub user: Option<String>,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportBundleArgs {
    #[arg(long, value_name = "DIR", help = "Directory containing evidence files")]
    pub dir: PathBuf,

    /// Target host identifier for host-scoped evidence
    #[arg(long)]
    pub host: Option<String>,

    /// Unix username fallback for authorized_keys files
    #[arg(long)]
    pub user: Option<String>,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportFileArgs {
    #[arg(long, value_name = "PATH", help = "Input file to import")]
    pub file: PathBuf,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportCsvArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// Optional YAML/JSON column mapping file
    #[arg(long, value_name = "PATH")]
    pub mapping: Option<PathBuf>,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportHostFileArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// Target host identifier (hostname, IP, or bracketed IPv6 with port)
    #[arg(long)]
    pub host: String,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportAuthorizedKeysArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    #[arg(long, help = "Host that owns the authorized_keys file")]
    pub host: String,

    #[arg(long, help = "Unix username for the authorized_keys entry")]
    pub user: String,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum EnrichCommand {
    /// Resolve hostnames and optional reverse DNS into host aliases
    Dns(EnrichDnsArgs),
    /// Apply cloud/CMDB tags from a JSON or YAML mapping file
    Cloud(EnrichCloudArgs),
}

#[derive(Debug, Args)]
pub struct EnrichDnsArgs {
    /// Maximum hostnames/IPs to process
    #[arg(long, default_value_t = 1000)]
    pub limit: usize,

    /// Also attempt reverse lookup through getent hosts
    #[arg(long)]
    pub reverse: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct EnrichCloudArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    /// Socket address to bind (e.g. 127.0.0.1:8080)
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: String,

    /// Open the database with SQLite read-only flags (required)
    #[arg(
        long,
        default_value_t = true,
        help = "Open database read-only (required)"
    )]
    pub read_only: bool,

    /// API token sent via X-SSHMap-Token header (required on non-loopback binds)
    #[arg(long, help = "Require X-SSHMap-Token header for /api/* routes")]
    pub token: Option<String>,

    /// Read-scoped API token (format read:secret or plain secret for read-only access)
    #[arg(long, value_name = "TOKEN")]
    pub read_token: Option<String>,

    /// Write-scoped API token required for POST/DELETE endpoints (format write:secret)
    #[arg(long, value_name = "TOKEN")]
    pub write_token: Option<String>,

    /// Enable write API endpoints for baselines and exceptions (requires --token)
    #[arg(long)]
    pub allow_write_api: bool,

    /// Directory containing a built React dashboard (index.html + assets)
    #[arg(long, value_name = "DIR")]
    pub dashboard: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ExceptionsCommand {
    /// List configured risk exceptions
    List(ExceptionListArgs),
    /// Add an exception to suppress matching findings
    Add(ExceptionAddArgs),
    /// Remove an exception by ID
    Remove(ExceptionRemoveArgs),
}

#[derive(Debug, Args)]
pub struct ExceptionListArgs {
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ExceptionAddArgs {
    /// Risk code to suppress (e.g. SSH_PASSWORD_AUTH_ENABLED)
    #[arg(long, value_name = "CODE")]
    pub code: String,

    /// Human-readable justification for the exception
    #[arg(long)]
    pub reason: String,

    /// Limit exception to a specific host database ID
    #[arg(long)]
    pub host_id: Option<i64>,

    /// Limit exception to a specific username
    #[arg(long)]
    pub username: Option<String>,

    /// Limit exception to a specific public key fingerprint
    #[arg(long, value_name = "SHA256")]
    pub fingerprint: Option<String>,

    /// Optional expiry timestamp in RFC3339 format
    #[arg(long, value_name = "RFC3339")]
    pub expires_at: Option<String>,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ExceptionRemoveArgs {
    /// Exception row ID from exceptions list
    pub id: i64,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct CompletionArgs {
    /// Shell to generate completions for
    #[arg(long, value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    /// Export inventory summary totals as JSON
    Summary(ExportSummaryArgs),
    /// Export risk findings as JSON or NDJSON
    Risks(ExportRisksArgs),
    /// Export host inventory as JSON or CSV
    Hosts(ExportHostsArgs),
    /// Export known_hosts entries as JSON or CSV
    KnownHosts(ExportKnownHostsArgs),
    /// Export SSH client config entries as JSON or CSV
    SshConfig(ExportSshConfigArgs),
    /// Export open risks as SARIF 2.1.0 JSON
    Sarif(ExportSarifArgs),
    /// Export remediation snippets as Ansible or shell
    Remediation(ExportRemediationArgs),
    /// Export an evidence audit bundle (.zip)
    Bundle(ExportBundleArgs),
}

#[derive(Debug, Args)]
pub struct ExportSummaryArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(
        long,
        value_name = "PATH",
        help = "Write JSON to file instead of stdout"
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExportRisksArgs {
    /// Output format: json or ndjson
    #[arg(long, default_value = "json")]
    pub format: String,

    #[arg(long, value_name = "LEVEL")]
    pub severity: Option<String>,

    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,

    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExportHostsArgs {
    #[arg(long, default_value = "csv")]
    pub format: String,

    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExportKnownHostsArgs {
    #[arg(long, default_value = "csv")]
    pub format: String,

    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExportSshConfigArgs {
    #[arg(long, default_value = "csv")]
    pub format: String,

    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, default_value_t = 3600)]
    pub interval: u64,

    #[arg(long, value_name = "URL")]
    pub webhook_url: Option<String>,

    #[arg(long, value_name = "NAME")]
    pub baseline: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum HardeningCommand {
    /// List per-host hardening scores
    Report(HardeningReportArgs),
}

#[derive(Debug, Args)]
pub struct HardeningReportArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExportSarifArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct ExportRemediationArgs {
    #[arg(long, default_value = "ansible")]
    pub format: String,

    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct ExportBundleArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,

    #[arg(long)]
    pub host: Option<String>,

    #[arg(long)]
    pub include_raw_evidence: bool,
}

#[derive(Debug, Args)]
pub struct BenchArgs {
    #[arg(long, default_value = "sshmap.db", help = "SQLite database file path")]
    pub db: PathBuf,

    /// Number of hosts to seed when --seed is used
    #[arg(long, default_value_t = crate::bench::default_host_count())]
    pub hosts: usize,

    /// Repetitions per benchmark operation
    #[arg(long, default_value_t = crate::bench::default_iterations())]
    pub iterations: u32,

    /// Recreate benchmark data before running timings
    #[arg(long)]
    pub seed: bool,

    /// Output timing report as JSON
    #[arg(long)]
    pub json: bool,

    /// JSON file with max timing thresholds for CI validation
    #[arg(long, value_name = "PATH")]
    pub thresholds: Option<PathBuf>,

    /// Prior JSON benchmark report for trend regression comparison
    #[arg(long, value_name = "PATH")]
    pub baseline: Option<PathBuf>,
}

pub fn run_completion(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut command = Cli::command();
    generate(shell, &mut command, "sshmap", &mut std::io::stdout());
}

pub fn analyze_scope(scope: AnalyzeOnlyScope) -> crate::models::AnalyzeScope {
    match scope {
        AnalyzeOnlyScope::All => crate::models::AnalyzeScope::All,
        AnalyzeOnlyScope::Risks => crate::models::AnalyzeScope::Risks,
        AnalyzeOnlyScope::Graph => crate::models::AnalyzeScope::Graph,
    }
}

pub fn print_authorization_notice() {
    use std::sync::Once;
    static NOTICE: Once = Once::new();
    NOTICE.call_once(|| {
        eprintln!(
            "SSHMap must only be used against systems you own or are explicitly authorized to assess."
        );
    });
}

pub fn run_doctor(
    db: Option<&std::path::Path>,
    config: Option<&std::path::Path>,
    scope: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    println!("SSHMap doctor");
    for check in crate::doctor::run_checks(db, config, scope)? {
        println!("{}: {}", check.label, check.status);
    }
    Ok(())
}

#[cfg(test)]
mod cli_help_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn root_help_lists_all_commands() {
        let mut command = Cli::command();
        let help = command.render_help().to_string();
        let long_help = command.render_long_help().to_string();
        for keyword in [
            "discover",
            "scan",
            "analyze",
            "serve",
            "COMMANDS",
            "WORKFLOW",
            "--verbose",
        ] {
            assert!(help.contains(keyword), "missing {keyword} in root help");
        }
        assert!(long_help.contains("Cuma Kurt"));
    }

    #[test]
    fn scan_help_documents_transport_flags() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .expect("scan subcommand")
            .render_help()
            .to_string();
        assert!(help.contains("proxy-jump") || help.contains("proxy_jump"));
        assert!(help.contains("transport"));
        assert!(help.contains("strict-host-key") || help.contains("strict_host_key"));
    }
}
