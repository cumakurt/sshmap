use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum AnalyzeOnlyScope {
    #[default]
    All,
    Risks,
    Graph,
}

#[derive(Debug, Parser)]
#[command(name = "sshmap")]
#[command(about = "Agentless SSH exposure management and access graph CLI")]
#[command(version)]
pub struct Cli {
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[arg(long, global = true, value_name = "PATH")]
    pub risk_policy: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init(InitArgs),
    Doctor(DoctorArgs),
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    Discover(DiscoverArgs),
    Scan(ScanArgs),
    LocalScan(LocalScanArgs),
    Analyze(AnalyzeArgs),
    Risks {
        #[command(subcommand)]
        command: RisksCommand,
    },
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Diff(DiffArgs),
    Graph {
        #[command(subcommand)]
        command: GraphCommand,
    },
    Path(PathArgs),
    BlastRadius(BlastRadiusArgs),
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
    Serve(ServeArgs),
    Exceptions {
        #[command(subcommand)]
        command: ExceptionsCommand,
    },
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    Bench(BenchArgs),
    Completion(CompletionArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub scope: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    Stats(DbStatsArgs),
    Migrate(DbMigrateArgs),
}

#[derive(Debug, Args)]
pub struct DbStatsArgs {
    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DbMigrateArgs {
    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    #[arg(long, conflicts_with = "file")]
    pub targets: Option<String>,

    #[arg(long, value_name = "PATH", conflicts_with = "targets")]
    pub file: Option<PathBuf>,

    #[arg(long, default_value = "22")]
    pub ports: String,

    #[arg(long, default_value_t = 100)]
    pub concurrency: usize,

    #[arg(long, default_value_t = 3)]
    pub timeout: u64,

    #[arg(long)]
    pub progress: bool,

    #[arg(long)]
    pub max_targets: Option<usize>,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[arg(long, conflicts_with = "file")]
    pub targets: Option<String>,

    #[arg(long, value_name = "PATH", conflicts_with = "targets")]
    pub file: Option<PathBuf>,

    #[arg(long)]
    pub user: Option<String>,

    #[arg(long, value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// Authenticate with keys loaded in the local SSH agent.
    #[arg(long)]
    pub agent: bool,

    /// SSH agent socket path (default: SSH_AUTH_SOCK).
    #[arg(long, value_name = "PATH")]
    pub identity_agent: Option<PathBuf>,

    /// Restrict authentication to --key only (OpenSSH IdentitiesOnly=yes).
    #[arg(long)]
    pub identities_only: bool,

    /// Allow SSH agent keys in addition to --key when both are configured.
    #[arg(long, conflicts_with = "identities_only")]
    pub no_identities_only: bool,

    #[arg(long)]
    pub sudo: bool,

    #[arg(long, default_value = "22")]
    pub ports: String,

    #[arg(long, default_value_t = 20)]
    pub concurrency: usize,

    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    #[arg(long)]
    pub progress: bool,

    #[arg(long)]
    pub max_targets: Option<usize>,

    #[arg(long, default_value = "openssh", value_name = "openssh|native")]
    pub transport: String,

    #[arg(long, value_name = "yes|no|accept-new", default_value = "accept-new")]
    pub strict_host_key: String,

    #[arg(long, value_name = "PATH")]
    pub known_hosts: Option<PathBuf>,

    /// Disable OpenSSH ControlMaster connection reuse (one SSH session per command).
    #[arg(long)]
    pub no_connection_reuse: bool,

    /// OpenSSH ProxyJump target (`-J`), comma-separated for multiple hops.
    #[arg(long, short = 'J', value_name = "HOST")]
    pub proxy_jump: Option<String>,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct LocalScanArgs {
    #[arg(long)]
    pub sudo: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,

    #[arg(long, value_enum, default_value_t = AnalyzeOnlyScope::All)]
    pub only: AnalyzeOnlyScope,

    #[arg(long)]
    pub incremental: bool,
}

#[derive(Debug, Subcommand)]
pub enum RisksCommand {
    List(RiskListArgs),
    Show(RiskShowArgs),
}

#[derive(Debug, Args)]
pub struct RiskListArgs {
    #[arg(long)]
    pub severity: Option<String>,

    #[arg(long)]
    pub code: Option<String>,

    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct RiskShowArgs {
    pub id: i64,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum HostCommand {
    List(InventoryListArgs),
    Show(InventoryShowArgs),
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    List(InventoryListArgs),
    Show(UserShowArgs),
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    List(KeyListArgs),
    Reuse(KeyReuseArgs),
    Show(KeyShowArgs),
}

#[derive(Debug, Args)]
pub struct InventoryListArgs {
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct InventoryShowArgs {
    pub target: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct UserShowArgs {
    pub username: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyListArgs {
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyReuseArgs {
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeyShowArgs {
    pub target: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    Create(ReportCreateArgs),
}

#[derive(Debug, Args)]
pub struct ReportCreateArgs {
    #[arg(long, default_value = "html")]
    pub format: String,

    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum BaselineCommand {
    Create(BaselineCreateArgs),
    List(BaselineListArgs),
}

#[derive(Debug, Args)]
pub struct BaselineCreateArgs {
    #[arg(long)]
    pub name: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct BaselineListArgs {
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    #[arg(long)]
    pub from: String,

    #[arg(long, default_value = "latest")]
    pub to: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum GraphCommand {
    Export(GraphExportArgs),
}

#[derive(Debug, Args)]
pub struct GraphExportArgs {
    #[arg(long, default_value = "json")]
    pub format: String,

    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct PathArgs {
    #[arg(long)]
    pub from: String,

    #[arg(long)]
    pub to: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct BlastRadiusArgs {
    #[arg(long)]
    pub user: String,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ImportCommand {
    Ansible(ImportFileArgs),
    Nmap(ImportFileArgs),
    Csv(ImportCsvArgs),
    KnownHosts(ImportFileArgs),
    SshConfig(ImportHostFileArgs),
    SshdConfig(ImportHostFileArgs),
    AuthorizedKeys(ImportAuthorizedKeysArgs),
    Sudoers(ImportHostFileArgs),
    Json(ImportFileArgs),
}

#[derive(Debug, Args)]
pub struct ImportFileArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportCsvArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub mapping: Option<PathBuf>,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportHostFileArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    #[arg(long)]
    pub host: String,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportAuthorizedKeysArgs {
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    #[arg(long)]
    pub host: String,

    #[arg(long)]
    pub user: String,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,

    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: String,

    #[arg(long, default_value_t = true)]
    pub read_only: bool,

    #[arg(long, help = "Require X-SSHMap-Token header for API requests")]
    pub token: Option<String>,

    #[arg(
        long,
        value_name = "DIR",
        help = "Serve a built React dashboard from DIR"
    )]
    pub dashboard: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ExceptionsCommand {
    List(ExceptionListArgs),
    Add(ExceptionAddArgs),
    Remove(ExceptionRemoveArgs),
}

#[derive(Debug, Args)]
pub struct ExceptionListArgs {
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ExceptionAddArgs {
    #[arg(long)]
    pub code: String,

    #[arg(long)]
    pub reason: String,

    #[arg(long)]
    pub host_id: Option<i64>,

    #[arg(long)]
    pub username: Option<String>,

    #[arg(long)]
    pub fingerprint: Option<String>,

    #[arg(long)]
    pub expires_at: Option<String>,

    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct ExceptionRemoveArgs {
    pub id: i64,

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,
}

#[derive(Debug, Args)]
pub struct CompletionArgs {
    #[arg(long, value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    Summary(ExportSummaryArgs),
    Risks(ExportRisksArgs),
    Hosts(ExportHostsArgs),
    KnownHosts(ExportKnownHostsArgs),
    SshConfig(ExportSshConfigArgs),
}

#[derive(Debug, Args)]
pub struct ExportSummaryArgs {
    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExportRisksArgs {
    #[arg(long, default_value = "json")]
    pub format: String,

    #[arg(long)]
    pub severity: Option<String>,

    #[arg(long)]
    pub code: Option<String>,

    #[arg(long, default_value_t = 10_000)]
    pub limit: usize,

    #[arg(long, default_value = "sshmap.db")]
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

    #[arg(long, default_value = "sshmap.db")]
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

    #[arg(long, default_value = "sshmap.db")]
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

    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct BenchArgs {
    #[arg(long, default_value = "sshmap.db")]
    pub db: PathBuf,

    #[arg(long, default_value_t = crate::bench::default_host_count())]
    pub hosts: usize,

    #[arg(long, default_value_t = crate::bench::default_iterations())]
    pub iterations: u32,

    #[arg(long, help = "Recreate the benchmark database before running")]
    pub seed: bool,

    #[arg(long)]
    pub json: bool,

    #[arg(long, value_name = "PATH")]
    pub thresholds: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Compare results against a previous JSON benchmark report"
    )]
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
