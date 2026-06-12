use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseStats {
    pub hosts: usize,
    pub users: usize,
    pub keys: usize,
    pub risks: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetailedDatabaseStats {
    pub schema_version: i64,
    pub hosts: usize,
    pub users: usize,
    pub keys: usize,
    pub risks: usize,
    pub raw_evidence: usize,
    pub graph_edges: usize,
    pub known_hosts_entries: usize,
    pub ssh_client_config_entries: usize,
    pub host_aliases: usize,
    pub data_quality_findings: usize,
    pub risk_exceptions: usize,
    pub baselines: usize,
    pub last_analysis_finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRunSummary {
    pub targets_scanned: usize,
    pub ssh_open: usize,
    pub closed_or_unreachable: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteScanSummary {
    pub targets_scanned: usize,
    pub hosts_succeeded: usize,
    pub hosts_failed: usize,
    pub evidence_items: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportSummary {
    pub imported: usize,
}

#[derive(Debug, Clone)]
pub struct ImportedHost {
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub ip_address: String,
    pub port: i64,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub environment: Option<String>,
    pub criticality: Option<String>,
    pub ssh_open: bool,
}

#[derive(Debug, Clone)]
pub struct RawEvidenceRecord {
    pub evidence_type: String,
    pub source: String,
    pub command: String,
    pub content: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub redacted: bool,
}

#[derive(Debug, Clone)]
pub struct HostScanResult {
    pub host: String,
    pub port: u16,
    pub evidence: Vec<RawEvidenceRecord>,
}

impl HostScanResult {
    pub fn succeeded(&self) -> bool {
        self.evidence
            .iter()
            .any(|record| record.exit_code == Some(0))
    }
}

#[derive(Debug, Clone)]
pub struct RawEvidenceForAnalysis {
    pub host_id: i64,
    pub evidence_type: String,
    pub source: String,
    pub content: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalysisSummary {
    pub skipped: bool,
    pub raw_evidence_items: usize,
    pub users: usize,
    pub groups: usize,
    pub public_keys: usize,
    pub authorized_keys: usize,
    pub sshd_config_entries: usize,
    pub sudo_rules: usize,
    pub known_hosts_entries: usize,
    pub ssh_client_config_entries: usize,
    pub host_aliases: usize,
    pub risks: usize,
}

#[derive(Debug, Clone, Default)]
pub struct NormalizedAnalysis {
    pub users: Vec<ParsedUser>,
    pub groups: Vec<ParsedGroup>,
    pub host_metadata: Vec<ParsedHostMetadata>,
    pub sshd_config_entries: Vec<ParsedSshdConfigEntry>,
    pub sshd_match_blocks: Vec<ParsedSshdMatchBlock>,
    pub authorized_keys: Vec<ParsedAuthorizedKey>,
    pub sudo_rules: Vec<ParsedSudoRule>,
    pub pam_entries: Vec<ParsedPamEntry>,
    pub known_hosts_entries: Vec<ParsedKnownHostEntry>,
    pub ssh_client_config_entries: Vec<ParsedSshClientConfigEntry>,
    pub host_aliases: Vec<ParsedHostAlias>,
}

impl NormalizedAnalysis {
    pub fn summary(&self, raw_evidence_items: usize, risks: usize) -> AnalysisSummary {
        let public_keys = self
            .authorized_keys
            .iter()
            .map(|entry| entry.public_key.fingerprint_sha256.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();

        AnalysisSummary {
            skipped: false,
            raw_evidence_items,
            users: self.users.len(),
            groups: self.groups.len(),
            public_keys,
            authorized_keys: self.authorized_keys.len(),
            sshd_config_entries: self.sshd_config_entries.len(),
            sudo_rules: self.sudo_rules.len(),
            known_hosts_entries: self.known_hosts_entries.len(),
            ssh_client_config_entries: self.ssh_client_config_entries.len(),
            host_aliases: self.host_aliases.len(),
            risks,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedHostAlias {
    pub host_id: i64,
    pub ip_address: String,
    pub alias: String,
    pub alias_kind: String,
    pub source: String,
    pub source_file: String,
    pub line_number: i64,
    pub confidence: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedKnownHostEntry {
    pub host_id: i64,
    pub known_host: Option<String>,
    pub known_ip: Option<String>,
    pub host_key_type: String,
    pub host_key_fingerprint: Option<String>,
    pub hashed: bool,
    pub source_file: String,
    pub line_number: i64,
    pub confidence: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedSshClientConfigEntry {
    pub host_id: i64,
    pub host_pattern: String,
    pub hostname: Option<String>,
    pub ssh_user: Option<String>,
    pub port: Option<i64>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub forward_agent: Option<String>,
    pub local_forward: Option<String>,
    pub remote_forward: Option<String>,
    pub dynamic_forward: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub include_file: Option<String>,
    pub source_file: String,
    pub line_number: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnownHostEntryRecord {
    pub id: i64,
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub known_host: Option<String>,
    pub known_ip: Option<String>,
    pub host_key_type: String,
    pub host_key_fingerprint: Option<String>,
    pub hashed: bool,
    pub source_file: Option<String>,
    pub line_number: Option<i64>,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshClientConfigEntryRecord {
    pub id: i64,
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub host_pattern: String,
    pub config_hostname: Option<String>,
    pub ssh_user: Option<String>,
    pub port: Option<i64>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub forward_agent: Option<String>,
    pub local_forward: Option<String>,
    pub remote_forward: Option<String>,
    pub dynamic_forward: Option<String>,
    pub strict_host_key_checking: Option<String>,
    pub include_file: Option<String>,
    pub source_file: Option<String>,
    pub line_number: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostAliasRecord {
    pub id: i64,
    pub host_id: i64,
    pub hostname: Option<String>,
    pub host_ip_address: String,
    pub ip_address: String,
    pub alias: String,
    pub alias_kind: String,
    pub source: String,
    pub source_file: Option<String>,
    pub line_number: Option<i64>,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataQualityFindingRecord {
    pub id: i64,
    pub host_id: Option<i64>,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub code: String,
    pub severity: String,
    pub message: String,
    pub evidence: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedUser {
    pub host_id: i64,
    pub username: String,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub home_dir: Option<String>,
    pub shell: Option<String>,
    pub is_root: bool,
    pub is_system_account: bool,
    pub is_service_account: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedGroup {
    pub host_id: i64,
    pub group_name: String,
    pub gid: Option<i64>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ParsedHostMetadata {
    pub host_id: i64,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedSshdMatchBlock {
    pub host_id: i64,
    pub source_file: String,
    pub line_number: i64,
    pub criteria: String,
    pub directives: Vec<(String, String)>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedPamEntry {
    pub host_id: i64,
    pub source_file: String,
    pub line_number: i64,
    pub service: String,
    pub module_type: String,
    pub control: String,
    pub module_path: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedSshdConfigEntry {
    pub host_id: i64,
    pub key: String,
    pub value: Option<String>,
    pub source_file: String,
    pub line_number: i64,
    pub effective: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedPublicKey {
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub key_bits: Option<i64>,
    pub key_comment: Option<String>,
    pub normalized_public_key: String,
    pub certificate_signing_ca: Option<String>,
    pub certificate_valid_after: Option<i64>,
    pub certificate_valid_before: Option<i64>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedAuthorizedKey {
    pub host_id: i64,
    pub username: String,
    pub public_key: ParsedPublicKey,
    pub source_file: String,
    pub line_number: i64,
    pub options: Option<String>,
    pub has_from_restriction: bool,
    pub has_command_restriction: bool,
    pub permits_pty: bool,
    pub permits_port_forwarding: bool,
    pub permits_agent_forwarding: bool,
    pub permits_x11_forwarding: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedSudoRule {
    pub host_id: i64,
    pub subject: String,
    pub subject_type: String,
    pub run_as: Option<String>,
    pub command: Option<String>,
    pub tags: Option<String>,
    pub nopasswd: bool,
    pub source_file: String,
    pub line_number: i64,
    pub risk_level: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GeneratedRisk {
    pub host_id: Option<i64>,
    pub username: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub risk_code: String,
    pub severity: String,
    pub score: i64,
    pub confidence: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskRecord {
    pub id: i64,
    pub host_id: Option<i64>,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub username: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub risk_code: String,
    pub severity: String,
    pub score: i64,
    pub confidence: String,
    pub title: String,
    pub description: Option<String>,
    pub impact: Option<String>,
    pub evidence: Option<String>,
    pub recommendation: Option<String>,
    pub status: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemediationRecord {
    pub risk_code: String,
    pub title: String,
    pub verify: Vec<String>,
    pub fix: Vec<String>,
    pub rollback: Vec<String>,
    pub ansible: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RiskQuery {
    pub severity: Option<String>,
    pub code: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Default)]
pub struct HostQuery {
    pub ssh_open: Option<bool>,
    pub source: Option<String>,
    pub search: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Default)]
pub struct UserQuery {
    pub search: Option<String>,
    pub min_hosts: Option<usize>,
    pub min_risks: Option<usize>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostRecord {
    pub id: i64,
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub ip_address: String,
    pub port: i64,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub environment: Option<String>,
    pub criticality: Option<String>,
    pub ssh_open: bool,
    pub ssh_banner: Option<String>,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub user_count: usize,
    pub risk_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostDetailRecord {
    pub host: HostRecord,
    pub users: Vec<UserAccountRecord>,
    pub risks: Vec<RiskRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRunRecord {
    pub id: i64,
    pub run_uuid: String,
    pub mode: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub targets_json: Option<String>,
    pub operator: Option<String>,
    pub sudo_enabled: Option<bool>,
    pub summary_json: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRunDetailRecord {
    pub run: ScanRunRecord,
    pub events: Vec<AuditEventRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEventRecord {
    pub id: i64,
    pub scan_run_id: Option<i64>,
    pub event_type: String,
    pub message: String,
    pub metadata_json: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserSummaryRecord {
    pub username: String,
    pub host_count: usize,
    pub key_count: usize,
    pub sudo_rule_count: usize,
    pub risk_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserAccountRecord {
    pub id: i64,
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: String,
    pub username: String,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub home_dir: Option<String>,
    pub shell: Option<String>,
    pub is_root: bool,
    pub is_system_account: bool,
    pub is_service_account: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserDetailRecord {
    pub username: String,
    pub accounts: Vec<UserAccountRecord>,
    pub authorized_keys: Vec<KeyLocationRecord>,
    pub sudo_rules: Vec<SudoRuleRecord>,
    pub risks: Vec<RiskRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeySummaryRecord {
    pub id: i64,
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub key_comment: Option<String>,
    pub host_count: usize,
    pub user_count: usize,
    pub root_usage_count: usize,
    pub risk_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyLocationRecord {
    pub public_key_id: i64,
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: String,
    pub username: String,
    pub source_file: Option<String>,
    pub line_number: Option<i64>,
    pub options: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyDetailRecord {
    pub key: KeySummaryRecord,
    pub locations: Vec<KeyLocationRecord>,
    pub risks: Vec<RiskRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SudoRuleRecord {
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: String,
    pub subject: String,
    pub subject_type: String,
    pub run_as: Option<String>,
    pub command: Option<String>,
    pub nopasswd: bool,
    pub source_file: Option<String>,
    pub line_number: Option<i64>,
    pub risk_level: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiSummary {
    pub stats: DatabaseStats,
    pub ssh_open_hosts: usize,
    pub critical_risks: usize,
    pub high_risks: usize,
    pub reused_keys: usize,
    pub scan_coverage_percent: f64,
    pub hosts_with_users: usize,
    pub severity_distribution: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostContextRecord {
    pub host_id: i64,
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub environment: Option<String>,
    pub criticality: Option<String>,
    pub ssh_open: bool,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostServerKeyRecord {
    pub host_id: i64,
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub first_seen: String,
    pub last_seen: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicKeyAgeRecord {
    pub fingerprint_sha256: String,
    pub first_seen: String,
    pub last_seen: String,
    pub age_days: i64,
    pub host_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperationsMetricsRecord {
    pub scan_coverage_percent: f64,
    pub hosts_with_users: usize,
    pub hosts_without_users: usize,
    pub severity_distribution: BTreeMap<String, usize>,
    pub baseline_trend: Vec<BaselineTrendPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineTrendPoint {
    pub name: String,
    pub created_at: String,
    pub critical_risks: usize,
    pub high_risks: usize,
    pub total_risks: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskExceptionRecord {
    pub id: i64,
    pub risk_code: String,
    pub host_id: Option<i64>,
    pub username: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub reason: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewRiskException {
    pub risk_code: String,
    pub host_id: Option<i64>,
    pub username: Option<String>,
    pub public_key_fingerprint: Option<String>,
    pub reason: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum AnalyzeScope {
    #[default]
    All,
    Risks,
    Graph,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportData {
    pub summary: ReportSummary,
    pub severity_counts: BTreeMap<String, usize>,
    pub hosts: Vec<HostRecord>,
    pub users: Vec<UserSummaryRecord>,
    pub keys: Vec<KeySummaryRecord>,
    pub reused_keys: Vec<KeySummaryRecord>,
    pub risks: Vec<RiskRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub hosts: usize,
    pub users: usize,
    pub keys: usize,
    pub risks: usize,
    pub ssh_open_hosts: usize,
    pub critical_risks: usize,
    pub high_risks: usize,
    pub reused_keys: usize,
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GraphNodeRecord {
    pub node_type: String,
    pub node_id: i64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdgeRecord {
    pub id: i64,
    pub from_type: String,
    pub from_id: i64,
    pub from_label: String,
    pub to_type: String,
    pub to_id: i64,
    pub to_label: String,
    pub edge_type: String,
    pub weight: i64,
    pub confidence: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphPathRecord {
    pub found: bool,
    pub from: GraphNodeRecord,
    pub to: GraphNodeRecord,
    pub nodes: Vec<GraphNodeRecord>,
    pub edges: Vec<GraphEdgeRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlastRadiusRecord {
    pub username: String,
    pub entry_points: Vec<GraphNodeRecord>,
    pub reachable_hosts: Vec<GraphNodeRecord>,
    pub passwordless_sudo_hosts: Vec<GraphNodeRecord>,
    pub reachable_public_keys: Vec<GraphNodeRecord>,
    pub reachable_sudo_rules: Vec<GraphNodeRecord>,
    pub host_count: usize,
    pub passwordless_sudo_host_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphPathsRecord {
    pub from: GraphNodeRecord,
    pub to: GraphNodeRecord,
    pub paths: Vec<GraphPathRecord>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyCompromiseBlastRadiusRecord {
    pub fingerprint: String,
    pub entry_points: Vec<GraphNodeRecord>,
    pub reachable_hosts: Vec<GraphNodeRecord>,
    pub reachable_users: Vec<GraphNodeRecord>,
    pub passwordless_sudo_hosts: Vec<GraphNodeRecord>,
    pub host_count: usize,
    pub total_path_weight: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub hosts: usize,
    pub users: usize,
    pub keys: usize,
    pub risks: usize,
    pub critical_risks: usize,
    pub high_risks: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineRecord {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub summary: BaselineSummary,
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct BaselineRiskRecord {
    pub signature: String,
    pub risk_code: String,
    pub severity: String,
    pub score: i64,
    pub target: String,
    pub title: String,
    pub evidence: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineDiffRecord {
    pub from: BaselineRecord,
    pub to: BaselineRecord,
    pub new_risks: Vec<BaselineRiskRecord>,
    pub resolved_risks: Vec<BaselineRiskRecord>,
    pub unchanged_risks: usize,
}
