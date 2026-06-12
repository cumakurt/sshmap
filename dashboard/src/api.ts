export interface DatabaseStats {
  hosts: number;
  users: number;
  keys: number;
  risks: number;
}

export interface ApiSummary {
  stats: DatabaseStats;
  ssh_open_hosts: number;
  critical_risks: number;
  high_risks: number;
  reused_keys: number;
  scan_coverage_percent: number;
  hosts_with_users: number;
  severity_distribution: Record<string, number>;
}

export interface OperationsMetricsRecord {
  scan_coverage_percent: number;
  hosts_with_users: number;
  hosts_without_users: number;
  severity_distribution: Record<string, number>;
  baseline_trend: BaselineTrendPoint[];
}

export interface BaselineTrendPoint {
  name: string;
  created_at: string;
  critical_risks: number;
  high_risks: number;
  total_risks: number;
}

export interface ComplianceReport {
  framework: string;
  total_controls: number;
  passing_controls: number;
  failing_controls: number;
  compliance_percent: number;
  controls: Array<{
    framework: string;
    control_id: string;
    title: string;
    status: string;
    failing_risk_codes: string[];
  }>;
}

export interface HostRecord {
  id: number;
  hostname: string | null;
  fqdn: string | null;
  ip_address: string;
  port: number;
  os_family: string | null;
  os_version: string | null;
  environment: string | null;
  criticality: string | null;
  ssh_open: boolean;
  ssh_banner: string | null;
  source: string;
  first_seen: string;
  last_seen: string;
  user_count: number;
  risk_count: number;
}

export interface RiskRecord {
  id: number;
  host_id: number | null;
  hostname: string | null;
  ip_address: string | null;
  username: string | null;
  public_key_fingerprint: string | null;
  risk_code: string;
  severity: string;
  score: number;
  confidence: string;
  title: string;
  description: string | null;
  impact: string | null;
  evidence: string | null;
  recommendation: string | null;
  status: string;
  first_seen: string;
  last_seen: string;
}

export interface UserSummaryRecord {
  username: string;
  host_count: number;
  key_count: number;
  sudo_rule_count: number;
  risk_count: number;
}

export interface UserAccountRecord {
  id: number;
  host_id: number;
  hostname: string | null;
  ip_address: string;
  username: string;
  uid: number | null;
  gid: number | null;
  home_dir: string | null;
  shell: string | null;
  is_root: boolean;
  is_system_account: boolean;
  is_service_account: boolean;
}

export interface HostDetailRecord {
  host: HostRecord;
  users: UserAccountRecord[];
  risks: RiskRecord[];
}

export interface KeyLocationRecord {
  public_key_id: number;
  key_type: string;
  fingerprint_sha256: string;
  host_id: number;
  hostname: string | null;
  ip_address: string;
  username: string;
  source_file: string | null;
  line_number: number | null;
  options: string | null;
}

export interface SudoRuleRecord {
  host_id: number;
  hostname: string | null;
  ip_address: string;
  subject: string;
  subject_type: string;
  run_as: string | null;
  command: string | null;
  nopasswd: boolean;
  source_file: string | null;
  line_number: number | null;
  risk_level: string | null;
}

export interface UserDetailRecord {
  username: string;
  accounts: UserAccountRecord[];
  authorized_keys: KeyLocationRecord[];
  sudo_rules: SudoRuleRecord[];
  risks: RiskRecord[];
}

export interface KeySummaryRecord {
  id: number;
  key_type: string;
  fingerprint_sha256: string;
  key_comment: string | null;
  host_count: number;
  user_count: number;
  root_usage_count: number;
  risk_count: number;
}

export interface KeyDetailRecord {
  key: KeySummaryRecord;
  locations: KeyLocationRecord[];
  risks: RiskRecord[];
}

export interface GraphListRecord {
  edges: GraphEdgeRecord[];
  truncated: boolean;
  total_edges: number;
  edge_limit: number;
}

export function parseGraphListResponse(
  response: GraphListRecord | GraphEdgeRecord[],
): GraphListRecord {
  if (Array.isArray(response)) {
    return {
      edges: response,
      truncated: false,
      total_edges: response.length,
      edge_limit: response.length,
    };
  }

  const edges = Array.isArray(response.edges) ? response.edges : [];
  return {
    edges,
    truncated: Boolean(response.truncated),
    total_edges: response.total_edges ?? edges.length,
    edge_limit: response.edge_limit ?? edges.length,
  };
}

export interface HardeningReport {
  hosts: HostHardeningScore[];
  summary: Record<string, number>;
  control_count: number;
}

export interface HostHardeningScore {
  host_id: number;
  hostname: string | null;
  ip_address: string;
  score: number;
  risk_count: number;
  critical_risks: number;
  high_risks: number;
  compliance_percent: number;
}

export interface GraphEdgeRecord {
  id: number;
  from_type: string;
  from_id: number;
  from_label: string;
  to_type: string;
  to_id: number;
  to_label: string;
  edge_type: string;
  weight: number;
  confidence: string;
  evidence: string | null;
}

export interface GraphPathRecord {
  found: boolean;
  nodes: unknown[];
  edges: GraphEdgeRecord[];
  edges_truncated?: boolean;
}

export interface BlastRadiusRecord {
  username: string;
  host_count: number;
  passwordless_sudo_host_count: number;
  entry_points: unknown[];
  reachable_hosts: unknown[];
  sudo_path_to_root_score?: number | null;
  edges_truncated?: boolean;
}

export interface RiskExceptionRecord {
  id: number;
  risk_code: string;
  host_id: number | null;
  username: string | null;
  public_key_fingerprint: string | null;
  reason: string;
  created_at: string;
  expires_at: string | null;
}

export interface ScanRunRecord {
  id: number;
  run_uuid: string;
  mode: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  targets_json: string | null;
  operator: string | null;
  sudo_enabled: boolean | null;
  summary_json: string | null;
  error_message: string | null;
}

export interface AuditEventRecord {
  id: number;
  scan_run_id: number | null;
  event_type: string;
  message: string;
  metadata_json: string | null;
  created_at: string;
}

export interface ScanRunDetailRecord {
  run: ScanRunRecord;
  events: AuditEventRecord[];
}

export interface BaselineSummary {
  hosts: number;
  users: number;
  keys: number;
  risks: number;
  critical_risks: number;
  high_risks: number;
}

export interface BaselineRecord {
  id: number;
  name: string;
  created_at: string;
  summary: BaselineSummary;
}

export interface BaselineRiskRecord {
  signature: string;
  risk_code: string;
  severity: string;
  score: number;
  target: string;
  title: string;
  evidence: string | null;
  status: string;
}

export interface BaselineDiffRecord {
  from: BaselineRecord;
  to: BaselineRecord;
  new_risks: BaselineRiskRecord[];
  resolved_risks: BaselineRiskRecord[];
  unchanged_risks: number;
}

export interface SshClientConfigEntryRecord {
  id: number;
  host_id: number;
  hostname: string | null;
  ip_address: string | null;
  host_pattern: string;
  config_hostname: string | null;
  ssh_user: string | null;
  port: number | null;
  identity_file: string | null;
  proxy_jump: string | null;
  proxy_command: string | null;
  forward_agent: string | null;
  local_forward: string | null;
  remote_forward: string | null;
  dynamic_forward: string | null;
  strict_host_key_checking: string | null;
  include_file: string | null;
  source_file: string | null;
  line_number: number | null;
}

export interface HostAliasRecord {
  id: number;
  host_id: number;
  hostname: string | null;
  host_ip_address: string;
  ip_address: string;
  alias: string;
  alias_kind: string;
  source: string;
  source_file: string | null;
  line_number: number | null;
  confidence: string;
}

export interface DataQualityFindingRecord {
  id: number;
  host_id: number | null;
  hostname: string | null;
  ip_address: string | null;
  code: string;
  severity: string;
  message: string;
  evidence: string | null;
  created_at: string;
}

export interface RemediationRecord {
  risk_code: string;
  title: string;
  verify: string[];
  fix: string[];
  rollback: string[];
  ansible: string | null;
}

const TOKEN_KEY = "sshmap_token";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string): void {
  if (token.trim()) {
    localStorage.setItem(TOKEN_KEY, token.trim());
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export async function api<T>(path: string): Promise<T> {
  return apiRequest<T>(path);
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  return apiRequest<T>(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function apiDelete<T>(path: string): Promise<T> {
  return apiRequest<T>(path, { method: "DELETE" });
}

async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) {
    headers["X-SSHMap-Token"] = token;
  }
  if (init.body) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json() as Promise<T>;
}

export function hostLabel(host: HostRecord): string {
  return host.hostname ?? host.fqdn ?? host.ip_address;
}

export function accountHostLabel(account: UserAccountRecord): string {
  return account.hostname ?? account.ip_address;
}

export function riskTarget(risk: RiskRecord): string {
  if (risk.username) {
    return `${risk.username}@${risk.hostname ?? risk.ip_address ?? "unknown"}`;
  }
  return risk.hostname ?? risk.ip_address ?? risk.public_key_fingerprint ?? "global";
}
