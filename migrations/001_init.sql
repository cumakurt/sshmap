CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    targets_json TEXT,
    config_hash TEXT,
    operator TEXT,
    summary_json TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT,
    fqdn TEXT,
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    os_family TEXT,
    os_version TEXT,
    environment TEXT,
    criticality TEXT,
    ssh_open INTEGER NOT NULL DEFAULT 0,
    ssh_banner TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT NOT NULL,
    UNIQUE(ip_address, port)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    uid INTEGER,
    gid INTEGER,
    home_dir TEXT,
    shell TEXT,
    is_root INTEGER NOT NULL DEFAULT 0,
    is_system_account INTEGER NOT NULL DEFAULT 0,
    is_service_account INTEGER NOT NULL DEFAULT 0,
    account_state TEXT,
    first_seen TEXT,
    last_seen TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, username)
);

CREATE TABLE IF NOT EXISTS public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    fingerprint_md5 TEXT,
    key_bits INTEGER,
    key_comment TEXT,
    normalized_public_key TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    host_id INTEGER,
    user_id INTEGER,
    public_key_id INTEGER,
    risk_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    evidence TEXT,
    recommendation TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(public_key_id) REFERENCES public_keys(id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_public_keys_fp ON public_keys(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_risks_code ON risks(risk_code);
CREATE INDEX IF NOT EXISTS idx_risks_severity ON risks(severity);
