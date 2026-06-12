ALTER TABLE ssh_client_config_entries ADD COLUMN include_file TEXT;

CREATE TABLE IF NOT EXISTS host_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    alias TEXT NOT NULL,
    alias_kind TEXT NOT NULL,
    source TEXT NOT NULL,
    source_file TEXT,
    line_number INTEGER,
    confidence TEXT NOT NULL DEFAULT 'MEDIUM',
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, alias, source, source_file, line_number)
);

CREATE TABLE IF NOT EXISTS data_quality_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    evidence TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_host_aliases_host_id ON host_aliases(host_id);
CREATE INDEX IF NOT EXISTS idx_host_aliases_alias ON host_aliases(alias);
CREATE INDEX IF NOT EXISTS idx_data_quality_host_id ON data_quality_findings(host_id);
