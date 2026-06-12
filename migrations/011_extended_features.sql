ALTER TABLE hosts ADD COLUMN hardening_score INTEGER;
ALTER TABLE hosts ADD COLUMN cloud_tags_json TEXT;

CREATE TABLE IF NOT EXISTS external_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    source TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    imported_at TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_external_findings_host ON external_findings(host_id);
CREATE INDEX IF NOT EXISTS idx_external_findings_source ON external_findings(source);

CREATE TABLE IF NOT EXISTS bastion_reachability (
    host_id INTEGER NOT NULL,
    bastion_host_id INTEGER NOT NULL,
    scan_run_id INTEGER,
    PRIMARY KEY(host_id, bastion_host_id),
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(bastion_host_id) REFERENCES hosts(id)
);
