ALTER TABLE scan_runs ADD COLUMN sudo_enabled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS raw_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    host_id INTEGER,
    evidence_type TEXT NOT NULL,
    source TEXT NOT NULL,
    command TEXT,
    content TEXT,
    stderr TEXT,
    exit_code INTEGER,
    content_hash TEXT,
    redacted INTEGER NOT NULL DEFAULT 0,
    collected_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_raw_evidence_scan_run ON raw_evidence(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_raw_evidence_host ON raw_evidence(host_id);
CREATE INDEX IF NOT EXISTS idx_raw_evidence_type ON raw_evidence(evidence_type);
