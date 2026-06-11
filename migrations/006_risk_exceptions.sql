CREATE TABLE IF NOT EXISTS risk_exceptions (
    id INTEGER PRIMARY KEY,
    risk_code TEXT NOT NULL,
    host_id INTEGER,
    username TEXT,
    public_key_fingerprint TEXT,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_exceptions_code ON risk_exceptions(risk_code);
