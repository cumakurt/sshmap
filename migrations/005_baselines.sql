CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    summary_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    baseline_id INTEGER NOT NULL,
    signature TEXT NOT NULL,
    risk_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    evidence TEXT,
    status TEXT NOT NULL,
    FOREIGN KEY(baseline_id) REFERENCES baselines(id) ON DELETE CASCADE,
    UNIQUE(baseline_id, signature)
);

CREATE INDEX IF NOT EXISTS idx_baseline_risks_baseline ON baseline_risks(baseline_id);
CREATE INDEX IF NOT EXISTS idx_baseline_risks_signature ON baseline_risks(signature);
CREATE INDEX IF NOT EXISTS idx_baseline_risks_code ON baseline_risks(risk_code);
