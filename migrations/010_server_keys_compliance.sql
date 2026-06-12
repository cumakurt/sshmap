CREATE TABLE IF NOT EXISTS host_server_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    key_type TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    public_key TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, fingerprint_sha256)
);

CREATE INDEX IF NOT EXISTS idx_host_server_keys_host ON host_server_keys(host_id);
CREATE INDEX IF NOT EXISTS idx_host_server_keys_fingerprint ON host_server_keys(fingerprint_sha256);

ALTER TABLE hosts ADD COLUMN openssh_version TEXT;

ALTER TABLE public_keys ADD COLUMN certificate_signing_ca TEXT;
