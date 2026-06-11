CREATE TABLE IF NOT EXISTS known_hosts_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    known_host TEXT,
    known_ip TEXT,
    host_key_type TEXT NOT NULL,
    host_key_fingerprint TEXT,
    hashed INTEGER NOT NULL DEFAULT 0,
    source_file TEXT,
    line_number INTEGER,
    confidence TEXT NOT NULL DEFAULT 'LOW',
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS ssh_client_config_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    host_pattern TEXT NOT NULL,
    hostname TEXT,
    ssh_user TEXT,
    port INTEGER,
    identity_file TEXT,
    proxy_jump TEXT,
    proxy_command TEXT,
    forward_agent TEXT,
    local_forward TEXT,
    remote_forward TEXT,
    dynamic_forward TEXT,
    strict_host_key_checking TEXT,
    source_file TEXT,
    line_number INTEGER,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_known_hosts_entries_host_id ON known_hosts_entries(host_id);
CREATE INDEX IF NOT EXISTS idx_ssh_client_config_entries_host_id ON ssh_client_config_entries(host_id);
