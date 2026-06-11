CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    group_name TEXT NOT NULL,
    gid INTEGER,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, group_name)
);

CREATE TABLE IF NOT EXISTS user_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(group_id) REFERENCES groups(id),
    UNIQUE(host_id, user_id, group_id)
);

CREATE TABLE IF NOT EXISTS sshd_config_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    source_file TEXT,
    line_number INTEGER,
    match_context TEXT,
    effective INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS authorized_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    public_key_id INTEGER NOT NULL,
    source_file TEXT,
    line_number INTEGER,
    options TEXT,
    has_from_restriction INTEGER NOT NULL DEFAULT 0,
    has_command_restriction INTEGER NOT NULL DEFAULT 0,
    permits_pty INTEGER NOT NULL DEFAULT 1,
    permits_port_forwarding INTEGER NOT NULL DEFAULT 1,
    permits_agent_forwarding INTEGER NOT NULL DEFAULT 1,
    permits_x11_forwarding INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(public_key_id) REFERENCES public_keys(id),
    UNIQUE(host_id, user_id, public_key_id, source_file, line_number)
);

CREATE TABLE IF NOT EXISTS sudo_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    run_as TEXT,
    command TEXT,
    tags TEXT,
    nopasswd INTEGER NOT NULL DEFAULT 0,
    source_file TEXT,
    line_number INTEGER,
    risk_level TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE INDEX IF NOT EXISTS idx_groups_host ON groups(host_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_user ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_sshd_config_host ON sshd_config_entries(host_id);
CREATE INDEX IF NOT EXISTS idx_authorized_keys_public_key ON authorized_keys(public_key_id);
CREATE INDEX IF NOT EXISTS idx_authorized_keys_user ON authorized_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_sudo_rules_host ON sudo_rules(host_id);
