CREATE TABLE IF NOT EXISTS graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_type TEXT NOT NULL,
    from_id INTEGER NOT NULL,
    from_label TEXT NOT NULL,
    to_type TEXT NOT NULL,
    to_id INTEGER NOT NULL,
    to_label TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    confidence TEXT NOT NULL DEFAULT 'MEDIUM',
    evidence TEXT,
    UNIQUE(from_type, from_id, to_type, to_id, edge_type)
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_from ON graph_edges(from_type, from_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_to ON graph_edges(to_type, to_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges(edge_type);
