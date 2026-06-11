# Graph Engine

The graph engine models SSH access relationships as directed edges between typed nodes.

## Node Types

- `host`
- `user`
- `key`

Node references in CLI commands use forms such as `host:web01`, `user:deploy`, and `key:SHA256:...`.

## Edge Types

Edges are rebuilt during analyze from normalized data:

| Edge type | Meaning |
|-----------|---------|
| Host-user membership | Account exists on host |
| User-key authorization | Authorized key grants user access |
| Sudo escalation | Sudo rule connects user to privilege scope |
| Client config | ProxyJump or client-side path hints |
| Known hosts | Client recorded host references |

See `insert_*_edges` functions in `src/db.rs`.

## Commands

```bash
sshmap graph export --format dot --output graph.dot --db sshmap.db
sshmap graph export --format cytoscape --output graph.cytoscape.json --db sshmap.db
sshmap path --from user:deploy --to host:db01 --db sshmap.db
sshmap blast-radius --user deploy --db sshmap.db
```

Supported export formats:

- `json` — raw edge records
- `dot` — Graphviz DOT
- `cytoscape` — Cytoscape.js elements document

## Algorithms

- Path search uses directed edge traversal in `src/graph.rs`
- Blast radius expands reachable hosts and privilege scopes from user entry points

## API Exposure

Read-only graph data is available through:

- CSV export via `report create --format csv`
- REST endpoints under `sshmap serve`

## Extension Notes

When adding a new relationship:

1. Persist normalized facts during analyze
2. Insert edges in the appropriate `insert_*_edges` helper
3. Update graph export and API serializers if new edge metadata is required
4. Add graph tests in `src/graph.rs`
