# Changelog

All notable changes to SSHMap are documented in this file.

## [1.2.0] - 2026-06-12

### Added

- `--full-graph` flag on `path`, `paths`, `blast-radius`, and `key-blast-radius` CLI commands to load up to 100,000 graph edges (default analysis limit is 10,000 for CLI and API).
- `SSHMAP_GRAPH_EDGE_LIMIT` environment variable to override the default graph edge cap for analysis.
- Dashboard Vitest coverage for `api.ts` helpers.
- API contract integration tests for `GET /api/graph` and `GET /api/hardening` response shapes.
- Dashboard E2E smoke test (`npm run test:e2e`) and optional Playwright suite (`npm run test:e2e:playwright`).
- Vitest component test for the dashboard navigation shell.
- `scripts/check-rustsec-rsa.sh` to track the `russh` → `rsa` advisory (RUSTSEC-2023-0071).
- SQLite access layer split into `src/db/{pool,migrations,graph,store}.rs`.

### Changed

- **`GET /api/graph`** now returns a `GraphListRecord` object (`edges`, `truncated`, `total_edges`, `edge_limit`) instead of a bare edge array.
- **`GET /api/hardening`** now returns a `HardeningReport` object (`hosts`, `summary`, `control_count`) instead of a bare host score array.
- Path, paths, blast-radius, and key-blast-radius responses include `edges_truncated` when graph analysis hits the edge limit.

### Security

- Webhook SSRF hardening, baseline name validation, graph node reference validation, and API input validation improvements.
- `cargo audit` runs in CI with a documented ignore for RUSTSEC-2023-0071 until `russh` ships a fixed `rsa` release.

### Migration notes for API consumers

Update clients that call:

```text
GET /api/graph
```

Parse `response.edges` instead of treating the JSON body as an array. Check `truncated` and `total_edges` before rendering large graphs.

Update clients that call:

```text
GET /api/hardening
```

Parse `response.hosts` for per-host scores; use `summary` and `control_count` for dashboard aggregates.

See `docs/api.md` for the full reference.
