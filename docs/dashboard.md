# React Dashboard

SSHMap includes a React dashboard under `dashboard/` that talks to the read-only REST API exposed by `sshmap serve`.

## Development

Terminal 1 — API server:

```bash
sshmap serve --read-only --db sshmap.db --listen 127.0.0.1:8080
```

Terminal 2 — Vite dev server with API proxy:

```bash
cd dashboard
npm install
npm run dev
```

Open the URL printed by Vite (default `http://127.0.0.1:5173`).

## Production Build

```bash
cd dashboard
npm ci
npm run build
```

Serve the compiled bundle:

```bash
sshmap serve \
  --read-only \
  --db sshmap.db \
  --listen 127.0.0.1:8080 \
  --dashboard dashboard/dist
```

YAML config equivalent:

```yaml
serve:
  listen: 127.0.0.1:8080
  read_only: true
  dashboard: dashboard/dist
  token: optional-shared-secret
```

When `--dashboard` is omitted, `sshmap serve` continues to serve the embedded HTML dashboard.

## Continuous Integration

Every push and pull request runs `npm ci && npm run build` in `dashboard/` alongside the Rust checks. Tagged releases publish `sshmap-dashboard.tar.gz`; extract it and pass the `dist` directory to `--dashboard`.

## Pages

| Route | Purpose |
|-------|---------|
| `/` | Inventory summary metrics |
| `/hosts` | Host inventory table |
| `/hosts/:id` | Host detail with users and risks |
| `/users` | User exposure summary |
| `/users/:username` | User detail with accounts, keys, sudo, and risks |
| `/keys` | Reused or full public key inventory |
| `/keys/:id` | Key detail with locations and risks |
| `/risks` | Risk findings list |
| `/risks/:id` | Risk detail with evidence and remediation |
| `/graph` | Access graph canvas and edge table |
| `/tools` | API token, path analysis, blast radius, exceptions |

## Authentication

If the server is started with `--token`, store the same value from the Tools page. The dashboard sends it as the `X-SSHMap-Token` header on API requests.

Detail pages show breadcrumb navigation (for example `Hosts / web01`) instead of single back links.

List filters are reflected in the URL query string:

| Page | Query parameters |
|------|------------------|
| `/hosts` | `ssh`, `source`, `q`, `limit` |
| `/users` | `q`, `min_hosts`, `min_risks`, `limit` |
| `/keys` | `filter=all` (default omits parameter for reused keys) |
| `/risks` | `severity`, `code`, `limit` |
