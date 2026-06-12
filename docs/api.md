# REST API

`sshmap serve --read-only` exposes a JSON REST API over the SQLite inventory. All endpoints are read-only and open the database with SQLite read-only flags.

## Authentication

When the server is started with `--token`, send the same value in the `X-SSHMap-Token` request header. Requests without a valid token receive HTTP 401. Token comparison is constant-time.

Non-loopback `--listen` addresses require `--token`. Loopback binds allow serving without a token, but that mode should be limited to trusted local development.

Internal server errors return a generic message; details are logged by the server process.

```bash
curl -H "X-SSHMap-Token: $SSHMAP_TOKEN" http://127.0.0.1:8080/api/summary
```

## Summary

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/summary` | Inventory totals, SSH-open host count, critical/high risk counts, reused key count |

## Hosts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/hosts` | Host inventory list |
| GET | `/api/hosts/{id}` | Host detail with users and risks |

`{id}` accepts a numeric host ID, hostname, FQDN, or IP address.

### `GET /api/hosts` query parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `ssh_open` | `true` / `false` | Filter by SSH port state |
| `source` | string | Exact match on host source (for example `scan`, `discover`) |
| `q` | string | Substring search on hostname, FQDN, or IP address |
| `limit` | integer | Maximum rows returned (default `1000`, max `10000`) |

Example:

```bash
curl 'http://127.0.0.1:8080/api/hosts?ssh_open=true&source=scan&q=web&limit=500'
```

## Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/users` | User exposure summary |
| GET | `/api/users/{username}` | User detail with accounts, authorized keys, sudo rules, and risks |

### `GET /api/users` query parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `q` | string | Substring search on username |
| `min_hosts` | integer | Minimum distinct host count |
| `min_risks` | integer | Minimum risk count |
| `limit` | integer | Maximum rows returned (default `500`, max `10000`) |

Example:

```bash
curl 'http://127.0.0.1:8080/api/users?q=deploy&min_hosts=5&min_risks=1&limit=500'
```

## Keys

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/keys` | All public keys |
| GET | `/api/keys/reuse` | Keys present on more than one host |
| GET | `/api/keys/{target}` | Key detail with locations and related risks |

`{target}` accepts a numeric public key ID or SHA256 fingerprint.

## Risks

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/risks` | Risk findings list |
| GET | `/api/risks/{id}` | Single risk record |

### `GET /api/risks` query parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`); invalid values return HTTP 400 |
| `code` | string | Exact match on risk code |
| `limit` | integer | Maximum rows returned (default `100`, max `10000`) |

Example:

```bash
curl 'http://127.0.0.1:8080/api/risks?severity=CRITICAL&code=SSH_ROOT_LOGIN&limit=500'
```

## Graph and analysis

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/graph` | Access graph edges (see query parameters below) |
| GET | `/api/path?from=...&to=...` | Shortest directed path between graph nodes |
| GET | `/api/blast-radius?user=...` | Reachable hosts from a user's graph entry points |

### `GET /api/graph` query parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Maximum edges returned (default `1000`, max `10000`) |

`from`, `to`, and `user` parameters on path/blast-radius endpoints must be non-empty. Empty values return HTTP 400.

Graph node references use the same `type:id` or label forms accepted by `sshmap graph path`.

## Supporting data

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/baselines` | Stored risk baselines |
| GET | `/api/exceptions` | Active risk exceptions |
| GET | `/api/known-hosts` | Collected known-hosts entries |
| GET | `/api/ssh-config` | Collected SSH client config entries |

## React dashboard

The React dashboard under `dashboard/` mirrors these list filters in URL query parameters. See `docs/dashboard.md` for page routes and shareable filter links.
