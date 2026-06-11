# Parsers

Parsers convert raw evidence strings into typed structures defined in `src/models.rs`.

## Layout

```text
src/parser/
  common.rs          Shared helpers and file section splitting
  passwd.rs
  group.rs
  sshd_config.rs
  authorized_keys.rs
  sudoers.rs
  known_hosts.rs
  ssh_config.rs
```

## Evidence Routing

`analyzer::build_normalized_analysis` routes by `evidence_type`:

| Evidence type | Parser |
|---------------|--------|
| `passwd` | `parse_passwd` |
| `group` | `parse_group` |
| `sshd_config` | `parse_sshd_config` |
| `authorized_keys` | `parse_authorized_keys` |
| `sudoers` | `parse_sudoers` |
| `known_hosts` | `parse_known_hosts` |
| `ssh_config` | `parse_ssh_config` |

Failed evidence rows with non-zero exit codes are skipped.

## File Sections

Multi-file bundles use markers such as:

```text
--- SSHMAP_FILE:/path/to/file ---
```

`parser::common::split_file_sections` splits these sections before parsing.

## Parser Rules

- Never panic on malformed input
- Preserve source file and line number metadata when available
- Keep parser output deterministic for repeatable tests
- Add unit tests beside each parser module

## Adding A Parser

1. Define a model struct in `src/models.rs`
2. Implement the parser module
3. Export it from `src/parser/mod.rs`
4. Route the evidence type in `analyzer.rs`
5. Persist rows in `db::replace_normalized_analysis`
6. Add tests with representative fixtures
