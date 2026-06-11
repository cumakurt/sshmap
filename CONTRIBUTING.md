# Contributing

## Coding Standard

All code and developer-facing technical assets must be written in English:

- Source identifiers
- Module and file names
- Database table and column names
- CLI command and flag names
- Log messages
- Error messages
- Test names
- Code comments
- Commit messages

Documentation for users may be translated later through a dedicated localization layer, but the codebase remains English.

## Local Checks

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```
