# Coding Standards

SSHMap is an English-only codebase.

## Language Rules

All of the following must be written in English:

- Source code identifiers
- Comments
- CLI command names and help text
- Error and log messages
- Database table and column names
- Test names and assertions
- Documentation under `docs/`

Do not introduce Turkish identifiers, comments, or user-facing strings in code.

## Rust Style

- Run `cargo fmt` before submitting changes
- Keep `cargo clippy --all-targets -- -D warnings` clean
- Prefer small, focused functions over premature abstraction
- Match existing module layout and naming in neighboring code

## Testing Expectations

- Parser changes require unit tests with fixtures or inline samples
- Risk rule changes require coverage in `src/risk/mod.rs` tests
- Database changes require migration files and migration stability checks

## Security

- Never store private keys or passwords
- Redact sensitive content before writing raw evidence
- Treat imported files as untrusted input; parsers must not panic on malformed data

## Commit Messages

Use clear English commit messages that explain why the change was made, not only what files changed.
