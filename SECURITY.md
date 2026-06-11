# Security Policy

SSHMap must only be used against systems you own or are explicitly authorized to assess.

## Current Safety Boundaries

- No brute force
- No exploit execution
- No password spraying
- No private key collection
- No password storage
- Discovery mode only performs TCP connect checks and SSH banner reads
- Scan mode runs a fixed read-only command manifest through OpenSSH
- Scan mode uses `BatchMode=yes` and disables password prompts

Report security issues privately to the project maintainers.
