# Remediation Guide

SSHMap findings include evidence and recommendation text for each risk.

## Workflow

1. Run discovery and scan against authorized targets
2. Run `sshmap analyze --db sshmap.db`
3. Review critical and high risks first
4. Remediate configuration and key hygiene issues
5. Create a baseline before major changes
6. Re-scan and compare with `sshmap diff`

## Priority Order

1. Root login and empty password settings
2. Shared root keys and key reuse with passwordless sudo
3. Password authentication on exposed hosts
4. Unrestricted root authorized keys
5. `NOPASSWD:ALL` sudo rules
6. Key reuse across many hosts

## Risk Exceptions

When a finding is accepted temporarily, record an exception:

```bash
sshmap exceptions add \
  --code SSH_PASSWORD_AUTH_ENABLED \
  --host-id 12 \
  --reason "Legacy jump host; migration scheduled" \
  --db sshmap.db
```

Re-run `sshmap analyze` to apply exceptions. Remove them when remediation is complete:

```bash
sshmap exceptions remove 1 --db sshmap.db
```

## Useful Commands

```bash
sshmap risks list --severity critical --db sshmap.db
sshmap keys reuse --db sshmap.db
sshmap blast-radius --user deploy --db sshmap.db
sshmap path --from key:SHA256:... --to host:prod01 --db sshmap.db
```
