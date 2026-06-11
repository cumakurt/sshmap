# Risk Engine

The risk engine converts normalized analysis data into actionable findings.

## Pipeline

```text
NormalizedAnalysis
  -> risk::generate_risks(analysis, policy)
  -> exceptions::apply_exceptions(risks, exceptions)
  -> db::replace_risks
```

## Rule Categories

| Category | Examples |
|----------|----------|
| SSH daemon config | Root login enabled, password auth enabled, TCP forwarding |
| Accounts | Service accounts with interactive shells |
| Authorized keys | Unrestricted keys, agent forwarding, command gaps |
| Sudo | NOPASSWD ALL, group-wide admin grants |
| Client config | Global forward agent, disabled strict host key checking, ProxyJump chains |
| Key reuse | Same public key authorized on many hosts |
| Combined | Key reuse plus sudo privileges |

## Policy File

Tune thresholds and toggles with YAML:

```bash
sshmap analyze --risk-policy examples/risk-policy.yaml --db sshmap.db
```

Example:

```yaml
rules:
  SSH_KEY_REUSED_MANY_HOSTS:
    enabled: true
    high_threshold: 5
    critical_threshold: 20
  SSH_PASSWORD_AUTH_ENABLED:
    enabled: true
    severity: HIGH
```

Policy loading order:

1. `--risk-policy` CLI flag
2. `risk_policy` key in main YAML config
3. Built-in defaults from `RiskPolicy::default()`

## Exceptions

Operators can suppress accepted findings:

```bash
sshmap exceptions add --code SSH_PASSWORD_AUTH_ENABLED --host web01 --db sshmap.db
```

Exceptions are applied after policy filtering during analyze.

## Adding A Rule

1. Implement generation logic in `src/risk/mod.rs`
2. Choose a stable uppercase risk code
3. Add policy hooks in `src/risk/policy.rs` when severity or thresholds should be configurable
4. Add unit tests with minimal `NormalizedAnalysis` fixtures
5. Document remediation guidance in `docs/remediation.md`
