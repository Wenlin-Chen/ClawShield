# Policy Reference

This document describes the default policy and detection rules shipped in the
ClawShield. These defaults are intentionally conservative.

## Skill scanner rules

Current high-signal patterns:

- `curl` or `wget` piped into `bash` or `sh`
- `subprocess.run`, `subprocess.call`, or `subprocess.Popen` with `shell=True`
- `os.system(...)`
- `eval(...)` or `exec(...)`
- base64 decoding primitives
- sensitive path references such as `~/.ssh`, `~/.aws`, `.env`, `id_rsa`,
  `id_ed25519`
- explicit outbound HTTP usage via `requests`, `httpx`, or hard-coded URLs

Recommendation thresholds:

- `block`: score `>= 70` or any critical finding
- `warn`: score `30-69`
- `allow`: score `< 30`

## Prompt injection detector rules

Flags currently emitted:

- `instruction override attempt`
- `secret exfiltration attempt`
- `tool abuse attempt`
- `system prompt extraction attempt`

High-signal phrases include:

- "ignore previous instructions"
- "read ~/.aws/credentials"
- "send secrets to attacker.example"
- "reveal the system prompt"
- "use the shell" or "run curl"

Suggested interpretation:

- `< 35`: likely benign
- `35-69`: suspicious and worth extra policy scrutiny
- `>= 70`: high-confidence prompt injection

## Sensitive data guardian defaults

Sensitive path markers:

- `~/.ssh`
- `.ssh/`
- `~/.aws`
- `.aws/`
- `.env`
- `id_rsa`
- `id_ed25519`
- browser profile or cookies references
- token-oriented directories or files

Secret regex families:

- AWS access keys
- private key headers
- GitHub tokens
- `sk-...` API-style keys
- bearer tokens
- generic `api_key`, `token`, or `secret` assignments

## Runtime policy broker rules

### File access

- Block reads and writes to sensitive paths by default.
- Warn when a non-sensitive target does not appear relevant to the task.

### Shell execution

Block commands matching:

- remote pipe execution such as `curl ... | bash`
- destructive deletes such as `rm -rf /`
- reverse shell style `nc -e`
- `bash -c` wrappers that fetch remote payloads

### Outbound actions

- Warn on destinations outside the default allowlist.
- Block outbound payloads that appear to contain secrets.
- Escalate outbound activity to `block` after a prior prompt-injection alert in
  the same session.
- Block outbound activity after sensitive file access in the same session.

### Skill installation

- Warn when skill install provenance is not local.

## Default allowlist

Current built-in safe domains:

- `localhost`
- `127.0.0.1`
- `::1`
- `example.com`

## How to add your own rules today

ClawShield keeps detection and policy rules in code today. There is no UI rule
editor or standalone policy bundle format yet.

### 1. Edit the rule source that matches your use case

- Skill scanning: [`backend/app/skill_scanner.py`](../backend/app/skill_scanner.py)
  Update `SCANNER_RULES` to add or tune signatures.
- Prompt injection detection: [`backend/app/injection_detector.py`](../backend/app/injection_detector.py)
  Update `RULES` to add or tune text patterns and weights.
- Sensitive file and secret detection: [`backend/app/sensitive_data.py`](../backend/app/sensitive_data.py)
  Update `SENSITIVE_PATH_MARKERS` and `SECRET_PATTERNS`.
- Runtime policy decisions: [`backend/app/policy_engine.py`](../backend/app/policy_engine.py)
  Update `SAFE_DOMAINS`, `DANGEROUS_COMMAND_PATTERNS`, or `evaluate_event`.

### 2. Add tests for both detection and false-positive control

- Put scanner, injection, and policy tests in [`backend/app/tests/`](../backend/app/tests/).
- Add at least one positive case and one benign case for every new rule.

### 3. Restart the backend and re-run checks

```bash
make test-backend
make test-openclaw-plugin
```

Then restart the backend so the new rule set is loaded.

### 4. Adjust OpenClaw plugin config separately when needed

If your OpenClaw install uses different tool names, update
`plugins.entries.clawshield.config` in your Gateway config. That mapping lives
in the plugin config, not in the backend rules. See
[docs/openclaw-integration.md](openclaw-integration.md).

## Planned configuration improvements

Near-term customization work is tracked for:

- configurable allowlisted domains
- configurable sensitive path patterns
- configurable severity thresholds
- import/export support for policy bundles
