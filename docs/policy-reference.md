# Policy Reference

This document describes the default policy and detection rules shipped in the
MVP. These defaults are intentionally conservative.

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

## Customization direction

The MVP keeps rules in code. Near-term customization should add:

- configurable allowlisted domains
- configurable sensitive path patterns
- configurable severity thresholds
- import/export support for policy bundles

