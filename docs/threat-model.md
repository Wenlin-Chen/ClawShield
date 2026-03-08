# Threat Model

## Goal

`agent-shield` aims to reduce the blast radius of local agent misuse, especially
for agents that consume untrusted content, install extensions or skills, and
touch local files or outbound network tools.

## In scope

- Malicious skills or plugins that contain obviously risky code paths
- Prompt injection attempts embedded in webpages, docs, email, or tool output
- Unauthorized reads of sensitive local paths such as `~/.ssh`, `~/.aws`, or
  `.env`
- Suspicious outbound requests or messages after sensitive access
- Dangerous shell execution patterns
- Session-level escalation when multiple weak signals combine into a stronger
  attack chain

## Out of scope

- Kernel- or OS-level malware detection
- Full endpoint telemetry, process trees, syscall tracing, or EDR-grade host
  isolation
- Perfect detection of obfuscated or novel attacks
- Memory scraping, browser exploit chains, or supply-chain compromise in third-
  party dependencies
- Remote multi-tenant deployment hardening

## Assumptions

- The broker runs locally with the agent or on the same trusted workstation.
- The integrating agent is willing to call the API before privileged actions.
- Users want safe defaults even at the cost of some warning noise.
- Demo policies are conservative and intentionally biased toward blocking obvious
  secrets access and risky execution patterns.

## Non-goals

- Pretending rule-based detection is complete protection
- Claiming host-level EDR coverage from API-only integration
- Allowing hidden side channels to bypass enforcement silently

## Security posture today

- Deterministic and explainable rules
- Local-only persistence in SQLite
- Explicit `allow` / `warn` / `block` responses
- Session-aware escalation for prompt injection and exfiltration chains

## Known gaps

- Static skill scanning can miss heavily obfuscated or staged payloads
- Path relevance checks are heuristic
- Domain allowlisting is static
- Frontend is an inspection UI, not an enforcement surface
- There is no signed rulepack or attestation workflow yet

