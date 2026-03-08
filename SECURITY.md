# Security Policy

`agent-shield` is itself a security product. Please report vulnerabilities
privately and do not publish exploit details in Issues, PRs, or Discussions
before a fix is available.

## Supported versions

Until `1.0.0`, only the latest tagged release is supported for security fixes.
The `main` branch may contain in-progress changes and should not be treated as a
stable deployment target.

## Reporting a vulnerability

Preferred channel:

- Use GitHub Private Vulnerability Reporting if the repository has it enabled.

Fallback channel:

- Contact the maintainers through a private contact method listed in the latest
  release notes or repository profile.

If neither private channel is available yet, open a minimal public issue asking
for a private contact route and do not include technical details, proofs of
concept, payloads, or impacted secrets.

## What to include

- A concise description of the issue
- Affected version or commit
- Reproduction steps
- Expected vs actual behavior
- Severity assessment and impact
- Whether sensitive data or credentials were involved
- Any suggested fix or mitigation

## Response targets

- Initial acknowledgement: within 3 business days
- Triage decision: within 7 business days
- Status updates: at least weekly for accepted reports

## Safe harbor

We appreciate good-faith research intended to improve user safety. Please avoid:

- Accessing someone else's data
- Exfiltrating or retaining secrets
- Running high-volume or destructive tests
- Public disclosure before coordination

## Disclosure policy

We prefer coordinated disclosure. Once a fix or mitigation is available,
maintainers should publish:

- affected versions
- fixed versions
- severity
- mitigation guidance
- acknowledgement for the reporter, if desired

