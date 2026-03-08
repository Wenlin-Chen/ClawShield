# Agent Shield

`agent-shield` is a local agent antivirus / agent EDR wrapper for OpenClaw-like
agents. It scans risky skills before install, evaluates sensitive runtime tool
calls before execution, detects prompt injection in untrusted content, and keeps
an audit trail of alerts and blocked actions.

> [!WARNING]
> **Experimental software:** `agent-shield` is an early-stage experimental
> project. It is not production-ready, it has known detection gaps, and it
> should not be relied on as a sole security control for protecting sensitive
> systems or data.

![agent-shield preview](docs/preview.svg)

## Why this exists

OpenClaw-style local agents are powerful because they can read files, call tools,
execute shell commands, and install extensions or skills. Those same capabilities
create a clear local security gap:

- a malicious skill can hide risky install or runtime behavior
- a webpage or document can try to override the agent's instructions
- a summarization task can drift into secret access or outbound exfiltration
- users need a local, inspectable control plane instead of opaque "trust me"
  agent safety

`agent-shield` is meant to be that control plane for local development and
experimentation.

## What it protects against

- Malicious or obviously risky skills before install
- Prompt injection attempts in external content
- Unauthorized reads of sensitive paths such as `~/.ssh`, `~/.aws`, and `.env`
- High-risk shell commands such as `curl | bash`
- Suspicious outbound requests and secret-bearing payloads
- Multi-step attack chains within a single agent session

## What it does not protect against

- Kernel- or OS-level malware
- Perfect detection of obfuscated or novel attacks
- Agents that never call the broker before privileged actions
- Full host telemetry or process-tree EDR coverage

Read the fuller threat model in [docs/threat-model.md](docs/threat-model.md).

## Stack

- `backend/`: FastAPI, stdlib `sqlite3`, pytest
- `frontend/`: React, Vite, TypeScript
- Storage: local SQLite database at `backend/data/agent_shield.db`

## 60-second quickstart

### Local native setup

```bash
make install
make run-backend
make run-frontend
```

Backend:

- API: [http://localhost:8000](http://localhost:8000)
- Docs: [http://localhost:8000/docs](http://localhost:8000/docs)

Frontend:

- UI: [http://localhost:5173](http://localhost:5173)

### Docker setup

```bash
docker compose up --build
```

Docker ports:

- Backend: `8000`
- Frontend preview: `4173`

## OpenClaw integration story

The intended integration flow is:

1. `POST /api/scan-skill` before skill install or update
2. `POST /api/check-content` before letting external text influence tool use
3. `POST /api/evaluate-event` before file, shell, network, or skill actions
4. Honor `allow`, `warn`, and `block` at the agent runtime boundary

Start with [docs/openclaw-integration.md](docs/openclaw-integration.md) for the
event contract and enforcement flow.

## Key files

```text
.
├── Makefile
├── backend/
│   ├── app/
│   │   ├── db.py
│   │   ├── injection_detector.py
│   │   ├── main.py
│   │   ├── policy_engine.py
│   │   ├── sample_data.py
│   │   ├── schemas.py
│   │   ├── sensitive_data.py
│   │   ├── skill_scanner.py
│   │   ├── routes/
│   │   └── tests/
│   ├── demo_skills/
│   └── requirements.txt
└── frontend/
    ├── package.json
    ├── src/
    │   ├── api/
    │   ├── components/
    │   ├── pages/
    │   └── types/
    └── vite.config.ts
```

## Features

- Skill scanner for risky code patterns such as `curl | bash`, `shell=True`, `os.system`, base64 decode plus execution, sensitive path access, and outbound HTTP calls
- Runtime policy broker for `file_read`, `file_write`, `shell_exec`, `http_request`, `send_message`, and `skill_install`
- Prompt injection firewall with rule-based scoring and flagging
- Sensitive data guardian for sensitive paths and common secret formats
- Audit console showing findings, decisions, blocked actions, and session timeline

## Useful commands

```bash
make install
make test-backend
make build-frontend
make check
make docker-up
```

## Demo scenarios included

1. Malicious skill install with `curl | bash`, `shell=True`, and `~/.ssh/id_rsa` access
2. Prompt injection content that attempts to override instructions, extract secrets, and trigger outbound exfiltration
3. Runtime policy blocking sensitive file access and suspicious outbound network
4. Benign local summarizer flow for a user-selected file

Use the dashboard button to load sample data, then inspect the seeded sessions in the audit console.

## API endpoints

- `POST /api/scan-skill`
- `POST /api/evaluate-event`
- `POST /api/check-content`
- `GET /api/events`
- `GET /api/findings`
- `POST /api/demo/load-sample-data`

## Limitations

- Detection is rule-based and deterministic; it does not execute sandboxed skills or trace real process/network activity.
- The policy engine uses lightweight task relevance heuristics and a static allowlist for outbound domains.
- Archive support is limited to zip uploads.
- Frontend coverage is manual only; tests focus on backend logic and API smoke paths.

## Documentation

- [docs/openclaw-integration.md](docs/openclaw-integration.md)
- [docs/policy-reference.md](docs/policy-reference.md)
- [docs/threat-model.md](docs/threat-model.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ROADMAP.md](ROADMAP.md)
- [RELEASING.md](RELEASING.md)

## Community

- Bugs and actionable product issues belong in GitHub Issues.
- Usage questions and design discussion should go to GitHub Discussions once the
  repository enables Discussions in repo settings.
- Sensitive findings should follow [SECURITY.md](SECURITY.md), not public issues.

## Release and versioning

This project aims to follow Semantic Versioning. Release notes live in
[CHANGELOG.md](CHANGELOG.md).

## Suggested next steps for maintainers

1. Add real filesystem/network hooks around the target agent runtime.
2. Expand the secret detector with entropy-based and provider-specific patterns.
3. Attach signed scan attestations to skill install workflows.
4. Add session drill-down filters and richer forensics in the dashboard.
