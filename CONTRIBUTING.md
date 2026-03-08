# Contributing to agent-shield

Thanks for contributing. This project is aimed at practical local defenses for
OpenClaw-like agents, so changes should optimize for clear security value,
predictable behavior, and easy local reproduction.

## Before you start

- Read [README.md](README.md) for the product overview and quickstart.
- Read [SECURITY.md](SECURITY.md) before reporting anything security-sensitive.
- Review [docs/openclaw-integration.md](docs/openclaw-integration.md) if your
  change affects runtime event handling.
- Review [docs/policy-reference.md](docs/policy-reference.md) if your change
  adds or alters policy rules.

## Local setup

```bash
make backend-install
make frontend-install
```

Optional reproducible setup:

```bash
docker compose up --build
```

## Development workflow

1. Create a focused branch.
2. Make the smallest coherent change that solves the problem.
3. Add or update tests for behavioral changes.
4. Update docs when APIs, defaults, or threat-model assumptions change.
5. Run local checks before opening a PR.

## Required checks

```bash
make test-backend
make build-frontend
```

If you change backend import or packaging behavior, also run:

```bash
python3 -m compileall backend/app
```

## Contribution guidelines

- Prefer small, reviewable PRs.
- Keep security rules deterministic unless there is a strong reason not to.
- Favor explicit allow/warn/block behavior over fuzzy heuristics.
- Add fixtures for both malicious and benign behavior when extending detection.
- Do not introduce external SaaS dependencies for core MVP paths.
- Do not include secrets, tokens, private keys, or real user data in tests.

## Adding or changing rules

When changing the scanner, prompt injection detector, or policy engine:

- Document the new rule in [docs/policy-reference.md](docs/policy-reference.md).
- Add at least one positive test and one false-positive guard.
- Include representative evidence strings in fixtures or tests.
- Explain the operational tradeoff in the PR description.

## Pull request expectations

- Summarize the user-facing impact.
- Note any schema, API, or rule changes.
- List new tests or manual verification steps.
- Call out residual risk or follow-up work if the change is intentionally partial.

## Discussions and support

Use GitHub Discussions for usage questions and design conversations once the
repository enables Discussions. Until then, keep Issues focused on actionable
bugs, feature work, and rule improvements.

