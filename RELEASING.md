# Releasing ClawShield

This project uses Semantic Versioning.

## Release checklist

1. Ensure CI is green.
2. Update [CHANGELOG.md](CHANGELOG.md).
3. Confirm [README.md](README.md), [SECURITY.md](SECURITY.md),
   [docs/openclaw-integration.md](docs/openclaw-integration.md), and
   [docs/policy-reference.md](docs/policy-reference.md) reflect the current
   API, defaults, and rule set.
4. Tag the release as `vX.Y.Z`.
5. Publish release notes with:
   - major changes
   - breaking changes
   - security-impacting fixes
   - migration notes
6. If the event schema changed, note compatibility expectations explicitly.

## Versioning guidance

- Patch: fixes, doc updates, rule tuning without API breakage
- Minor: backward-compatible features or new optional fields
- Major: breaking API, schema, policy-contract, or runtime behavior changes
