# Roadmap

## Near-term

- Add configurable security modes such as `monitor`, `balanced`, and `strict`
- Add interactive user approval for risky actions so `warn` and selected `block`
  events can prompt the user to allow or deny execution based on the active
  security mode
- Add configurable policy overrides and domain allowlists
- Add a non-code rule editor so non-developer users can add or tune allowlists,
  blocked paths, blocked commands, and custom detection patterns without
  editing Python files
- Publish and harden the OpenClaw plugin with broader hook coverage
- Add first-class skill lifecycle interception if OpenClaw exposes a documented hook
- Expand secret detection coverage with provider-specific patterns
- Add session filtering and detail drill-down in the audit console
- Add better audit search, filtering, and export for incident review
- Add setup validation and onboarding checks so users can verify plugin config,
  backend reachability, and tool-name mappings before first use

## Mid-term

- Add policy import/export and versioned rule bundles
- Add per-project and per-agent policy profiles
- Add signed scan attestations for skills and updates
- Track capability drift between skill versions
- Add richer outbound payload inspection and correlation across sessions
- Support streaming and inline enforcement for long-running tool flows
- Add optional desktop notifications or in-app alerts for newly blocked actions
- Add packaged installers and easier upgrade paths for backend, frontend, and
  OpenClaw plugin distribution

## Long-term

- Add optional LLM-assisted risk judgment for actions, content, and skills,
  with clear rationale, confidence reporting, and deterministic-rule fallback
- Add pluggable classifiers for prompt injection scoring
- Add host telemetry adapters for filesystem and process monitoring
- Publish a stable policy SDK for other agent frameworks
- Provide a benchmark corpus for detection quality and false-positive tracking
- Add policy simulation and replay tooling so users can test rule changes
  against historical events before enforcing them
- Add compatibility testing across OpenClaw versions and supported tool
  inventories

## Product-readiness priorities

- Make risky-action approvals auditable so every allow or deny decision is
  stored with timestamp, user choice, reason, and session context
- Add migration-safe config storage for user-defined rules and security modes
- Add backup and restore for policy configuration and audit history
- Add clearer error handling when the backend is unavailable, including explicit
  fail-open and fail-closed user guidance
- Add performance budgets and profiling for large audit histories and high tool
  event volume
- Add release validation for docs, plugin behavior, backend API compatibility,
  and upgrade paths
