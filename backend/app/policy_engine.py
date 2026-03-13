from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

from . import db
from .models import Decision, EventType, Severity
from .schemas import PolicyAlert, PolicyDecisionResponse, RuntimeEventRequest
from .sensitive_data import is_sensitive_path, match_sensitive_path, summarize_payload_secrets

DECISION_ORDER = {
    Decision.ALLOW: 0,
    Decision.WARN: 1,
    Decision.BLOCK: 2,
}

SAFE_DOMAINS = {"localhost", "127.0.0.1", "::1", "example.com"}
DANGEROUS_COMMAND_PATTERNS = [
    ("remote-pipe-exec", re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]{0,140}\|\s*(?:bash|sh)\b")),
    ("destructive-delete", re.compile(r"(?i)\brm\s+-rf\s+(?:/|~|/\*)")),
    ("netcat-shell", re.compile(r"(?i)\b(?:nc|ncat)\b.{0,80}\s-e\s")),
    ("bash-remote-payload", re.compile(r"(?i)\bbash\s+-c\b.{0,120}\b(?:curl|wget)\b")),
]


def strictest(current: Decision, candidate: Decision) -> Decision:
    return candidate if DECISION_ORDER[candidate] > DECISION_ORDER[current] else current


def extract_domain(event: RuntimeEventRequest) -> str | None:
    url_value = event.url or event.target_resource
    if not url_value.startswith(("http://", "https://")):
        return None
    return (urlparse(url_value).hostname or "").lower() or None


def task_is_relevant(task: str, target_resource: str) -> bool:
    task_lower = task.lower()
    target_lower = target_resource.lower()
    basename = target_lower.rsplit("/", maxsplit=1)[-1]
    hints = ["user-selected", "selected file", "local file", "document", "summary", "summarize"]
    return basename in task_lower or any(hint in task_lower for hint in hints)


def get_session_context(session_id: str | None) -> dict[str, bool]:
    if not session_id:
        return {"prompt_injection_seen": False, "sensitive_access_seen": False}

    findings = db.list_findings(limit=200, session_id=session_id)
    events = db.list_events(limit=200, session_id=session_id)
    prompt_injection_seen = any(
        finding.source_type == "prompt_injection" and finding.score >= 60 for finding in findings
    )
    sensitive_access_seen = any(is_sensitive_path(event.target_resource) for event in events)
    return {
        "prompt_injection_seen": prompt_injection_seen,
        "sensitive_access_seen": sensitive_access_seen,
    }


def shell_command_sensitive_labels(command: str) -> list[str]:
    labels: list[str] = []
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    for token in tokens:
        if token.startswith("-"):
            continue
        for label in match_sensitive_path(token):
            if label not in labels:
                labels.append(label)
    return labels


def evaluate_event(event: RuntimeEventRequest) -> PolicyDecisionResponse:
    decision = Decision.ALLOW
    reasons: list[str] = []
    matched_rules: list[str] = []
    context = get_session_context(event.session_id)

    if event.event_type in {EventType.FILE_READ, EventType.FILE_WRITE}:
        sensitive_labels = match_sensitive_path(event.target_resource)
        if sensitive_labels:
            decision = strictest(decision, Decision.BLOCK)
            reasons.append(f"Target matches sensitive location(s): {', '.join(sensitive_labels)}.")
            matched_rules.append("block-sensitive-paths")
        elif not task_is_relevant(event.task, event.target_resource):
            decision = strictest(decision, Decision.WARN)
            reasons.append("Target resource does not look clearly relevant to the stated task.")
            matched_rules.append("warn-low-task-relevance")

    if event.event_type == EventType.SHELL_EXEC:
        command = event.command or ""
        sensitive_labels = shell_command_sensitive_labels(command)
        if sensitive_labels:
            decision = strictest(decision, Decision.BLOCK)
            reasons.append(f"Shell command targets sensitive location(s): {', '.join(sensitive_labels)}.")
            matched_rules.append("block-shell-sensitive-paths")
        for rule_name, pattern in DANGEROUS_COMMAND_PATTERNS:
            if pattern.search(command):
                decision = strictest(decision, Decision.BLOCK)
                reasons.append("Shell command matches a high-risk execution pattern.")
                matched_rules.append(rule_name)
                break

    if event.event_type in {EventType.HTTP_REQUEST, EventType.SEND_MESSAGE}:
        domain = extract_domain(event)
        payload_secret_hits = summarize_payload_secrets(event.payload_excerpt or "")
        if payload_secret_hits:
            decision = strictest(decision, Decision.BLOCK)
            reasons.append(f"Outbound payload appears to contain secrets: {', '.join(payload_secret_hits)}.")
            matched_rules.append("block-sensitive-exfiltration")
        if domain and domain not in SAFE_DOMAINS:
            decision = strictest(decision, Decision.WARN)
            reasons.append(f"Outbound destination {domain} is not allowlisted.")
            matched_rules.append("warn-unknown-domain")
        if context["prompt_injection_seen"] and domain and domain not in SAFE_DOMAINS:
            decision = strictest(decision, Decision.BLOCK)
            reasons.append("Session already contains prompt injection signals; outbound action is escalated.")
            matched_rules.append("escalate-after-injection")
        elif context["prompt_injection_seen"]:
            decision = strictest(decision, Decision.WARN)
            reasons.append("Session contains prompt injection signals, increasing scrutiny.")
            matched_rules.append("warn-after-injection")
        if context["sensitive_access_seen"]:
            decision = strictest(decision, Decision.BLOCK)
            reasons.append("Session attempted sensitive file access before outbound activity.")
            matched_rules.append("block-sensitive-read-followed-by-egress")

    if event.event_type == EventType.SKILL_INSTALL and event.provenance.lower() != "local":
        decision = strictest(decision, Decision.WARN)
        reasons.append("Skill installation from non-local provenance requires pre-install review.")
        matched_rules.append("warn-untrusted-skill-install")

    if context["prompt_injection_seen"] and event.event_type in {EventType.FILE_READ, EventType.SHELL_EXEC}:
        decision = strictest(decision, Decision.WARN)
        reasons.append("Session contains prompt injection signals, so capability use is constrained.")
        matched_rules.append("warn-capability-drift-after-injection")

    alert = build_alert(event, decision, reasons)
    return PolicyDecisionResponse(
        decision=decision,
        reasons=reasons or ["No blocking policy matched."],
        matched_rules=matched_rules,
        alert=alert,
    )


def build_alert(
    event: RuntimeEventRequest, decision: Decision, reasons: list[str]
) -> PolicyAlert | None:
    if decision == Decision.ALLOW:
        return None
    severity = Severity.HIGH if decision == Decision.WARN else Severity.CRITICAL
    evidence = event.command or event.url or event.target_resource
    return PolicyAlert(
        title=f"{decision.value.upper()} {event.event_type.value}",
        severity=severity,
        description=" ".join(reasons),
        evidence=evidence,
    )
