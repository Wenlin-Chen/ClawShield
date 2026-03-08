from __future__ import annotations

import re
from pathlib import Path

SENSITIVE_PATH_MARKERS = [
    (re.compile(r"(^|/)\.ssh($|/)"), "SSH material"),
    (re.compile(r"(^|/)\.aws($|/)"), "AWS credentials"),
    (re.compile(r"(^|/)\.env(?:\.[^/]+)?$"), "dotenv secrets"),
    (re.compile(r"(^|/)(id_rsa|id_ed25519)$"), "private key"),
    (re.compile(r"(^|/)(cookies|cookies\.sqlite|login data|web data)$"), "browser session data"),
]

SENSITIVE_SOURCE_MARKERS = [
    (re.compile(r"(?i)(~\/\.ssh|\.ssh\/|id_rsa\b|id_ed25519\b)"), "SSH material"),
    (re.compile(r"(?i)(~\/\.aws|\.aws\/(?:credentials|config))"), "AWS credentials"),
    (re.compile(r"(?i)(^|[^A-Za-z0-9_])\.env(?:\.[A-Za-z0-9_.-]+)?($|[^A-Za-z0-9_])"), "dotenv secrets"),
    (re.compile(r"(?i)(cookies\.sqlite|login data|web data)"), "browser session data"),
]

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b")),
    ("Generic secret assignment", re.compile(r"(?i)\b(api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9/_+=.-]{8,}")),
]


def _path_variants(path_value: str) -> list[str]:
    raw = path_value.replace("\\", "/").lower()
    expanded = str(Path(path_value).expanduser()).replace("\\", "/").lower()
    return list(dict.fromkeys([raw, expanded]))


def match_sensitive_path(path_value: str) -> list[str]:
    matches: list[str] = []
    for variant in _path_variants(path_value):
        for pattern, label in SENSITIVE_PATH_MARKERS:
            if pattern.search(variant) and label not in matches:
                matches.append(label)
    return matches


def is_sensitive_path(path_value: str) -> bool:
    return bool(match_sensitive_path(path_value))


def detect_secrets(text: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            snippet = match.group(0)
            if len(snippet) > 48:
                snippet = f"{snippet[:24]}...{snippet[-8:]}"
            findings.append({"label": label, "evidence": snippet})
    return findings


def summarize_payload_secrets(text: str) -> list[str]:
    return [secret["label"] for secret in detect_secrets(text)]
