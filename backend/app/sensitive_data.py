from __future__ import annotations

import re
from pathlib import Path

SENSITIVE_PATH_MARKERS = [
    ("~/.ssh", "SSH material"),
    (".ssh/", "SSH material"),
    ("~/.aws", "AWS credentials"),
    (".aws/", "AWS credentials"),
    (".env", "dotenv secrets"),
    ("id_rsa", "private key"),
    ("id_ed25519", "private key"),
    ("browser", "browser profile data"),
    ("cookies", "session cookies"),
    ("tokens", "access tokens"),
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
        for marker, label in SENSITIVE_PATH_MARKERS:
            if marker.lower() in variant and label not in matches:
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

