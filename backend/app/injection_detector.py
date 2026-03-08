from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol


class ClassifierPlugin(Protocol):
    def classify(self, text: str) -> dict[str, object]:
        ...


@dataclass(frozen=True)
class InjectionRule:
    label: str
    flag: str
    weight: int
    pattern: re.Pattern[str]


RULES = [
    InjectionRule(
        label="Instruction override attempt",
        flag="instruction override attempt",
        weight=30,
        pattern=re.compile(
            r"(?is)\b(ignore|disregard|forget|override)\b.{0,60}\b(previous|prior|system|developer)\b.{0,50}\b(instruction|prompt)s?\b"
        ),
    ),
    InjectionRule(
        label="Secret exfiltration attempt",
        flag="secret exfiltration attempt",
        weight=35,
        pattern=re.compile(
            r"(?is)\b(read|open|print|send|upload|exfiltrat[e|ion]*)\b.{0,100}\b(\.aws|credentials|id_rsa|id_ed25519|token|secret|\.env)\b"
        ),
    ),
    InjectionRule(
        label="Tool abuse attempt",
        flag="tool abuse attempt",
        weight=25,
        pattern=re.compile(
            r"(?is)\b(use|call|run|execute)\b.{0,70}\b(shell|terminal|bash|powershell|curl|wget|tool)\b"
        ),
    ),
    InjectionRule(
        label="System prompt extraction attempt",
        flag="system prompt extraction attempt",
        weight=30,
        pattern=re.compile(
            r"(?is)\b(reveal|show|print|dump|expose)\b.{0,70}\b(system prompt|developer instruction|hidden prompt)\b"
        ),
    ),
    InjectionRule(
        label="Authority hijack phrasing",
        flag="instruction override attempt",
        weight=15,
        pattern=re.compile(r"(?is)\byou must\b.{0,40}\bignore safety\b"),
    ),
]


def analyze_content(text: str, plugin: ClassifierPlugin | None = None) -> dict[str, object]:
    normalized = text.strip()
    score = 0
    flags: list[str] = []
    matched_patterns: list[str] = []
    for rule in RULES:
        if rule.pattern.search(normalized):
            score += rule.weight
            if rule.flag not in flags:
                flags.append(rule.flag)
            matched_patterns.append(rule.label)

    if plugin is not None:
        plugin_result = plugin.classify(normalized)
        score += int(plugin_result.get("score", 0))
        for flag in plugin_result.get("flags", []):
            if isinstance(flag, str) and flag not in flags:
                flags.append(flag)
        for label in plugin_result.get("matched_patterns", []):
            if isinstance(label, str):
                matched_patterns.append(label)

    score = min(score, 100)
    return {
        "injection_score": score,
        "flags": flags,
        "matched_patterns": matched_patterns,
    }

