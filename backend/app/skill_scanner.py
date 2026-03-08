from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Recommendation, Severity
from .schemas import ScanFinding, SkillScanResponse
from .sensitive_data import SENSITIVE_SOURCE_MARKERS

TEXT_SUFFIXES = {
    "",
    ".py",
    ".sh",
    ".ps1",
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".js",
    ".ts",
}


@dataclass(frozen=True)
class ScannerRule:
    category: str
    title: str
    severity: Severity
    score: int
    pattern: re.Pattern[str]


SCANNER_RULES = [
    ScannerRule(
        category="network",
        title="Downloads and executes remote script",
        severity=Severity.CRITICAL,
        score=35,
        pattern=re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]{0,140}\|\s*(?:bash|sh)\b"),
    ),
    ScannerRule(
        category="execution",
        title="Uses subprocess with shell=True",
        severity=Severity.HIGH,
        score=25,
        pattern=re.compile(r"subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True"),
    ),
    ScannerRule(
        category="execution",
        title="Uses os.system",
        severity=Severity.HIGH,
        score=25,
        pattern=re.compile(r"\bos\.system\s*\("),
    ),
    ScannerRule(
        category="execution",
        title="Uses dynamic code execution",
        severity=Severity.HIGH,
        score=20,
        pattern=re.compile(r"\b(?:eval|exec)\s*\("),
    ),
    ScannerRule(
        category="obfuscation",
        title="Decodes base64 content",
        severity=Severity.MEDIUM,
        score=15,
        pattern=re.compile(r"base64\.(?:b64decode|urlsafe_b64decode)\s*\("),
    ),
    ScannerRule(
        category="network",
        title="Makes outbound HTTP requests",
        severity=Severity.MEDIUM,
        score=10,
        pattern=re.compile(r"(?i)\b(?:requests|httpx)\.(?:get|post|put|delete)\s*\(|https?://"),
    ),
]


def _should_scan(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in TEXT_SUFFIXES and path.stat().st_size <= 512_000


def _risk_recommendation(score: int, findings: list[ScanFinding]) -> Recommendation:
    if score >= 70 or any(finding.severity == Severity.CRITICAL for finding in findings):
        return Recommendation.BLOCK
    if score >= 30:
        return Recommendation.WARN
    return Recommendation.ALLOW


def _scan_file(file_path: Path, findings: list[ScanFinding]) -> None:
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines() or [content]

    for line_number, line in enumerate(lines, start=1):
        for rule in SCANNER_RULES:
            if rule.pattern.search(line):
                findings.append(
                    ScanFinding(
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.title,
                        evidence=line.strip(),
                        file_path=str(file_path),
                        line_number=line_number,
                        score=rule.score,
                    )
                )
        for pattern, label in SENSITIVE_SOURCE_MARKERS:
            if pattern.search(line):
                findings.append(
                    ScanFinding(
                        category="sensitive_access",
                        severity=Severity.HIGH,
                        title=f"References sensitive location: {label}",
                        evidence=line.strip(),
                        file_path=str(file_path),
                        line_number=line_number,
                        score=20,
                    )
                )

    if "base64.b64decode" in content and re.search(r"\b(?:eval|exec|os\.system|subprocess\.)", content):
        findings.append(
            ScanFinding(
                category="obfuscation",
                severity=Severity.CRITICAL,
                title="Combines base64 decode with code execution",
                evidence="base64 decode combined with dynamic execution primitives",
                file_path=str(file_path),
                line_number=None,
                score=30,
            )
        )


def _collect_scannable_files(path: Path) -> list[Path]:
    if not path.exists():
        raise FileNotFoundError(f"Skill path does not exist: {path}")
    if path.is_file():
        if path.is_symlink():
            raise ValueError(f"Skill file symlinks are not supported: {path}")
        if not _should_scan(path):
            raise ValueError(f"Skill file type is not supported for scanning: {path}")
        return [path]
    if path.is_dir():
        files_to_scan: list[Path] = []
        for file_path in sorted(path.rglob("*")):
            if file_path.is_symlink():
                raise ValueError(f"Skill directories containing symlinks are not supported: {file_path}")
            if _should_scan(file_path):
                files_to_scan.append(file_path)
        return files_to_scan
    raise FileNotFoundError(f"Skill path is not a regular file or directory: {path}")


def scan_skill_path(path: Path, scan_id: str) -> SkillScanResponse:
    files_to_scan = _collect_scannable_files(path)
    findings: list[ScanFinding] = []

    for file_path in files_to_scan:
        _scan_file(file_path, findings)

    score = min(sum(finding.score for finding in findings), 100)
    recommendation = _risk_recommendation(score, findings)
    return SkillScanResponse(
        scan_id=scan_id,
        scanned_path=str(path),
        scanned_files=len(files_to_scan),
        score=score,
        recommendation=recommendation,
        findings=findings,
    )


def scan_skill_directory(path: Path, scan_id: str) -> SkillScanResponse:
    return scan_skill_path(path, scan_id=scan_id)
