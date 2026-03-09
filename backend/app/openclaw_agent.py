from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib import error, request

from .models import Recommendation, Severity
from .schemas import ScanFinding

MAX_FILES = 25
MAX_FILE_CHARS = 6_000


@dataclass(frozen=True)
class OpenClawAgentConfig:
    endpoint: str
    model: str
    api_key: str | None = None


def _load_config() -> OpenClawAgentConfig:
    endpoint = os.environ.get("OPENCLAW_AGENT_URL", "").strip()
    model = os.environ.get("OPENCLAW_AGENT_MODEL", "").strip()
    api_key = os.environ.get("OPENCLAW_AGENT_API_KEY", "").strip() or None

    if not endpoint or not model:
        raise RuntimeError(
            "OpenCLAW agent mode requires OPENCLAW_AGENT_URL and OPENCLAW_AGENT_MODEL environment variables."
        )

    return OpenClawAgentConfig(endpoint=endpoint, model=model, api_key=api_key)


def _build_prompt(files_to_scan: list[Path]) -> str:
    chunks: list[str] = []
    for file_path in files_to_scan[:MAX_FILES]:
        content = file_path.read_text(encoding="utf-8", errors="ignore")[:MAX_FILE_CHARS]
        chunks.append(f"## File: {file_path}\n{content}")

    file_manifest = "\n".join(f"- {path}" for path in files_to_scan[:MAX_FILES])

    combined_chunks = "\n\n".join(chunks)

    return (
        "You are OpenCLAW security reviewer. Analyze these skill files for malware, hidden exfiltration, "
        "prompt injection scaffolding, or dangerous installer behavior.\n"
        "Return STRICT JSON with this schema only:\n"
        "{\n"
        '  "recommendation": "allow|warn|block",\n'
        '  "summary": "short sentence",\n'
        '  "findings": [{"title": "...", "severity": "low|medium|high|critical", "category": "...", '
        '"evidence": "...", "file_path": "...", "line_number": null}]\n'
        "}\n"
        "Never include markdown.\n"
        f"Files:\n{file_manifest}\n\n"
        f"Content excerpts:\n{combined_chunks}"
    )


def _as_severity(value: str) -> Severity:
    lowered = value.strip().lower()
    if lowered in {"low", "medium", "high", "critical"}:
        return Severity(lowered)
    return Severity.MEDIUM


def _as_recommendation(value: str) -> Recommendation:
    lowered = value.strip().lower()
    if lowered in {"allow", "warn", "block"}:
        return Recommendation(lowered)
    return Recommendation.WARN


def _score_for_severity(severity: Severity) -> int:
    return {
        Severity.LOW: 5,
        Severity.MEDIUM: 15,
        Severity.HIGH: 25,
        Severity.CRITICAL: 35,
    }[severity]


def analyze_with_openclaw(files_to_scan: list[Path]) -> tuple[Recommendation, list[ScanFinding], str]:
    config = _load_config()
    prompt = _build_prompt(files_to_scan)
    body = {
        "model": config.model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You are OpenCLAW malware analyst."},
            {"role": "user", "content": prompt},
        ],
    }

    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"

    req = request.Request(
        config.endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=45) as response:
            raw = json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        raise RuntimeError(f"OpenCLAW agent request failed: {exc}") from exc

    content = raw["choices"][0]["message"]["content"]
    payload = json.loads(content)

    summary = str(payload.get("summary", "OpenCLAW agent completed analysis.")).strip()
    recommendation = _as_recommendation(str(payload.get("recommendation", "warn")))

    findings: list[ScanFinding] = []
    for finding in payload.get("findings", []):
        severity = _as_severity(str(finding.get("severity", "medium")))
        findings.append(
            ScanFinding(
                title=str(finding.get("title", "OpenCLAW agent finding")),
                severity=severity,
                category=str(finding.get("category", "openclaw_agent")),
                evidence=str(finding.get("evidence", "No evidence provided by OpenCLAW agent.")),
                file_path=str(finding.get("file_path", files_to_scan[0] if files_to_scan else "")),
                line_number=finding.get("line_number"),
                score=_score_for_severity(severity),
            )
        )

    return recommendation, findings, summary
