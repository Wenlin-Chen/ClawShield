from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from .models import Decision, EventType, Recommendation, Severity


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanFinding(BaseModel):
    category: str
    severity: Severity
    title: str
    evidence: str
    file_path: str
    line_number: int | None = None
    score: int = 0


class SkillScanRequest(BaseModel):
    path: str | None = None


class SkillScanResponse(BaseModel):
    scan_id: str
    scanned_path: str
    scanned_files: int
    score: int
    recommendation: Recommendation
    findings: list[ScanFinding] = Field(default_factory=list)


class RuntimeEventRequest(BaseModel):
    event_type: EventType
    actor: str
    task: str
    target_resource: str
    provenance: str
    timestamp: datetime = Field(default_factory=utc_now)
    session_id: str | None = None
    command: str | None = None
    url: str | None = None
    payload_excerpt: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyAlert(BaseModel):
    title: str
    severity: Severity
    description: str
    evidence: str


class PolicyDecisionResponse(BaseModel):
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    alert: PolicyAlert | None = None


class ContentCheckRequest(BaseModel):
    text: str
    session_id: str | None = None
    source: str | None = None


class ContentCheckResponse(BaseModel):
    check_id: str
    injection_score: int
    flags: list[str] = Field(default_factory=list)
    matched_patterns: list[str] = Field(default_factory=list)


class FindingRecord(BaseModel):
    id: int | None = None
    reference_id: str | None = None
    session_id: str | None = None
    source_type: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str
    related_resource: str | None = None
    score: int = 0
    recommendation: Recommendation | None = None
    created_at: datetime | None = None


class EventRecord(BaseModel):
    id: int
    session_id: str | None = None
    event_type: EventType
    actor: str
    task: str
    target_resource: str
    provenance: str
    timestamp: datetime
    command: str | None = None
    url: str | None = None
    payload_excerpt: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    created_at: datetime


class DemoLoadResponse(BaseModel):
    message: str
    inserted_events: int
    inserted_findings: int
    sample_sessions: list[str] = Field(default_factory=list)

