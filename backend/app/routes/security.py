from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from .. import db
from ..injection_detector import analyze_content
from ..models import Decision, Recommendation, Severity
from ..policy_engine import evaluate_event
from ..sample_data import load_sample_data
from ..schemas import (
    ContentCheckRequest,
    ContentCheckResponse,
    DemoLoadResponse,
    FindingRecord,
    PolicyDecisionResponse,
    RuntimeEventRequest,
    SkillScanRequest,
    SkillScanResponse,
)
from ..skill_scanner import scan_skill_directory

router = APIRouter(prefix="/api", tags=["security"])


def persist_scan_findings(result: SkillScanResponse) -> None:
    for finding in result.findings:
        db.insert_finding(
            FindingRecord(
                reference_id=result.scan_id,
                source_type="skill_scan",
                category=finding.category,
                severity=finding.severity,
                title=finding.title,
                description="Detected risky skill behavior during pre-install scan.",
                evidence=finding.evidence,
                related_resource=finding.file_path,
                score=finding.score,
                recommendation=result.recommendation,
            )
        )


def persist_policy_alert(event: RuntimeEventRequest, response: PolicyDecisionResponse) -> None:
    if response.alert is None:
        return
    db.insert_finding(
        FindingRecord(
            session_id=event.session_id,
            source_type="policy_alert",
            category="runtime_policy",
            severity=response.alert.severity,
            title=response.alert.title,
            description=response.alert.description,
            evidence=response.alert.evidence,
            related_resource=event.target_resource,
            score=90 if response.decision == Decision.BLOCK else 60,
            recommendation=Recommendation(response.decision.value),
        )
    )


@router.post("/scan-skill", response_model=SkillScanResponse)
async def scan_skill(request: Request, archive: UploadFile | None = File(default=None)) -> SkillScanResponse:
    content_type = request.headers.get("content-type", "")
    scan_id = f"scan-{uuid4().hex[:8]}"

    if "application/json" in content_type:
        body = SkillScanRequest.model_validate(await request.json())
        if not body.path:
            raise HTTPException(status_code=400, detail="JSON request must include path.")
        result = scan_skill_directory(Path(body.path).expanduser(), scan_id=scan_id)
        persist_scan_findings(result)
        return result

    if archive is None:
        raise HTTPException(status_code=400, detail="Provide either a JSON path or a zip upload.")
    if not archive.filename or not archive.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only zip archives are supported for upload.")

    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = Path(temp_dir) / archive.filename
        with archive_path.open("wb") as file_handle:
            shutil.copyfileobj(archive.file, file_handle)
        extract_root = Path(temp_dir) / "extracted"
        with zipfile.ZipFile(archive_path) as zip_handle:
            zip_handle.extractall(extract_root)
        scan_root = next(iter(sorted(extract_root.iterdir())), extract_root)
        result = scan_skill_directory(scan_root, scan_id=scan_id)
        persist_scan_findings(result)
        return result


@router.post("/evaluate-event", response_model=PolicyDecisionResponse)
def evaluate_runtime_event(event: RuntimeEventRequest) -> PolicyDecisionResponse:
    response = evaluate_event(event)
    db.insert_event(event, response.decision, response.reasons, response.matched_rules)
    persist_policy_alert(event, response)
    return response


@router.post("/check-content", response_model=ContentCheckResponse)
def check_content(payload: ContentCheckRequest) -> ContentCheckResponse:
    result = analyze_content(payload.text)
    check_id = f"check-{uuid4().hex[:8]}"
    if result["injection_score"] >= 35:
        severity = Severity.CRITICAL if result["injection_score"] >= 70 else Severity.HIGH
        db.insert_finding(
            FindingRecord(
                reference_id=check_id,
                session_id=payload.session_id,
                source_type="prompt_injection",
                category="prompt_injection",
                severity=severity,
                title="Prompt injection content detected",
                description=", ".join(result["flags"]) or "Suspicious external content detected.",
                evidence=payload.text[:500],
                related_resource=payload.source,
                score=int(result["injection_score"]),
                recommendation=Recommendation.BLOCK if result["injection_score"] >= 70 else Recommendation.WARN,
            )
        )
    return ContentCheckResponse(
        check_id=check_id,
        injection_score=int(result["injection_score"]),
        flags=list(result["flags"]),
        matched_patterns=list(result["matched_patterns"]),
    )


@router.post("/demo/load-sample-data", response_model=DemoLoadResponse)
def load_demo() -> DemoLoadResponse:
    return load_sample_data()

