from __future__ import annotations

import os
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
    ClearHistoryResponse,
    ContentCheckRequest,
    ContentCheckResponse,
    DemoLoadResponse,
    FindingRecord,
    PolicyDecisionResponse,
    RuntimeEventRequest,
    SkillScanRequest,
    SkillScanResponse,
)
from ..skill_scanner import scan_skill_path

router = APIRouter(prefix="/api", tags=["security"])
REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _scan_roots() -> list[Path]:
    env_value = os.environ.get("CLAWSHIELD_SCAN_ROOTS", "").strip()
    if env_value:
        raw_roots = [segment.strip() for segment in env_value.split(",") if segment.strip()]
    else:
        raw_roots = [
            str(Path.home() / ".openclaw" / "skills"),
            str(Path.home() / ".openclaw" / "workspace" / "skills"),
            str(REPO_ROOT / "skills"),
            str(BACKEND_ROOT / "demo_skills"),
        ]

    roots: list[Path] = []
    for raw_root in raw_roots:
        resolved = Path(raw_root).expanduser().resolve()
        if resolved not in roots:
            roots.append(resolved)
    return roots


def _validate_scan_path(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    allowed_roots = _scan_roots()
    if any(_is_within_root(resolved, root) for root in allowed_roots):
        return resolved

    allowed_display = ", ".join(str(root) for root in allowed_roots)
    raise HTTPException(
        status_code=400,
        detail=(
            "Path-based skill scans are limited to configured scan roots. "
            f"Allowed roots: {allowed_display}"
        ),
    )


def _sanitize_upload_filename(filename: str) -> str:
    candidate = Path(filename)
    if candidate.is_absolute() or ".." in candidate.parts or any(sep in filename for sep in ("/", "\\")):
        raise HTTPException(status_code=400, detail="Uploaded filename must not contain path traversal sequences.")
    if not candidate.name:
        raise HTTPException(status_code=400, detail="Uploaded file must have a valid filename.")
    return candidate.name


def _is_zip_symlink(member: zipfile.ZipInfo) -> bool:
    return ((member.external_attr >> 16) & 0o170000) == 0o120000


def _extract_zip_safely(zip_path: Path, extract_root: Path) -> None:
    extract_root_resolved = extract_root.resolve()
    try:
        with zipfile.ZipFile(zip_path) as zip_handle:
            for member in zip_handle.infolist():
                member_path = Path(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise HTTPException(status_code=400, detail="Archive contains unsafe path traversal entries.")
                if _is_zip_symlink(member):
                    raise HTTPException(status_code=400, detail="Archive symlinks are not supported.")

                destination = (extract_root / member_path).resolve()
                if not _is_within_root(destination, extract_root_resolved):
                    raise HTTPException(status_code=400, detail="Archive extraction would escape the scan directory.")

                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue

                destination.parent.mkdir(parents=True, exist_ok=True)
                with zip_handle.open(member) as source, destination.open("wb") as target:
                    shutil.copyfileobj(source, target)
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Uploaded archive is not a valid zip file.") from exc


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
async def scan_skill(
    request: Request,
    upload: UploadFile | None = File(default=None),
    archive: UploadFile | None = File(default=None),
) -> SkillScanResponse:
    content_type = request.headers.get("content-type", "")
    scan_id = f"scan-{uuid4().hex[:8]}"

    if "application/json" in content_type:
        body = SkillScanRequest.model_validate(await request.json())
        if not body.path:
            raise HTTPException(status_code=400, detail="JSON request must include path.")
        try:
            result = scan_skill_path(_validate_scan_path(Path(body.path)), scan_id=scan_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        persist_scan_findings(result)
        return result

    incoming_file = upload or archive
    if incoming_file is None:
        raise HTTPException(status_code=400, detail="Provide either a JSON path or an uploaded zip or skill file.")
    if not incoming_file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

    with tempfile.TemporaryDirectory() as temp_dir:
        safe_filename = _sanitize_upload_filename(incoming_file.filename)
        upload_path = Path(temp_dir) / safe_filename
        with upload_path.open("wb") as file_handle:
            shutil.copyfileobj(incoming_file.file, file_handle)

        if safe_filename.lower().endswith(".zip"):
            extract_root = Path(temp_dir) / "extracted"
            _extract_zip_safely(upload_path, extract_root)
            try:
                result = scan_skill_path(extract_root, scan_id=scan_id)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            result.scanned_path = safe_filename
        else:
            try:
                result = scan_skill_path(upload_path, scan_id=scan_id)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            result.scanned_path = safe_filename
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


@router.post("/clear-history", response_model=ClearHistoryResponse)
def clear_history() -> ClearHistoryResponse:
    cleared_events = db.count_events()
    cleared_findings = db.count_findings()
    db.clear_all()
    return ClearHistoryResponse(
        message="Cleared stored audit events and findings.",
        cleared_events=cleared_events,
        cleared_findings=cleared_findings,
    )
