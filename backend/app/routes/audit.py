from __future__ import annotations

from fastapi import APIRouter, Query

from .. import db
from ..schemas import EventRecord, FindingRecord

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/events", response_model=list[EventRecord])
def get_events(limit: int = Query(default=100, le=500), session_id: str | None = None) -> list[EventRecord]:
    return db.list_events(limit=limit, session_id=session_id)


@router.get("/findings", response_model=list[FindingRecord])
def get_findings(
    limit: int = Query(default=100, le=500), session_id: str | None = None
) -> list[FindingRecord]:
    return db.list_findings(limit=limit, session_id=session_id)

