from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Decision, EventType, Recommendation, Severity
from .schemas import EventRecord, FindingRecord, RuntimeEventRequest

APP_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = APP_ROOT / "data" / "clawshield.db"


def get_db_path() -> Path:
    env_path = os.environ.get("CLAWSHIELD_DB_PATH")
    return Path(env_path).expanduser() if env_path else DEFAULT_DB_PATH


def _json(value: Any, default: Any) -> str:
    return json.dumps(value if value is not None else default)


def _parse_json(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


def get_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                task TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                provenance TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                command TEXT,
                url TEXT,
                payload_excerpt TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                decision TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                matched_rules_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference_id TEXT,
                session_id TEXT,
                source_type TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                related_resource TEXT,
                score INTEGER NOT NULL DEFAULT 0,
                recommendation TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
            """
        )


def clear_all() -> None:
    with get_connection() as connection:
        connection.execute("DELETE FROM events")
        connection.execute("DELETE FROM findings")
        connection.commit()


def count_events(session_id: str | None = None) -> int:
    query = "SELECT COUNT(*) FROM events {where_clause}"
    params: list[Any] = []
    where_clause = ""
    if session_id:
        where_clause = "WHERE session_id = ?"
        params.append(session_id)
    with get_connection() as connection:
        row = connection.execute(query.format(where_clause=where_clause), params).fetchone()
    return int(row[0] if row else 0)


def count_findings(session_id: str | None = None) -> int:
    query = "SELECT COUNT(*) FROM findings {where_clause}"
    params: list[Any] = []
    where_clause = ""
    if session_id:
        where_clause = "WHERE session_id = ?"
        params.append(session_id)
    with get_connection() as connection:
        row = connection.execute(query.format(where_clause=where_clause), params).fetchone()
    return int(row[0] if row else 0)


def insert_event(
    event: RuntimeEventRequest,
    decision: Decision,
    reasons: list[str],
    matched_rules: list[str],
) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (
                session_id, event_type, actor, task, target_resource, provenance,
                timestamp, command, url, payload_excerpt, metadata_json,
                decision, reasons_json, matched_rules_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.session_id,
                event.event_type.value,
                event.actor,
                event.task,
                event.target_resource,
                event.provenance,
                event.timestamp.isoformat(),
                event.command,
                event.url,
                event.payload_excerpt,
                _json(event.metadata, {}),
                decision.value,
                _json(reasons, []),
                _json(matched_rules, []),
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def insert_finding(finding: FindingRecord) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO findings (
                reference_id, session_id, source_type, category, severity,
                title, description, evidence, related_resource, score,
                recommendation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.reference_id,
                finding.session_id,
                finding.source_type,
                finding.category,
                finding.severity.value,
                finding.title,
                finding.description,
                finding.evidence,
                finding.related_resource,
                finding.score,
                finding.recommendation.value if finding.recommendation else None,
            ),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_events(limit: int = 100, session_id: str | None = None) -> list[EventRecord]:
    query = """
        SELECT * FROM events
        {where_clause}
        ORDER BY datetime(timestamp) DESC, id DESC
        LIMIT ?
    """
    params: list[Any] = []
    where_clause = ""
    if session_id:
        where_clause = "WHERE session_id = ?"
        params.append(session_id)
    params.append(limit)
    with get_connection() as connection:
        rows = connection.execute(query.format(where_clause=where_clause), params).fetchall()
    return [
        EventRecord(
            id=row["id"],
            session_id=row["session_id"],
            event_type=EventType(row["event_type"]),
            actor=row["actor"],
            task=row["task"],
            target_resource=row["target_resource"],
            provenance=row["provenance"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            command=row["command"],
            url=row["url"],
            payload_excerpt=row["payload_excerpt"],
            metadata=_parse_json(row["metadata_json"], {}),
            decision=Decision(row["decision"]),
            reasons=_parse_json(row["reasons_json"], []),
            matched_rules=_parse_json(row["matched_rules_json"], []),
            created_at=datetime.fromisoformat(row["created_at"].replace(" ", "T")),
        )
        for row in rows
    ]


def list_findings(limit: int = 100, session_id: str | None = None) -> list[FindingRecord]:
    query = """
        SELECT * FROM findings
        {where_clause}
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT ?
    """
    params: list[Any] = []
    where_clause = ""
    if session_id:
        where_clause = "WHERE session_id = ?"
        params.append(session_id)
    params.append(limit)
    with get_connection() as connection:
        rows = connection.execute(query.format(where_clause=where_clause), params).fetchall()
    return [
        FindingRecord(
            id=row["id"],
            reference_id=row["reference_id"],
            session_id=row["session_id"],
            source_type=row["source_type"],
            category=row["category"],
            severity=Severity(row["severity"]),
            title=row["title"],
            description=row["description"],
            evidence=row["evidence"],
            related_resource=row["related_resource"],
            score=row["score"],
            recommendation=Recommendation(row["recommendation"]) if row["recommendation"] else None,
            created_at=datetime.fromisoformat(row["created_at"].replace(" ", "T")),
        )
        for row in rows
    ]
