from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Recommendation(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class EventType(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL_EXEC = "shell_exec"
    HTTP_REQUEST = "http_request"
    SEND_MESSAGE = "send_message"
    SKILL_INSTALL = "skill_install"

