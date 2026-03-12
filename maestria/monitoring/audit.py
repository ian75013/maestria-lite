"""Audit Logging — SIEM-Ready Event Logger.

Produces structured audit logs in Common Event Format (CEF) and JSON
for integration with SIEM platforms (Splunk, ELK, QRadar).

Compliance: FDA 21 CFR Part 11 (§11.10(e)) — audit trail requirements.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class AuditSeverity(Enum):
    INFO = 0
    LOW = 3
    MEDIUM = 5
    HIGH = 7
    CRITICAL = 10


class AuditCategory(Enum):
    AUTHENTICATION = "authentication"
    MESSAGE_PROCESSING = "message_processing"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_EVENT = "security_event"
    SYSTEM_LIFECYCLE = "system_lifecycle"
    DATA_ACCESS = "data_access"
    PATCH_MANAGEMENT = "patch_management"


@dataclass
class AuditRecord:
    """A structured audit record."""
    event_name: str
    category: AuditCategory
    severity: AuditSeverity
    source: str
    actor: str = "system"
    target: str = ""
    outcome: str = "success"
    details: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_json(self) -> str:
        return json.dumps({
            "timestamp": self.timestamp,
            "event_name": self.event_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "source": self.source,
            "actor": self.actor,
            "target": self.target,
            "outcome": self.outcome,
            "correlation_id": self.correlation_id,
            "details": self.details,
        })

    def to_cef(self) -> str:
        """Format as Common Event Format (CEF) string."""
        extensions = " ".join(
            f"{k}={v}" for k, v in {
                "src": self.source,
                "act": self.event_name,
                "suser": self.actor,
                "dst": self.target,
                "outcome": self.outcome,
                "cs1": self.correlation_id,
            }.items() if v
        )
        return (
            f"CEF:0|MAESTRIA|Middleware|2.4.1|{self.event_name}"
            f"|{self.category.value}|{self.severity.value}|{extensions}"
        )


class AuditLogger:
    """Centralized audit logger for regulatory compliance.

    All security-relevant events are logged with full context
    for traceability and forensic analysis.
    """

    def __init__(self, output_format: str = "json") -> None:
        self._format = output_format  # "json" or "cef"
        self._records: list[AuditRecord] = []
        self._max_records = 100_000

    def log(self, record: AuditRecord) -> None:
        """Log an audit record."""
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records:]

        formatted = (
            record.to_cef() if self._format == "cef" else record.to_json()
        )
        logger.info("audit", raw=formatted)

    def query(
        self,
        category: AuditCategory | None = None,
        severity_min: AuditSeverity = AuditSeverity.INFO,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """Query audit records with optional filters."""
        records = self._records
        if category:
            records = [r for r in records if r.category == category]
        records = [r for r in records if r.severity.value >= severity_min.value]
        return records[-limit:]

    @property
    def record_count(self) -> int:
        return len(self._records)
