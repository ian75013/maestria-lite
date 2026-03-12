"""CVE Vulnerability Tracker.

Tracks, assesses, and manages security vulnerabilities (CVEs)
affecting the middleware and its dependencies. Integrates with
NVD (National Vulnerability Database) data and produces reports
for compliance with IEC 62443 and ISO 27001.

Lifecycle: Detection → Assessment → Prioritization → Remediation → Verification
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class CVSSVersion(Enum):
    V3_1 = "3.1"
    V4_0 = "4.0"


class CVESeverity(Enum):
    CRITICAL = "critical"   # CVSS 9.0-10.0
    HIGH = "high"           # CVSS 7.0-8.9
    MEDIUM = "medium"       # CVSS 4.0-6.9
    LOW = "low"             # CVSS 0.1-3.9
    NONE = "none"           # CVSS 0.0

    @classmethod
    def from_score(cls, score: float) -> CVESeverity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 0.1:
            return cls.LOW
        return cls.NONE


class CVEStatus(Enum):
    OPEN = "open"
    IN_ANALYSIS = "in_analysis"
    RISK_ACCEPTED = "risk_accepted"
    IN_REMEDIATION = "in_remediation"
    MITIGATED = "mitigated"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"
    DEFERRED = "deferred"


class RemediationAction(Enum):
    PATCH = "patch"
    UPGRADE = "upgrade"
    CONFIGURATION = "configuration"
    WORKAROUND = "workaround"
    COMPENSATING_CONTROL = "compensating_control"
    ACCEPT_RISK = "accept_risk"


@dataclass
class CVEEntry:
    """A tracked CVE vulnerability.

    Attributes:
        cve_id: CVE identifier (e.g., CVE-2024-12345).
        title: Brief vulnerability description.
        description: Detailed description.
        cvss_score: CVSS base score (0.0-10.0).
        severity: Derived severity level.
        affected_component: Software component affected.
        affected_versions: Version range(s) affected.
        status: Current remediation status.
        detected_at: When the vulnerability was first detected.
        remediation: Planned remediation action.
        due_date: Target remediation date.
        assignee: Person/team responsible.
        references: External reference URLs.
        notes: Internal analysis notes.
    """
    cve_id: str
    title: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_version: CVSSVersion = CVSSVersion.V3_1
    severity: CVESeverity = CVESeverity.NONE
    vector_string: str = ""
    affected_component: str = ""
    affected_versions: list[str] = field(default_factory=list)
    fixed_version: str | None = None
    status: CVEStatus = CVEStatus.OPEN
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    remediation: RemediationAction | None = None
    remediation_notes: str = ""
    due_date: str | None = None
    assignee: str = ""
    references: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity == CVESeverity.NONE and self.cvss_score > 0:
            self.severity = CVESeverity.from_score(self.cvss_score)

    @property
    def is_overdue(self) -> bool:
        if not self.due_date:
            return False
        due = datetime.fromisoformat(self.due_date)
        return datetime.now(timezone.utc) > due

    @property
    def sla_days(self) -> int:
        """Maximum days to remediate based on severity (IEC 62443)."""
        sla_map = {
            CVESeverity.CRITICAL: 15,
            CVESeverity.HIGH: 30,
            CVESeverity.MEDIUM: 90,
            CVESeverity.LOW: 180,
            CVESeverity.NONE: 365,
        }
        return sla_map.get(self.severity, 365)

    def transition(self, new_status: CVEStatus, note: str = "") -> None:
        """Transition the CVE to a new status with audit trail."""
        old_status = self.status
        self.status = new_status
        self.history.append({
            "from": old_status.value,
            "to": new_status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": note,
        })
        if note:
            self.notes.append(note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "cvss_score": self.cvss_score,
            "severity": self.severity.value,
            "affected_component": self.affected_component,
            "status": self.status.value,
            "detected_at": self.detected_at,
            "due_date": self.due_date,
            "is_overdue": self.is_overdue,
            "remediation": self.remediation.value if self.remediation else None,
            "assignee": self.assignee,
        }


class CVETracker:
    """Manages the full CVE lifecycle for the middleware.

    Provides:
    - Vulnerability registration and tracking
    - Severity-based SLA enforcement
    - Status workflow management
    - Compliance reporting (IEC 62443, ISO 27001)
    - Risk scoring and prioritization
    """

    def __init__(self) -> None:
        self._vulnerabilities: dict[str, CVEEntry] = {}
        self._scan_history: list[dict[str, Any]] = []

    def register(self, cve: CVEEntry) -> None:
        """Register a new CVE or update an existing one."""
        if cve.cve_id in self._vulnerabilities:
            existing = self._vulnerabilities[cve.cve_id]
            existing.cvss_score = cve.cvss_score
            existing.severity = CVESeverity.from_score(cve.cvss_score)
            existing.description = cve.description or existing.description
            logger.info("cve.updated", cve_id=cve.cve_id, score=cve.cvss_score)
        else:
            self._vulnerabilities[cve.cve_id] = cve
            logger.info(
                "cve.registered",
                cve_id=cve.cve_id,
                severity=cve.severity.value,
                score=cve.cvss_score,
                component=cve.affected_component,
            )

    def get(self, cve_id: str) -> CVEEntry | None:
        return self._vulnerabilities.get(cve_id)

    def transition(
        self,
        cve_id: str,
        new_status: CVEStatus,
        note: str = "",
    ) -> bool:
        """Transition a CVE to a new status."""
        cve = self.get(cve_id)
        if cve is None:
            return False
        cve.transition(new_status, note)
        logger.info(
            "cve.status_changed",
            cve_id=cve_id,
            new_status=new_status.value,
        )
        return True

    def get_by_severity(self, severity: CVESeverity) -> list[CVEEntry]:
        return [
            v for v in self._vulnerabilities.values()
            if v.severity == severity
        ]

    def get_open_vulnerabilities(self) -> list[CVEEntry]:
        """Get all non-closed vulnerabilities sorted by severity."""
        closed = {CVEStatus.REMEDIATED, CVEStatus.FALSE_POSITIVE}
        vulns = [
            v for v in self._vulnerabilities.values()
            if v.status not in closed
        ]
        severity_order = {
            CVESeverity.CRITICAL: 0,
            CVESeverity.HIGH: 1,
            CVESeverity.MEDIUM: 2,
            CVESeverity.LOW: 3,
            CVESeverity.NONE: 4,
        }
        return sorted(vulns, key=lambda v: severity_order.get(v.severity, 5))

    def get_overdue(self) -> list[CVEEntry]:
        """Get all overdue vulnerabilities."""
        return [
            v for v in self._vulnerabilities.values()
            if v.is_overdue and v.status not in {
                CVEStatus.REMEDIATED, CVEStatus.FALSE_POSITIVE
            }
        ]

    def get_risk_score(self) -> float:
        """Calculate aggregate risk score (0-100).

        Weighted by severity and status:
        - Open critical = 25 points each
        - Open high = 10 points each
        - Open medium = 3 points each
        - In remediation = 50% weight reduction
        """
        score = 0.0
        weights = {
            CVESeverity.CRITICAL: 25.0,
            CVESeverity.HIGH: 10.0,
            CVESeverity.MEDIUM: 3.0,
            CVESeverity.LOW: 1.0,
        }
        for vuln in self.get_open_vulnerabilities():
            weight = weights.get(vuln.severity, 0.0)
            if vuln.status == CVEStatus.IN_REMEDIATION:
                weight *= 0.5
            elif vuln.status == CVEStatus.MITIGATED:
                weight *= 0.25
            score += weight

        return min(score, 100.0)

    def generate_compliance_report(self) -> dict[str, Any]:
        """Generate a compliance report suitable for IEC 62443 audits."""
        open_vulns = self.get_open_vulnerabilities()
        overdue = self.get_overdue()

        return {
            "report_type": "vulnerability_compliance",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework": "IEC 62443 / ISO 27001",
            "summary": {
                "total_tracked": len(self._vulnerabilities),
                "open": len(open_vulns),
                "overdue": len(overdue),
                "risk_score": round(self.get_risk_score(), 1),
                "by_severity": {
                    sev.value: len(self.get_by_severity(sev))
                    for sev in CVESeverity
                    if sev != CVESeverity.NONE
                },
                "by_status": self._count_by_status(),
            },
            "overdue_items": [v.to_dict() for v in overdue],
            "critical_open": [
                v.to_dict() for v in open_vulns
                if v.severity == CVESeverity.CRITICAL
            ],
            "sla_compliance": self._calculate_sla_compliance(),
        }

    def record_scan(self, scan_result: dict[str, Any]) -> None:
        """Record a vulnerability scan result for audit trail."""
        self._scan_history.append({
            **scan_result,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        })

    def _count_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for vuln in self._vulnerabilities.values():
            key = vuln.status.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _calculate_sla_compliance(self) -> dict[str, Any]:
        """Calculate SLA compliance percentage per severity."""
        compliance: dict[str, dict[str, int]] = {}
        for vuln in self._vulnerabilities.values():
            sev = vuln.severity.value
            if sev not in compliance:
                compliance[sev] = {"total": 0, "within_sla": 0}
            compliance[sev]["total"] += 1
            if not vuln.is_overdue:
                compliance[sev]["within_sla"] += 1

        return {
            sev: {
                "compliance_pct": round(
                    (data["within_sla"] / data["total"]) * 100, 1
                ) if data["total"] > 0 else 100.0,
                **data,
            }
            for sev, data in compliance.items()
        }
