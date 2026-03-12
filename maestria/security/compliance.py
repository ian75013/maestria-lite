"""Regulatory Compliance Engine.

Evaluates the middleware configuration and security posture against
industry standards and regulatory frameworks:
- IEC 62443 (Industrial Cybersecurity)
- ISO 27001 (Information Security Management)
- FDA 21 CFR Part 11 (Electronic Records)
- HIPAA (Health Information Privacy)

Each control is modeled as a check that can be evaluated automatically
or flagged for manual review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

import structlog

logger = structlog.get_logger(__name__)


class ComplianceFramework(Enum):
    IEC_62443 = "iec_62443"
    ISO_27001 = "iso_27001"
    FDA_21_CFR_11 = "fda_21_cfr_11"
    HIPAA = "hipaa"


class ControlStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    MANUAL_REVIEW = "manual_review"


class ControlCategory(Enum):
    ACCESS_CONTROL = "access_control"
    AUDIT_TRAIL = "audit_trail"
    DATA_INTEGRITY = "data_integrity"
    ENCRYPTION = "encryption"
    NETWORK_SECURITY = "network_security"
    PATCH_MANAGEMENT = "patch_management"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    INCIDENT_RESPONSE = "incident_response"
    CONFIGURATION_MANAGEMENT = "configuration_management"
    AUTHENTICATION = "authentication"


@dataclass
class ComplianceControl:
    """A single compliance control/check."""
    control_id: str
    title: str
    description: str
    framework: ComplianceFramework
    category: ControlCategory
    check_fn: Callable[[dict[str, Any]], ControlStatus] | None = None
    status: ControlStatus = ControlStatus.MANUAL_REVIEW
    evidence: str = ""
    notes: str = ""
    last_checked: str | None = None

    def evaluate(self, context: dict[str, Any]) -> ControlStatus:
        """Evaluate this control against the given context."""
        if self.check_fn:
            self.status = self.check_fn(context)
        self.last_checked = datetime.now(timezone.utc).isoformat()
        return self.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "framework": self.framework.value,
            "category": self.category.value,
            "status": self.status.value,
            "last_checked": self.last_checked,
            "evidence": self.evidence,
        }


@dataclass
class ComplianceReport:
    """Full compliance assessment report."""
    framework: ComplianceFramework
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    controls: list[ComplianceControl] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.controls)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.controls if c.status == ControlStatus.FAIL)

    @property
    def compliance_score(self) -> float:
        applicable = [
            c for c in self.controls
            if c.status != ControlStatus.NOT_APPLICABLE
        ]
        if not applicable:
            return 100.0
        passed = sum(1 for c in applicable if c.status == ControlStatus.PASS)
        return round((passed / len(applicable)) * 100, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "generated_at": self.generated_at,
            "summary": {
                "total_controls": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "compliance_score": self.compliance_score,
            },
            "controls": [c.to_dict() for c in self.controls],
        }


class ComplianceEngine:
    """Evaluates middleware compliance against regulatory frameworks."""

    def __init__(self) -> None:
        self._controls: dict[str, ComplianceControl] = {}
        self._register_default_controls()

    def register_control(self, control: ComplianceControl) -> None:
        self._controls[control.control_id] = control

    def evaluate_framework(
        self,
        framework: ComplianceFramework,
        context: dict[str, Any],
    ) -> ComplianceReport:
        """Run all controls for a given framework and produce a report."""
        controls = [
            c for c in self._controls.values()
            if c.framework == framework
        ]
        for control in controls:
            control.evaluate(context)
            logger.debug(
                "compliance.control_evaluated",
                control_id=control.control_id,
                status=control.status.value,
            )

        report = ComplianceReport(framework=framework, controls=controls)
        logger.info(
            "compliance.report_generated",
            framework=framework.value,
            score=report.compliance_score,
            passed=report.passed,
            failed=report.failed,
        )
        return report

    def evaluate_all(self, context: dict[str, Any]) -> list[ComplianceReport]:
        """Evaluate all registered frameworks."""
        reports = []
        for fw in ComplianceFramework:
            report = self.evaluate_framework(fw, context)
            if report.total > 0:
                reports.append(report)
        return reports

    # --- Built-in Controls ---

    def _register_default_controls(self) -> None:
        """Register default compliance controls for IVD environments."""

        # IEC 62443 Controls
        self.register_control(ComplianceControl(
            control_id="IEC62443-SR-1.1",
            title="Human user identification and authentication",
            description="All human users shall be identified and authenticated.",
            framework=ComplianceFramework.IEC_62443,
            category=ControlCategory.AUTHENTICATION,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("auth_enabled") else ControlStatus.FAIL
            ),
        ))
        self.register_control(ComplianceControl(
            control_id="IEC62443-SR-2.8",
            title="Auditable events",
            description="Security-relevant events shall be logged.",
            framework=ComplianceFramework.IEC_62443,
            category=ControlCategory.AUDIT_TRAIL,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("audit_logging") else ControlStatus.FAIL
            ),
        ))
        self.register_control(ComplianceControl(
            control_id="IEC62443-SR-3.1",
            title="Communication integrity",
            description="Communication channels shall ensure data integrity.",
            framework=ComplianceFramework.IEC_62443,
            category=ControlCategory.DATA_INTEGRITY,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("tls_enabled") and ctx.get("tls_min_version", "") >= "1.2"
                else ControlStatus.FAIL
            ),
        ))
        self.register_control(ComplianceControl(
            control_id="IEC62443-SR-3.4",
            title="Software and information integrity",
            description="Integrity of software and data shall be verified.",
            framework=ComplianceFramework.IEC_62443,
            category=ControlCategory.DATA_INTEGRITY,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("checksum_verification") else ControlStatus.FAIL
            ),
        ))
        self.register_control(ComplianceControl(
            control_id="IEC62443-SR-7.6",
            title="Network and security configuration settings",
            description="Current security configurations shall be documented.",
            framework=ComplianceFramework.IEC_62443,
            category=ControlCategory.CONFIGURATION_MANAGEMENT,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("config_documented") else ControlStatus.PARTIAL
            ),
        ))

        # FDA 21 CFR Part 11
        self.register_control(ComplianceControl(
            control_id="CFR11-11.10a",
            title="System validation",
            description="Systems shall be validated for accuracy and reliability.",
            framework=ComplianceFramework.FDA_21_CFR_11,
            category=ControlCategory.DATA_INTEGRITY,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("validation_suite_passes") else ControlStatus.FAIL
            ),
        ))
        self.register_control(ComplianceControl(
            control_id="CFR11-11.10e",
            title="Audit trail",
            description="Secure, computer-generated, time-stamped audit trail.",
            framework=ComplianceFramework.FDA_21_CFR_11,
            category=ControlCategory.AUDIT_TRAIL,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("audit_logging") and ctx.get("tamper_proof_logs")
                else ControlStatus.FAIL
            ),
        ))

        # ISO 27001
        self.register_control(ComplianceControl(
            control_id="ISO27001-A.12.6.1",
            title="Management of technical vulnerabilities",
            description="Timely identification and remediation of vulnerabilities.",
            framework=ComplianceFramework.ISO_27001,
            category=ControlCategory.VULNERABILITY_MANAGEMENT,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("cve_tracking_active")
                and ctx.get("open_critical_cves", 99) == 0
                else ControlStatus.FAIL
            ),
        ))
        self.register_control(ComplianceControl(
            control_id="ISO27001-A.14.2.2",
            title="System change control procedures",
            description="Changes shall be controlled using formal procedures.",
            framework=ComplianceFramework.ISO_27001,
            category=ControlCategory.PATCH_MANAGEMENT,
            check_fn=lambda ctx: (
                ControlStatus.PASS
                if ctx.get("change_control_enabled")
                and ctx.get("signed_changelogs")
                else ControlStatus.FAIL
            ),
        ))
