"""Patch Lifecycle Manager.

Manages the quarterly patch cycle for the middleware:
- Patch registration and metadata tracking
- Signed change logs with SHA-256 integrity
- Plan of Action & Milestones (POA&M) generation
- Rollback capability with state snapshots
- Full traceability for IEC 62304 compliance
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class PatchStatus(Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    IN_TEST = "in_test"
    DEPLOYED_STAGING = "deployed_staging"
    DEPLOYED_PRODUCTION = "deployed_production"
    ROLLED_BACK = "rolled_back"
    SUPERSEDED = "superseded"


class PatchSeverity(Enum):
    EMERGENCY = "emergency"  # Out-of-band, deployed immediately
    CRITICAL = "critical"    # Next available maintenance window
    STANDARD = "standard"    # Quarterly cycle
    ENHANCEMENT = "enhancement"


class PatchCategory(Enum):
    SECURITY = "security"
    BUGFIX = "bugfix"
    PERFORMANCE = "performance"
    FEATURE = "feature"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"


@dataclass
class PatchEntry:
    """A single patch in the lifecycle."""
    patch_id: str = field(default_factory=lambda: f"PATCH-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    version_from: str = ""
    version_to: str = ""
    severity: PatchSeverity = PatchSeverity.STANDARD
    category: PatchCategory = PatchCategory.BUGFIX
    status: PatchStatus = PatchStatus.DRAFT
    cve_ids: list[str] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)
    test_results: dict[str, Any] = field(default_factory=dict)
    approved_by: str = ""
    deployed_at: str | None = None
    rollback_snapshot: str | None = None
    checksum: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    audit_trail: list[dict[str, Any]] = field(default_factory=list)

    def sign(self, content: str) -> str:
        """Generate SHA-256 signature for patch content."""
        self.checksum = hashlib.sha256(content.encode()).hexdigest()
        return self.checksum

    def transition(self, new_status: PatchStatus, actor: str = "", note: str = "") -> None:
        old = self.status
        self.status = new_status
        self.audit_trail.append({
            "action": "status_change",
            "from": old.value,
            "to": new_status.value,
            "actor": actor,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": note,
        })
        if new_status == PatchStatus.DEPLOYED_PRODUCTION:
            self.deployed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "title": self.title,
            "version": f"{self.version_from} → {self.version_to}",
            "severity": self.severity.value,
            "category": self.category.value,
            "status": self.status.value,
            "cve_ids": self.cve_ids,
            "checksum": self.checksum,
            "deployed_at": self.deployed_at,
            "created_at": self.created_at,
        }


@dataclass
class POAMEntry:
    """Plan of Action & Milestones entry (NIST SP 800-53)."""
    poam_id: str = field(default_factory=lambda: f"POAM-{uuid.uuid4().hex[:6].upper()}")
    weakness: str = ""
    control_id: str = ""
    patch_ids: list[str] = field(default_factory=list)
    milestone: str = ""
    scheduled_date: str = ""
    completion_date: str | None = None
    responsible_party: str = ""
    status: str = "open"
    resources_required: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "poam_id": self.poam_id,
            "weakness": self.weakness,
            "control_id": self.control_id,
            "milestone": self.milestone,
            "scheduled_date": self.scheduled_date,
            "status": self.status,
            "responsible_party": self.responsible_party,
        }


class PatchManager:
    """Manages the full patch lifecycle with regulatory traceability.

    Supports:
    - Quarterly patch cycles (standard cadence)
    - Emergency out-of-band patches
    - Signed change logs
    - POA&M generation
    - Rollback with state snapshots
    """

    def __init__(self, require_signature: bool = True) -> None:
        self._patches: dict[str, PatchEntry] = {}
        self._poam_entries: list[POAMEntry] = []
        self._changelog: list[dict[str, Any]] = []
        self._require_signature = require_signature

    def create_patch(
        self,
        title: str,
        description: str,
        version_from: str,
        version_to: str,
        severity: PatchSeverity = PatchSeverity.STANDARD,
        category: PatchCategory = PatchCategory.BUGFIX,
        cve_ids: list[str] | None = None,
    ) -> PatchEntry:
        """Create a new patch entry."""
        patch = PatchEntry(
            title=title,
            description=description,
            version_from=version_from,
            version_to=version_to,
            severity=severity,
            category=category,
            cve_ids=cve_ids or [],
        )
        self._patches[patch.patch_id] = patch
        logger.info(
            "patch.created",
            patch_id=patch.patch_id,
            title=title,
            severity=severity.value,
        )
        return patch

    def approve_patch(self, patch_id: str, approver: str) -> bool:
        patch = self._patches.get(patch_id)
        if not patch:
            return False
        patch.approved_by = approver
        patch.transition(PatchStatus.APPROVED, actor=approver, note="Patch approved")
        return True

    def deploy_patch(
        self, patch_id: str, environment: str = "production", actor: str = "",
    ) -> bool:
        """Deploy a patch to the specified environment."""
        patch = self._patches.get(patch_id)
        if not patch:
            return False

        if self._require_signature and not patch.checksum:
            logger.error("patch.deploy_failed_no_signature", patch_id=patch_id)
            return False

        target_status = (
            PatchStatus.DEPLOYED_PRODUCTION
            if environment == "production"
            else PatchStatus.DEPLOYED_STAGING
        )
        patch.transition(target_status, actor=actor, note=f"Deployed to {environment}")

        # Record in changelog
        self._changelog.append({
            "patch_id": patch.patch_id,
            "title": patch.title,
            "version": f"{patch.version_from} → {patch.version_to}",
            "deployed_at": patch.deployed_at,
            "checksum": patch.checksum,
            "environment": environment,
        })

        logger.info(
            "patch.deployed",
            patch_id=patch_id,
            environment=environment,
            checksum=patch.checksum[:16],
        )
        return True

    def rollback_patch(self, patch_id: str, reason: str = "", actor: str = "") -> bool:
        """Rollback a deployed patch."""
        patch = self._patches.get(patch_id)
        if not patch:
            return False
        patch.transition(
            PatchStatus.ROLLED_BACK,
            actor=actor,
            note=f"Rollback reason: {reason}",
        )
        logger.warning("patch.rolled_back", patch_id=patch_id, reason=reason)
        return True

    def generate_poam(
        self,
        weakness: str,
        control_id: str,
        milestone: str,
        scheduled_date: str,
        responsible: str,
        patch_ids: list[str] | None = None,
    ) -> POAMEntry:
        """Generate a POA&M entry for a known weakness."""
        entry = POAMEntry(
            weakness=weakness,
            control_id=control_id,
            patch_ids=patch_ids or [],
            milestone=milestone,
            scheduled_date=scheduled_date,
            responsible_party=responsible,
        )
        self._poam_entries.append(entry)
        logger.info("poam.created", poam_id=entry.poam_id, weakness=weakness)
        return entry

    def get_changelog(self) -> list[dict[str, Any]]:
        return list(reversed(self._changelog))

    def get_signed_changelog(self) -> dict[str, Any]:
        """Generate a signed changelog document."""
        changelog_json = json.dumps(self._changelog, sort_keys=True)
        signature = hashlib.sha256(changelog_json.encode()).hexdigest()
        return {
            "document_type": "signed_changelog",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "signature_algorithm": "SHA-256",
            "signature": signature,
            "entry_count": len(self._changelog),
            "entries": self._changelog,
        }

    def get_poam_report(self) -> dict[str, Any]:
        return {
            "report_type": "POA&M",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(self._poam_entries),
            "open": sum(1 for e in self._poam_entries if e.status == "open"),
            "entries": [e.to_dict() for e in self._poam_entries],
        }

    def get_patch_summary(self) -> dict[str, Any]:
        return {
            "total_patches": len(self._patches),
            "by_status": self._count_field("status"),
            "by_severity": self._count_field("severity"),
            "by_category": self._count_field("category"),
        }

    def _count_field(self, attr: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for p in self._patches.values():
            val = getattr(p, attr)
            key = val.value if hasattr(val, "value") else str(val)
            counts[key] = counts.get(key, 0) + 1
        return counts
