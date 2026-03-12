"""Vulnerability Remediation Workflow.

Manages the end-to-end remediation lifecycle from vulnerability detection
to verified closure, with full audit trail for regulatory compliance.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import structlog

from maestria.security.cve_tracker import (
    CVEEntry, CVEStatus, CVESeverity, RemediationAction,
)

logger = structlog.get_logger(__name__)


class TaskPriority(Enum):
    P0_EMERGENCY = 0
    P1_CRITICAL = 1
    P2_HIGH = 2
    P3_MEDIUM = 3
    P4_LOW = 4


class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    TESTING = "testing"
    VERIFIED = "verified"
    CLOSED = "closed"
    BLOCKED = "blocked"


@dataclass
class RemediationTask:
    """A concrete remediation task linked to one or more CVEs."""
    task_id: str = field(default_factory=lambda: f"REM-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    cve_ids: list[str] = field(default_factory=list)
    action: RemediationAction = RemediationAction.PATCH
    priority: TaskPriority = TaskPriority.P3_MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    assignee: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    due_date: str | None = None
    completed_at: str | None = None
    verification_steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    audit_trail: list[dict[str, Any]] = field(default_factory=list)

    def update_status(self, new_status: TaskStatus, note: str = "") -> None:
        old = self.status
        self.status = new_status
        self.audit_trail.append({
            "action": "status_change",
            "from": old.value,
            "to": new_status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": note,
        })
        if new_status == TaskStatus.CLOSED:
            self.completed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "cve_ids": self.cve_ids,
            "action": self.action.value,
            "priority": self.priority.name,
            "status": self.status.value,
            "assignee": self.assignee,
            "due_date": self.due_date,
            "completed_at": self.completed_at,
        }


class RemediationWorkflow:
    """Orchestrates the vulnerability remediation process.

    Creates remediation tasks from CVEs, tracks progress,
    and ensures verification before closure.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, RemediationTask] = {}

    def create_task_from_cve(
        self,
        cve: CVEEntry,
        action: RemediationAction = RemediationAction.PATCH,
        assignee: str = "",
    ) -> RemediationTask:
        """Create a remediation task for a CVE."""
        priority_map = {
            CVESeverity.CRITICAL: TaskPriority.P0_EMERGENCY,
            CVESeverity.HIGH: TaskPriority.P1_CRITICAL,
            CVESeverity.MEDIUM: TaskPriority.P2_HIGH,
            CVESeverity.LOW: TaskPriority.P3_MEDIUM,
        }

        now = datetime.now(timezone.utc)
        due = now + timedelta(days=cve.sla_days)

        task = RemediationTask(
            title=f"Remediate {cve.cve_id}: {cve.title}",
            description=cve.description,
            cve_ids=[cve.cve_id],
            action=action,
            priority=priority_map.get(cve.severity, TaskPriority.P4_LOW),
            assignee=assignee,
            due_date=due.isoformat(),
            verification_steps=[
                f"Verify {cve.cve_id} is no longer exploitable",
                "Run security regression tests",
                "Update SBOM and CVE tracker",
                "Document remediation in change log",
            ],
        )
        self._tasks[task.task_id] = task
        logger.info(
            "remediation.task_created",
            task_id=task.task_id,
            cve_id=cve.cve_id,
            priority=task.priority.name,
        )
        return task

    def get_task(self, task_id: str) -> RemediationTask | None:
        return self._tasks.get(task_id)

    def update_task(
        self,
        task_id: str,
        status: TaskStatus,
        note: str = "",
    ) -> bool:
        task = self.get_task(task_id)
        if task is None:
            return False
        task.update_status(status, note)
        logger.info(
            "remediation.task_updated",
            task_id=task_id,
            status=status.value,
        )
        return True

    def get_open_tasks(self) -> list[RemediationTask]:
        closed = {TaskStatus.CLOSED, TaskStatus.VERIFIED}
        return sorted(
            [t for t in self._tasks.values() if t.status not in closed],
            key=lambda t: t.priority.value,
        )

    def get_dashboard_summary(self) -> dict[str, Any]:
        all_tasks = list(self._tasks.values())
        return {
            "total_tasks": len(all_tasks),
            "by_status": self._count_by("status", all_tasks),
            "by_priority": self._count_by("priority", all_tasks),
            "open_count": len(self.get_open_tasks()),
            "overdue": sum(
                1 for t in all_tasks
                if t.due_date
                and t.status not in {TaskStatus.CLOSED, TaskStatus.VERIFIED}
                and datetime.now(timezone.utc) > datetime.fromisoformat(t.due_date)
            ),
        }

    def _count_by(
        self, attr: str, tasks: list[RemediationTask],
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for t in tasks:
            val = getattr(t, attr)
            key = val.value if hasattr(val, "value") else val.name
            counts[key] = counts.get(key, 0) + 1
        return counts
