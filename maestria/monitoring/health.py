"""Health Check System.

Provides comprehensive health monitoring for the middleware and all
connected subsystems. Exposes HTTP-compatible health endpoints
following the RFC Health Check Response Format.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Awaitable

import structlog

logger = structlog.get_logger(__name__)

HealthCheckFn = Callable[[], Awaitable["ComponentHealth"]]


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a single component."""
    name: str
    status: HealthStatus
    latency_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    last_checked: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class SystemHealth:
    """Aggregate health status of the entire system."""
    status: HealthStatus
    version: str
    uptime_seconds: float
    components: list[ComponentHealth] = field(default_factory=list)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "version": self.version,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "checked_at": self.checked_at,
            "components": {
                c.name: {
                    "status": c.status.value,
                    "latency_ms": round(c.latency_ms, 2),
                    "message": c.message,
                    "details": c.details,
                }
                for c in self.components
            },
        }


class HealthChecker:
    """Manages health checks for all middleware components.

    Registers check functions for each component and performs
    periodic or on-demand health assessments.
    """

    def __init__(self, version: str = "unknown") -> None:
        self._checks: dict[str, HealthCheckFn] = {}
        self._version = version
        self._started_at = time.time()
        self._last_result: SystemHealth | None = None

    def register(self, component_name: str, check_fn: HealthCheckFn) -> None:
        """Register a health check function for a component."""
        self._checks[component_name] = check_fn

    async def check_all(self, timeout: float = 5.0) -> SystemHealth:
        """Run all health checks with a timeout per check."""
        components: list[ComponentHealth] = []

        for name, check_fn in self._checks.items():
            start = time.monotonic()
            try:
                result = await asyncio.wait_for(check_fn(), timeout=timeout)
                result.latency_ms = (time.monotonic() - start) * 1000
                components.append(result)
            except asyncio.TimeoutError:
                components.append(ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    latency_ms=timeout * 1000,
                    message=f"Health check timed out after {timeout}s",
                ))
            except Exception as exc:
                components.append(ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    latency_ms=(time.monotonic() - start) * 1000,
                    message=str(exc),
                ))

        # Determine aggregate status
        statuses = [c.status for c in components]
        if all(s == HealthStatus.HEALTHY for s in statuses):
            aggregate = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            aggregate = HealthStatus.UNHEALTHY
        else:
            aggregate = HealthStatus.DEGRADED

        result = SystemHealth(
            status=aggregate,
            version=self._version,
            uptime_seconds=time.time() - self._started_at,
            components=components,
        )
        self._last_result = result
        return result

    async def check_component(self, name: str) -> ComponentHealth:
        """Check a single component's health."""
        check_fn = self._checks.get(name)
        if not check_fn:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"No health check registered for '{name}'",
            )
        return await check_fn()

    @property
    def last_result(self) -> SystemHealth | None:
        return self._last_result
