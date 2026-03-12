"""Prometheus-Compatible Metrics Collector.

Provides counters, gauges, histograms, and summaries for middleware
observability. Exposes metrics in Prometheus exposition format.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class MetricPoint:
    """A single metric data point."""
    name: str
    value: float
    labels: dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class MetricsCollector:
    """Lightweight Prometheus-compatible metrics collector.

    Supports:
    - Counters (monotonically increasing)
    - Gauges (can go up and down)
    - Histograms (bucketed observations)
    - Metric labels for dimensional data
    - Prometheus exposition format export
    """

    def __init__(self, namespace: str = "maestria") -> None:
        self._namespace = namespace
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = defaultdict(float)
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._metadata: dict[str, dict[str, str]] = {}
        self._started_at: float | None = None

    async def start(self) -> None:
        self._started_at = time.time()
        logger.info("metrics.started", namespace=self._namespace)

    async def stop(self) -> None:
        logger.info("metrics.stopped", namespace=self._namespace)

    def register(
        self, name: str, metric_type: str, description: str = "",
    ) -> None:
        """Register a metric with metadata."""
        self._metadata[name] = {
            "type": metric_type,
            "help": description,
        }

    def increment(self, name: str, value: float = 1.0) -> None:
        """Increment a counter metric."""
        key = f"{self._namespace}_{name}"
        self._counters[key] += value

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge metric to a specific value."""
        key = f"{self._namespace}_{name}"
        self._gauges[key] = value

    def observe(self, name: str, value: float) -> None:
        """Record an observation for a histogram metric."""
        key = f"{self._namespace}_{name}"
        self._histograms[key].append(value)
        # Keep only last 10000 observations
        if len(self._histograms[key]) > 10_000:
            self._histograms[key] = self._histograms[key][-10_000:]

    def get_counter(self, name: str) -> float:
        return self._counters.get(f"{self._namespace}_{name}", 0.0)

    def get_gauge(self, name: str) -> float:
        return self._gauges.get(f"{self._namespace}_{name}", 0.0)

    def get_histogram_stats(self, name: str) -> dict[str, float]:
        """Get histogram statistics (count, sum, avg, p50, p95, p99)."""
        key = f"{self._namespace}_{name}"
        values = self._histograms.get(key, [])
        if not values:
            return {"count": 0, "sum": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_vals = sorted(values)
        count = len(sorted_vals)
        return {
            "count": count,
            "sum": round(sum(sorted_vals), 3),
            "avg": round(sum(sorted_vals) / count, 3),
            "min": round(sorted_vals[0], 3),
            "max": round(sorted_vals[-1], 3),
            "p50": round(sorted_vals[int(count * 0.50)], 3),
            "p95": round(sorted_vals[int(count * 0.95)], 3),
            "p99": round(sorted_vals[min(int(count * 0.99), count - 1)], 3),
        }

    def export_prometheus(self) -> str:
        """Export all metrics in Prometheus exposition format."""
        lines: list[str] = []

        # Add uptime gauge
        if self._started_at:
            uptime = time.time() - self._started_at
            lines.append(f"# TYPE {self._namespace}_uptime_seconds gauge")
            lines.append(f"{self._namespace}_uptime_seconds {uptime:.2f}")

        # Counters
        for key, value in sorted(self._counters.items()):
            meta = self._metadata.get(key.replace(f"{self._namespace}_", ""), {})
            if meta.get("help"):
                lines.append(f"# HELP {key} {meta['help']}")
            lines.append(f"# TYPE {key} counter")
            lines.append(f"{key} {value}")

        # Gauges
        for key, value in sorted(self._gauges.items()):
            meta = self._metadata.get(key.replace(f"{self._namespace}_", ""), {})
            if meta.get("help"):
                lines.append(f"# HELP {key} {meta['help']}")
            lines.append(f"# TYPE {key} gauge")
            lines.append(f"{key} {value}")

        # Histograms
        for key, values in sorted(self._histograms.items()):
            if not values:
                continue
            stats = self.get_histogram_stats(
                key.replace(f"{self._namespace}_", "")
            )
            lines.append(f"# TYPE {key} histogram")
            lines.append(f'{key}_count {stats["count"]}')
            lines.append(f'{key}_sum {stats["sum"]}')

        return "\n".join(lines) + "\n"

    def get_all_metrics(self) -> dict[str, Any]:
        """Get all metrics as a structured dictionary."""
        return {
            "namespace": self._namespace,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                k: self.get_histogram_stats(k.replace(f"{self._namespace}_", ""))
                for k in self._histograms
            },
        }
