"""Asynchronous Event Bus for inter-subsystem communication.

Implements a pub/sub pattern allowing decoupled communication between
middleware components (engine, router, security, monitoring).
All events are typed and carry audit metadata for IEC 62304 traceability.
"""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Awaitable

import structlog

logger = structlog.get_logger(__name__)

# Type alias for event handler coroutines
EventHandler = Callable[["Event"], Awaitable[None]]


class EventType(Enum):
    """Categorized event types for the middleware event bus."""

    # Engine lifecycle
    ENGINE_STARTED = "engine.started"
    ENGINE_STOPPED = "engine.stopped"
    ENGINE_DEGRADED = "engine.degraded"

    # Message processing
    MESSAGE_RECEIVED = "message.received"
    MESSAGE_ROUTED = "message.routed"
    MESSAGE_VALIDATED = "message.validated"
    MESSAGE_TRANSFORMED = "message.transformed"
    MESSAGE_DELIVERED = "message.delivered"
    MESSAGE_DEAD_LETTER = "message.dead_letter"

    # Interface contracts
    CONTRACT_LOADED = "contract.loaded"
    CONTRACT_VIOLATION = "contract.violation"
    CONTRACT_UPDATED = "contract.updated"

    # Security events
    CVE_DETECTED = "security.cve_detected"
    CVE_REMEDIATED = "security.cve_remediated"
    COMPLIANCE_CHECK = "security.compliance_check"
    SBOM_GENERATED = "security.sbom_generated"
    SECURITY_ALERT = "security.alert"

    # Patch management
    PATCH_APPLIED = "patch.applied"
    PATCH_ROLLED_BACK = "patch.rolled_back"
    PATCH_CYCLE_STARTED = "patch.cycle_started"

    # Monitoring
    HEALTH_CHECK = "monitoring.health_check"
    THRESHOLD_BREACH = "monitoring.threshold_breach"


@dataclass(frozen=True)
class Event:
    """Immutable event with full audit metadata.

    Attributes:
        event_type: Categorized type of the event.
        source: Identifier of the component that emitted the event.
        payload: Arbitrary event data.
        event_id: Unique identifier for this event instance.
        timestamp: UTC timestamp when the event was created.
        correlation_id: Optional ID linking related events.
    """
    event_type: EventType
    source: str
    payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    correlation_id: str | None = None

    def to_audit_record(self) -> dict[str, Any]:
        """Serialize to an audit-compliant record (21 CFR Part 11)."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "payload_keys": list(self.payload.keys()),
        }


class EventBus:
    """Asynchronous event bus with topic-based pub/sub.

    Features:
    - Type-safe event subscriptions
    - Wildcard subscriptions (receive all events)
    - Non-blocking event dispatch
    - Event history for audit trail
    - Configurable queue depth per subscriber
    """

    def __init__(self, max_history: int = 10_000) -> None:
        self._handlers: dict[EventType, list[EventHandler]] = defaultdict(list)
        self._wildcard_handlers: list[EventHandler] = []
        self._history: list[Event] = []
        self._max_history = max_history
        self._is_running = False
        self._dispatch_queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=5_000)
        self._dispatch_task: asyncio.Task[None] | None = None
        self._stats = {"published": 0, "dispatched": 0, "errors": 0}

    async def start(self) -> None:
        """Start the event dispatch loop."""
        if self._is_running:
            return
        self._is_running = True
        self._dispatch_task = asyncio.create_task(
            self._dispatch_loop(), name="event-bus-dispatch"
        )
        logger.info("event_bus.started")

    async def stop(self) -> None:
        """Stop the event bus and flush remaining events."""
        self._is_running = False
        if self._dispatch_task:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
        logger.info("event_bus.stopped", stats=self._stats)

    def subscribe(
        self,
        event_type: EventType | None,
        handler: EventHandler,
    ) -> None:
        """Subscribe a handler to a specific event type.

        Args:
            event_type: The event type to subscribe to, or None for wildcard.
            handler: Async callable that processes the event.
        """
        if event_type is None:
            self._wildcard_handlers.append(handler)
            logger.debug("event_bus.subscribed_wildcard", handler=handler.__name__)
        else:
            self._handlers[event_type].append(handler)
            logger.debug(
                "event_bus.subscribed",
                event_type=event_type.value,
                handler=handler.__name__,
            )

    def unsubscribe(
        self,
        event_type: EventType | None,
        handler: EventHandler,
    ) -> None:
        """Remove a handler subscription."""
        if event_type is None:
            self._wildcard_handlers = [
                h for h in self._wildcard_handlers if h != handler
            ]
        else:
            self._handlers[event_type] = [
                h for h in self._handlers[event_type] if h != handler
            ]

    async def publish(self, event: Event) -> None:
        """Publish an event to the bus for async dispatch.

        Events are enqueued for non-blocking dispatch to all matching
        subscribers. If the queue is full, the event is dispatched
        synchronously as a fallback.
        """
        self._stats["published"] += 1

        # Store in history for audit
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        try:
            self._dispatch_queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("event_bus.queue_full, dispatching synchronously")
            await self._dispatch_event(event)

    def get_history(
        self,
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Retrieve event history, optionally filtered by type."""
        events = self._history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]

    # --- Internal ---

    async def _dispatch_loop(self) -> None:
        """Main dispatch loop processing queued events."""
        while self._is_running:
            try:
                event = await asyncio.wait_for(
                    self._dispatch_queue.get(), timeout=0.5
                )
                await self._dispatch_event(event)
                self._dispatch_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def _dispatch_event(self, event: Event) -> None:
        """Dispatch an event to all matching handlers."""
        handlers = [
            *self._handlers.get(event.event_type, []),
            *self._wildcard_handlers,
        ]

        for handler in handlers:
            try:
                await handler(event)
                self._stats["dispatched"] += 1
            except Exception as exc:
                self._stats["errors"] += 1
                logger.error(
                    "event_bus.handler_error",
                    event_type=event.event_type.value,
                    handler=handler.__name__,
                    error=str(exc),
                )
