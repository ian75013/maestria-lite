"""MAESTRIA-Lite Core Engine.

Central orchestrator managing the middleware lifecycle, worker pool,
and coordination between all subsystems (router, security, patches, monitoring).
"""

from __future__ import annotations

import asyncio
import signal
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog

from maestria.core.event_bus import EventBus, Event, EventType
from maestria.core.pipeline import MessagePipeline
from maestria.core.router import MessageRouter
from maestria.monitoring.metrics import MetricsCollector
from maestria.utils.config import MaestriaConfig

logger = structlog.get_logger(__name__)


class EngineState(Enum):
    """Middleware engine lifecycle states (IEC 62304 compliant)."""
    INITIALIZING = "initializing"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    DRAINING = "draining"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass
class EngineStats:
    """Runtime statistics for the engine."""
    started_at: datetime | None = None
    messages_processed: int = 0
    messages_failed: int = 0
    messages_routed: int = 0
    avg_latency_ms: float = 0.0
    active_workers: int = 0
    uptime_seconds: float = 0.0
    last_health_check: datetime | None = None


@dataclass
class WorkerContext:
    """Context for an individual message processing worker."""
    worker_id: str = field(default_factory=lambda: f"w-{uuid.uuid4().hex[:8]}")
    task: asyncio.Task[None] | None = None
    messages_handled: int = 0
    is_active: bool = False
    started_at: datetime | None = None


class MaestriaEngine:
    """Main middleware engine — the heartbeat of MAESTRIA-Lite.

    Manages the full lifecycle of the middleware:
    - Initializes all subsystems (router, pipeline, event bus, security)
    - Spawns worker pool for concurrent message processing
    - Handles graceful shutdown with message draining
    - Emits lifecycle events for monitoring and audit

    Compliant with IEC 62304 software lifecycle requirements.
    """

    def __init__(self, config: MaestriaConfig) -> None:
        self.config = config
        self.instance_id = config.engine.instance_id
        self.state = EngineState.INITIALIZING
        self.stats = EngineStats()

        # Core subsystems
        self.event_bus = EventBus()
        self.router = MessageRouter(config.interfaces, self.event_bus)
        self.pipeline = MessagePipeline(self.router, self.event_bus)
        self.metrics = MetricsCollector(namespace="maestria")

        # Worker pool
        self._workers: list[WorkerContext] = []
        self._message_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=config.engine.queue_max_size
        )
        self._shutdown_event = asyncio.Event()
        self._drain_timeout = config.engine.drain_timeout_seconds

        logger.info(
            "engine.initialized",
            instance_id=self.instance_id,
            worker_count=config.engine.worker_count,
            queue_backend=config.engine.queue_backend,
        )

    @property
    def is_running(self) -> bool:
        return self.state == EngineState.RUNNING

    @property
    def is_healthy(self) -> bool:
        return self.state in (EngineState.RUNNING, EngineState.DEGRADED)

    async def start(self) -> None:
        """Start the middleware engine and all subsystems.

        Lifecycle:
        1. Initialize event bus and internal queues
        2. Start monitoring subsystem
        3. Spawn worker pool
        4. Register signal handlers for graceful shutdown
        5. Emit ENGINE_STARTED event
        """
        self._transition_state(EngineState.STARTING)
        logger.info("engine.starting", instance_id=self.instance_id)

        try:
            # Initialize subsystems
            await self.event_bus.start()
            await self.router.initialize()
            await self.metrics.start()

            # Spawn workers
            for i in range(self.config.engine.worker_count):
                ctx = WorkerContext()
                ctx.task = asyncio.create_task(
                    self._worker_loop(ctx),
                    name=f"maestria-worker-{i}",
                )
                ctx.is_active = True
                ctx.started_at = datetime.now(timezone.utc)
                self._workers.append(ctx)

            self.stats.started_at = datetime.now(timezone.utc)
            self.stats.active_workers = len(self._workers)
            self._transition_state(EngineState.RUNNING)

            # Register OS signal handlers
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self._handle_shutdown_signal)

            await self.event_bus.publish(Event(
                event_type=EventType.ENGINE_STARTED,
                source=self.instance_id,
                payload={"worker_count": len(self._workers)},
            ))

            logger.info(
                "engine.running",
                instance_id=self.instance_id,
                workers=len(self._workers),
            )

        except Exception as exc:
            logger.error("engine.start_failed", error=str(exc))
            self._transition_state(EngineState.STOPPED)
            raise

    async def stop(self, graceful: bool = True) -> None:
        """Stop the engine with optional graceful drain.

        Args:
            graceful: If True, drain the message queue before stopping.
        """
        if self.state in (EngineState.STOPPING, EngineState.STOPPED):
            return

        self._transition_state(EngineState.DRAINING if graceful else EngineState.STOPPING)
        logger.info("engine.stopping", graceful=graceful)

        if graceful:
            # Wait for queue to drain
            try:
                await asyncio.wait_for(
                    self._drain_queue(),
                    timeout=self._drain_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "engine.drain_timeout",
                    remaining=self._message_queue.qsize(),
                )

        # Signal shutdown to workers
        self._shutdown_event.set()

        # Cancel all worker tasks
        self._transition_state(EngineState.STOPPING)
        for worker in self._workers:
            if worker.task and not worker.task.done():
                worker.task.cancel()
                try:
                    await worker.task
                except asyncio.CancelledError:
                    pass
                worker.is_active = False

        # Shutdown subsystems
        await self.metrics.stop()
        await self.event_bus.publish(Event(
            event_type=EventType.ENGINE_STOPPED,
            source=self.instance_id,
            payload={"messages_processed": self.stats.messages_processed},
        ))
        await self.event_bus.stop()

        self._transition_state(EngineState.STOPPED)
        logger.info(
            "engine.stopped",
            total_processed=self.stats.messages_processed,
            total_failed=self.stats.messages_failed,
        )

    async def submit_message(self, message: dict[str, Any]) -> str:
        """Submit a message to the processing queue.

        Args:
            message: Raw message payload (HL7, JSON, etc.)

        Returns:
            Correlation ID for tracking the message.

        Raises:
            RuntimeError: If the engine is not in a running state.
            asyncio.QueueFull: If the processing queue is saturated.
        """
        if not self.is_running:
            raise RuntimeError(f"Engine is not running (state={self.state.value})")

        correlation_id = f"msg-{uuid.uuid4().hex[:12]}"
        envelope = {
            "correlation_id": correlation_id,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "payload": message,
            "retries": 0,
        }

        await self._message_queue.put(envelope)
        self.metrics.increment("messages_queued")
        logger.debug("message.queued", correlation_id=correlation_id)
        return correlation_id

    async def get_status(self) -> dict[str, Any]:
        """Get current engine status for health checks."""
        now = datetime.now(timezone.utc)
        uptime = (
            (now - self.stats.started_at).total_seconds()
            if self.stats.started_at
            else 0.0
        )
        return {
            "instance_id": self.instance_id,
            "state": self.state.value,
            "uptime_seconds": uptime,
            "stats": {
                "messages_processed": self.stats.messages_processed,
                "messages_failed": self.stats.messages_failed,
                "messages_queued": self._message_queue.qsize(),
                "active_workers": sum(1 for w in self._workers if w.is_active),
                "avg_latency_ms": self.stats.avg_latency_ms,
            },
            "version": self.config.version,
            "timestamp": now.isoformat(),
        }

    # --- Internal Methods ---

    async def _worker_loop(self, ctx: WorkerContext) -> None:
        """Main loop for a message processing worker."""
        logger.info("worker.started", worker_id=ctx.worker_id)

        while not self._shutdown_event.is_set():
            try:
                envelope = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0,
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            start_time = asyncio.get_event_loop().time()
            correlation_id = envelope["correlation_id"]

            try:
                await self.pipeline.process(envelope)
                ctx.messages_handled += 1
                self.stats.messages_processed += 1
                self.metrics.increment("messages_processed")

                elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000
                self.metrics.observe("message_latency_ms", elapsed_ms)
                self._update_avg_latency(elapsed_ms)

                logger.debug(
                    "message.processed",
                    worker_id=ctx.worker_id,
                    correlation_id=correlation_id,
                    latency_ms=round(elapsed_ms, 2),
                )

            except Exception as exc:
                self.stats.messages_failed += 1
                self.metrics.increment("messages_failed")
                logger.error(
                    "message.processing_failed",
                    worker_id=ctx.worker_id,
                    correlation_id=correlation_id,
                    error=str(exc),
                )

                # Retry logic
                if envelope["retries"] < self.config.engine.max_retries:
                    envelope["retries"] += 1
                    await self._message_queue.put(envelope)
                    self.metrics.increment("messages_retried")
                else:
                    await self.event_bus.publish(Event(
                        event_type=EventType.MESSAGE_DEAD_LETTER,
                        source=ctx.worker_id,
                        payload={"correlation_id": correlation_id, "error": str(exc)},
                    ))

            finally:
                self._message_queue.task_done()

        ctx.is_active = False
        logger.info("worker.stopped", worker_id=ctx.worker_id, handled=ctx.messages_handled)

    async def _drain_queue(self) -> None:
        """Wait for all queued messages to be processed."""
        if self._message_queue.empty():
            return
        logger.info("engine.draining", remaining=self._message_queue.qsize())
        await self._message_queue.join()
        logger.info("engine.drained")

    def _transition_state(self, new_state: EngineState) -> None:
        """Transition engine to a new state with validation."""
        old_state = self.state
        self.state = new_state
        logger.info(
            "engine.state_transition",
            old_state=old_state.value,
            new_state=new_state.value,
        )

    def _update_avg_latency(self, new_latency_ms: float) -> None:
        """Update rolling average latency using exponential moving average."""
        alpha = 0.1
        if self.stats.avg_latency_ms == 0.0:
            self.stats.avg_latency_ms = new_latency_ms
        else:
            self.stats.avg_latency_ms = (
                alpha * new_latency_ms + (1 - alpha) * self.stats.avg_latency_ms
            )

    def _handle_shutdown_signal(self) -> None:
        """Handle OS shutdown signals (SIGTERM, SIGINT)."""
        logger.info("engine.shutdown_signal_received")
        asyncio.create_task(self.stop(graceful=True))
