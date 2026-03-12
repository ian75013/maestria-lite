"""Message Processing Pipeline.

Multi-stage pipeline for processing diagnostic messages:
1. Parse — Decode raw message (HL7v2, ASTM, JSON)
2. Validate — Check against interface contract
3. Transform — Enrich / map fields
4. Route — Send to target endpoint(s)
5. Acknowledge — Generate ACK/NAK response

Each stage is a composable async step with observability hooks.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

import structlog

from maestria.core.event_bus import EventBus, Event, EventType

logger = structlog.get_logger(__name__)

PipelineStep = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class PipelineStage(Enum):
    PARSE = "parse"
    VALIDATE = "validate"
    TRANSFORM = "transform"
    ROUTE = "route"
    ACKNOWLEDGE = "acknowledge"


@dataclass
class StageResult:
    """Result of a single pipeline stage execution."""
    stage: PipelineStage
    success: bool
    duration_ms: float
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class PipelineResult:
    """Aggregate result of the full pipeline execution."""
    correlation_id: str
    stages: list[StageResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    success: bool = True

    @property
    def failed_stage(self) -> PipelineStage | None:
        for stage in self.stages:
            if not stage.success:
                return stage.stage
        return None


class MessagePipeline:
    """Multi-stage message processing pipeline.

    Processes messages through a configurable series of stages.
    Each stage can modify the message envelope and produce events
    for monitoring. Failed stages halt the pipeline and trigger
    error handling.
    """

    def __init__(self, router: Any, event_bus: EventBus) -> None:
        self._router = router
        self._event_bus = event_bus
        self._stages: list[tuple[PipelineStage, PipelineStep]] = []
        self._setup_default_stages()

    def add_stage(self, stage: PipelineStage, step: PipelineStep) -> None:
        """Add a processing stage to the pipeline."""
        self._stages.append((stage, step))
        self._stages.sort(key=lambda s: list(PipelineStage).index(s[0]))

    async def process(self, envelope: dict[str, Any]) -> PipelineResult:
        """Execute the full pipeline on a message envelope.

        Args:
            envelope: Message envelope with payload, metadata, and routing info.

        Returns:
            PipelineResult with per-stage outcomes and timing.
        """
        correlation_id = envelope.get("correlation_id", "unknown")
        result = PipelineResult(correlation_id=correlation_id)
        pipeline_start = time.monotonic()

        for stage_type, step_fn in self._stages:
            stage_start = time.monotonic()
            try:
                envelope = await step_fn(envelope)
                duration = (time.monotonic() - stage_start) * 1000

                result.stages.append(StageResult(
                    stage=stage_type,
                    success=True,
                    duration_ms=round(duration, 2),
                    output={"keys": list(envelope.keys())},
                ))

            except Exception as exc:
                duration = (time.monotonic() - stage_start) * 1000
                result.stages.append(StageResult(
                    stage=stage_type,
                    success=False,
                    duration_ms=round(duration, 2),
                    error=str(exc),
                ))
                result.success = False

                await self._event_bus.publish(Event(
                    event_type=EventType.MESSAGE_DEAD_LETTER,
                    source=f"pipeline.{stage_type.value}",
                    correlation_id=correlation_id,
                    payload={
                        "stage": stage_type.value,
                        "error": str(exc),
                    },
                ))

                logger.error(
                    "pipeline.stage_failed",
                    stage=stage_type.value,
                    correlation_id=correlation_id,
                    error=str(exc),
                )
                break

        result.total_duration_ms = round(
            (time.monotonic() - pipeline_start) * 1000, 2
        )

        logger.info(
            "pipeline.completed",
            correlation_id=correlation_id,
            success=result.success,
            total_ms=result.total_duration_ms,
            stages_completed=len(result.stages),
        )
        return result

    # --- Default Pipeline Stages ---

    def _setup_default_stages(self) -> None:
        """Register the default IVD message processing stages."""
        self._stages = [
            (PipelineStage.PARSE, self._stage_parse),
            (PipelineStage.VALIDATE, self._stage_validate),
            (PipelineStage.TRANSFORM, self._stage_transform),
            (PipelineStage.ROUTE, self._stage_route),
            (PipelineStage.ACKNOWLEDGE, self._stage_acknowledge),
        ]

    async def _stage_parse(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Parse the raw message payload into structured data."""
        payload = envelope.get("payload", {})
        raw = payload.get("raw_message", "")

        if isinstance(raw, str) and raw.startswith("MSH"):
            # HL7v2 message — delegate to HL7 parser
            from maestria.interfaces.hl7_parser import HL7v2Parser
            parser = HL7v2Parser()
            parsed = parser.parse(raw)
            envelope["parsed"] = parsed.to_dict()
            envelope["protocol"] = "hl7v2"
        elif isinstance(payload, dict) and "resourceType" in payload:
            # FHIR resource
            envelope["parsed"] = payload
            envelope["protocol"] = "fhir"
        else:
            envelope["parsed"] = payload
            envelope["protocol"] = "json"

        return envelope

    async def _stage_validate(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Validate the parsed message against its interface contract."""
        parsed = envelope.get("parsed", {})
        protocol = envelope.get("protocol", "unknown")

        # Basic structural validation
        if protocol == "hl7v2":
            required_segments = ["msh"]
            segments = parsed.get("segments", {})
            missing = [s for s in required_segments if s not in segments]
            if missing:
                raise ValueError(
                    f"HL7v2 validation failed: missing segments {missing}"
                )

        envelope["validated"] = True
        await self._event_bus.publish(Event(
            event_type=EventType.MESSAGE_VALIDATED,
            source="pipeline.validate",
            correlation_id=envelope.get("correlation_id"),
            payload={"protocol": protocol},
        ))
        return envelope

    async def _stage_transform(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Transform and enrich the message for target systems."""
        parsed = envelope.get("parsed", {})

        # Add middleware metadata
        envelope["transformed"] = {
            **parsed,
            "_middleware": {
                "processed_by": "maestria-lite",
                "correlation_id": envelope.get("correlation_id"),
                "protocol": envelope.get("protocol"),
            },
        }

        await self._event_bus.publish(Event(
            event_type=EventType.MESSAGE_TRANSFORMED,
            source="pipeline.transform",
            correlation_id=envelope.get("correlation_id"),
        ))
        return envelope

    async def _stage_route(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Route the transformed message to target endpoints."""
        routing_result = await self._router.route(envelope)
        envelope["routing"] = {
            "matched_rule": routing_result.matched_rule,
            "targets": routing_result.targets,
            "strategy": routing_result.strategy.value,
        }
        return envelope

    async def _stage_acknowledge(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Generate acknowledgment for the processed message."""
        protocol = envelope.get("protocol", "unknown")

        if protocol == "hl7v2":
            from maestria.interfaces.hl7_parser import HL7v2Parser
            ack = HL7v2Parser.build_ack(
                original_control_id=envelope.get("parsed", {})
                .get("segments", {})
                .get("msh", {})
                .get("message_control_id", ""),
                ack_code="AA",  # Application Accept
            )
            envelope["acknowledgment"] = ack
        else:
            envelope["acknowledgment"] = {
                "status": "accepted",
                "correlation_id": envelope.get("correlation_id"),
            }

        await self._event_bus.publish(Event(
            event_type=EventType.MESSAGE_DELIVERED,
            source="pipeline.acknowledge",
            correlation_id=envelope.get("correlation_id"),
        ))
        return envelope
