"""Message Router — Intelligent routing of diagnostic messages.

Routes messages between instruments, LIS, and HIS based on configurable
routing rules. Supports content-based routing, message transformation,
and dead-letter handling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog

from maestria.core.event_bus import EventBus, Event, EventType

logger = structlog.get_logger(__name__)


class RoutingStrategy(Enum):
    """Supported routing strategies."""
    DIRECT = "direct"          # Route to a specific endpoint
    CONTENT_BASED = "content"  # Route based on message content
    BROADCAST = "broadcast"    # Route to all registered endpoints
    ROUND_ROBIN = "round_robin"  # Distribute across endpoints


class EndpointStatus(Enum):
    """Health status of a connected endpoint."""
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


@dataclass
class Endpoint:
    """A connected system endpoint (instrument, LIS, HIS)."""
    endpoint_id: str
    name: str
    system_type: str  # "instrument" | "lis" | "his" | "middleware"
    protocol: str     # "hl7v2" | "fhir" | "json" | "astm"
    address: str
    status: EndpointStatus = EndpointStatus.OFFLINE
    contract_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    last_seen: datetime | None = None
    message_count: int = 0


@dataclass
class RoutingRule:
    """A message routing rule.

    Attributes:
        rule_id: Unique identifier for this rule.
        name: Human-readable name.
        strategy: How messages matching this rule are routed.
        source_filter: Regex pattern matching source endpoint IDs.
        message_type_filter: Regex pattern matching HL7 message types.
        field_filters: Key-value pairs that must match in message fields.
        target_endpoints: List of target endpoint IDs.
        priority: Higher priority rules are evaluated first.
        enabled: Whether this rule is active.
        transform: Optional transformation to apply before routing.
    """
    rule_id: str
    name: str
    strategy: RoutingStrategy
    source_filter: str = ".*"
    message_type_filter: str = ".*"
    field_filters: dict[str, str] = field(default_factory=dict)
    target_endpoints: list[str] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True
    transform: dict[str, Any] | None = None


@dataclass
class RoutingResult:
    """Outcome of routing a message."""
    correlation_id: str
    matched_rule: str | None
    targets: list[str]
    strategy: RoutingStrategy
    transformed: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class MessageRouter:
    """Routes diagnostic messages between connected systems.

    Evaluates routing rules in priority order, validates endpoints,
    and manages delivery with observability events.
    """

    def __init__(self, config: Any, event_bus: EventBus) -> None:
        self._config = config
        self._event_bus = event_bus
        self._endpoints: dict[str, Endpoint] = {}
        self._rules: list[RoutingRule] = []
        self._round_robin_index: dict[str, int] = {}

    async def initialize(self) -> None:
        """Load routing rules and register default endpoints."""
        self._load_default_rules()
        logger.info("router.initialized", rules=len(self._rules))

    def register_endpoint(self, endpoint: Endpoint) -> None:
        """Register a connected system endpoint."""
        self._endpoints[endpoint.endpoint_id] = endpoint
        logger.info(
            "router.endpoint_registered",
            endpoint_id=endpoint.endpoint_id,
            system_type=endpoint.system_type,
            protocol=endpoint.protocol,
        )

    def unregister_endpoint(self, endpoint_id: str) -> None:
        """Remove a connected system endpoint."""
        self._endpoints.pop(endpoint_id, None)
        logger.info("router.endpoint_unregistered", endpoint_id=endpoint_id)

    def add_rule(self, rule: RoutingRule) -> None:
        """Add a routing rule and re-sort by priority."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)
        logger.info("router.rule_added", rule_id=rule.rule_id, priority=rule.priority)

    async def route(self, envelope: dict[str, Any]) -> RoutingResult:
        """Route a message envelope to target endpoints.

        Args:
            envelope: Message envelope containing payload and metadata.

        Returns:
            RoutingResult with matched rule and target endpoints.
        """
        correlation_id = envelope.get("correlation_id", "unknown")
        payload = envelope.get("payload", {})
        source = payload.get("source_endpoint", "")
        msg_type = payload.get("message_type", "")

        # Evaluate rules in priority order
        for rule in self._rules:
            if not rule.enabled:
                continue

            if self._matches_rule(rule, source, msg_type, payload):
                targets = self._resolve_targets(rule)
                result = RoutingResult(
                    correlation_id=correlation_id,
                    matched_rule=rule.rule_id,
                    targets=targets,
                    strategy=rule.strategy,
                )

                await self._event_bus.publish(Event(
                    event_type=EventType.MESSAGE_ROUTED,
                    source="router",
                    correlation_id=correlation_id,
                    payload={
                        "rule": rule.rule_id,
                        "targets": targets,
                        "strategy": rule.strategy.value,
                    },
                ))

                logger.debug(
                    "router.message_routed",
                    correlation_id=correlation_id,
                    rule=rule.rule_id,
                    targets=targets,
                )
                return result

        # No matching rule — dead letter
        logger.warning(
            "router.no_matching_rule",
            correlation_id=correlation_id,
            source=source,
            message_type=msg_type,
        )
        return RoutingResult(
            correlation_id=correlation_id,
            matched_rule=None,
            targets=[],
            strategy=RoutingStrategy.DIRECT,
        )

    def get_endpoints(
        self,
        status: EndpointStatus | None = None,
    ) -> list[Endpoint]:
        """List registered endpoints, optionally filtered by status."""
        endpoints = list(self._endpoints.values())
        if status:
            endpoints = [ep for ep in endpoints if ep.status == status]
        return endpoints

    # --- Internal ---

    def _matches_rule(
        self,
        rule: RoutingRule,
        source: str,
        msg_type: str,
        payload: dict[str, Any],
    ) -> bool:
        """Check if a message matches a routing rule."""
        if not re.match(rule.source_filter, source):
            return False
        if not re.match(rule.message_type_filter, msg_type):
            return False
        for key, pattern in rule.field_filters.items():
            value = str(payload.get(key, ""))
            if not re.match(pattern, value):
                return False
        return True

    def _resolve_targets(self, rule: RoutingRule) -> list[str]:
        """Resolve target endpoints based on routing strategy."""
        if rule.strategy == RoutingStrategy.BROADCAST:
            return [
                ep_id for ep_id, ep in self._endpoints.items()
                if ep.status == EndpointStatus.ONLINE
            ]

        if rule.strategy == RoutingStrategy.ROUND_ROBIN:
            online = [
                ep_id for ep_id in rule.target_endpoints
                if self._endpoints.get(ep_id, Endpoint(
                    endpoint_id="", name="", system_type="",
                    protocol="", address=""
                )).status == EndpointStatus.ONLINE
            ]
            if not online:
                return []
            idx = self._round_robin_index.get(rule.rule_id, 0) % len(online)
            self._round_robin_index[rule.rule_id] = idx + 1
            return [online[idx]]

        # DIRECT or CONTENT_BASED: return configured targets that are online
        return [
            ep_id for ep_id in rule.target_endpoints
            if ep_id in self._endpoints
            and self._endpoints[ep_id].status == EndpointStatus.ONLINE
        ]

    def _load_default_rules(self) -> None:
        """Load default routing rules for common IVD message flows."""
        self._rules = [
            RoutingRule(
                rule_id="oru-to-lis",
                name="Route ORU results to LIS",
                strategy=RoutingStrategy.DIRECT,
                message_type_filter=r"ORU.*",
                target_endpoints=["lis-primary"],
                priority=100,
            ),
            RoutingRule(
                rule_id="orm-to-instruments",
                name="Route ORM orders to instruments",
                strategy=RoutingStrategy.CONTENT_BASED,
                message_type_filter=r"ORM.*",
                target_endpoints=["analyzer-01", "analyzer-02"],
                priority=90,
            ),
            RoutingRule(
                rule_id="adt-broadcast",
                name="Broadcast ADT events to all systems",
                strategy=RoutingStrategy.BROADCAST,
                message_type_filter=r"ADT.*",
                priority=80,
            ),
            RoutingRule(
                rule_id="ack-direct",
                name="Route ACK back to source",
                strategy=RoutingStrategy.DIRECT,
                message_type_filter=r"ACK.*",
                priority=70,
            ),
        ]
