"""HL7v2 Message Parser for Laboratory Diagnostic Systems.

Parses HL7 version 2.x messages commonly used in IVD environments.
Supports message types: ORM (orders), ORU (results), ADT (patient admin),
ACK (acknowledgments), QRY (queries).

Reference: HL7 International — Health Level Seven v2.5.1
Segments: MSH, PID, PV1, ORC, OBR, OBX, NTE, ERR
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Standard HL7v2 delimiters
DEFAULT_FIELD_SEP = "|"
DEFAULT_COMPONENT_SEP = "^"
DEFAULT_REPEAT_SEP = "~"
DEFAULT_ESCAPE_CHAR = "\\"
DEFAULT_SUBCOMPONENT_SEP = "&"


@dataclass
class HL7Field:
    """A single HL7 field with optional components and repetitions."""
    raw: str
    components: list[str] = field(default_factory=list)
    repetitions: list[str] = field(default_factory=list)

    @property
    def value(self) -> str:
        return self.components[0] if self.components else self.raw

    def __str__(self) -> str:
        return self.raw


@dataclass
class HL7Segment:
    """A parsed HL7 segment (e.g., MSH, PID, OBR, OBX)."""
    segment_type: str
    fields: list[HL7Field]
    raw: str

    def get_field(self, index: int) -> HL7Field | None:
        """Get field by 1-based index (HL7 convention)."""
        if 0 < index <= len(self.fields):
            return self.fields[index - 1]
        return None

    def get_value(self, index: int, component: int = 0) -> str:
        """Get a field value by index and optional component."""
        fld = self.get_field(index)
        if fld is None:
            return ""
        if component > 0 and component <= len(fld.components):
            return fld.components[component - 1]
        return fld.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_type": self.segment_type,
            "fields": [f.raw for f in self.fields],
        }


@dataclass
class HL7Message:
    """A fully parsed HL7v2 message with segment-level access."""
    raw: str
    message_type: str = ""
    trigger_event: str = ""
    version: str = ""
    control_id: str = ""
    sending_app: str = ""
    sending_facility: str = ""
    receiving_app: str = ""
    receiving_facility: str = ""
    timestamp: str = ""
    segments: dict[str, list[HL7Segment]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0 and "msh" in self.segments

    def get_segments(self, segment_type: str) -> list[HL7Segment]:
        """Get all segments of a given type."""
        return self.segments.get(segment_type.lower(), [])

    def get_first_segment(self, segment_type: str) -> HL7Segment | None:
        """Get the first segment of a given type."""
        segs = self.get_segments(segment_type)
        return segs[0] if segs else None

    def get_patient_id(self) -> str:
        """Extract patient ID from PID segment."""
        pid = self.get_first_segment("pid")
        if pid:
            return pid.get_value(3)
        return ""

    def get_order_id(self) -> str:
        """Extract order/placer ID from ORC segment."""
        orc = self.get_first_segment("orc")
        if orc:
            return orc.get_value(2)
        return ""

    def get_observations(self) -> list[dict[str, str]]:
        """Extract all observation results from OBX segments."""
        results = []
        for obx in self.get_segments("obx"):
            results.append({
                "set_id": obx.get_value(1),
                "value_type": obx.get_value(2),
                "identifier": obx.get_value(3),
                "value": obx.get_value(5),
                "units": obx.get_value(6),
                "reference_range": obx.get_value(7),
                "abnormal_flags": obx.get_value(8),
                "status": obx.get_value(11),
            })
        return results

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_type": self.message_type,
            "trigger_event": self.trigger_event,
            "version": self.version,
            "control_id": self.control_id,
            "sending_app": self.sending_app,
            "sending_facility": self.sending_facility,
            "receiving_app": self.receiving_app,
            "receiving_facility": self.receiving_facility,
            "timestamp": self.timestamp,
            "is_valid": self.is_valid,
            "errors": self.errors,
            "segments": {
                seg_type: [s.to_dict() for s in segs]
                for seg_type, segs in self.segments.items()
            },
        }


class HL7v2Parser:
    """Parser for HL7 v2.x messages.

    Handles the full parsing lifecycle:
    1. Detect delimiters from MSH segment
    2. Split message into segments
    3. Parse each segment into typed fields
    4. Extract header metadata
    5. Validate structural integrity

    Example:
        parser = HL7v2Parser()
        msg = parser.parse(raw_hl7_string)
        if msg.is_valid:
            patient_id = msg.get_patient_id()
            results = msg.get_observations()
    """

    def __init__(
        self,
        field_sep: str = DEFAULT_FIELD_SEP,
        component_sep: str = DEFAULT_COMPONENT_SEP,
        repeat_sep: str = DEFAULT_REPEAT_SEP,
    ) -> None:
        self.field_sep = field_sep
        self.component_sep = component_sep
        self.repeat_sep = repeat_sep

    def parse(self, raw: str) -> HL7Message:
        """Parse a raw HL7v2 message string.

        Args:
            raw: Raw HL7v2 message with \\r or \\n segment separators.

        Returns:
            HL7Message with parsed segments and extracted metadata.
        """
        message = HL7Message(raw=raw)

        # Normalize line endings
        raw = raw.strip()
        lines = re.split(r"[\r\n]+", raw)
        lines = [line.strip() for line in lines if line.strip()]

        if not lines:
            message.errors.append("Empty message")
            return message

        # First line must be MSH
        if not lines[0].startswith("MSH"):
            message.errors.append(
                f"Message must start with MSH segment, got: {lines[0][:10]}"
            )
            return message

        # Detect delimiters from MSH-1 and MSH-2
        msh_line = lines[0]
        if len(msh_line) >= 8:
            self.field_sep = msh_line[3]
            encoding_chars = msh_line[4:8]
            if len(encoding_chars) >= 4:
                self.component_sep = encoding_chars[0]
                self.repeat_sep = encoding_chars[1]

        # Parse all segments
        for line in lines:
            try:
                segment = self._parse_segment(line)
                seg_key = segment.segment_type.lower()
                if seg_key not in message.segments:
                    message.segments[seg_key] = []
                message.segments[seg_key].append(segment)
            except Exception as exc:
                message.errors.append(f"Failed to parse segment: {exc}")

        # Extract header metadata from MSH
        msh = message.get_first_segment("msh")
        if msh:
            message.sending_app = msh.get_value(3)
            message.sending_facility = msh.get_value(4)
            message.receiving_app = msh.get_value(5)
            message.receiving_facility = msh.get_value(6)
            message.timestamp = msh.get_value(7)
            msg_type_field = msh.get_field(9)
            if msg_type_field:
                parts = msg_type_field.raw.split(self.component_sep)
                message.message_type = parts[0] if len(parts) > 0 else ""
                message.trigger_event = parts[1] if len(parts) > 1 else ""
            message.control_id = msh.get_value(10)
            message.version = msh.get_value(12)

        # Structural validation
        self._validate_structure(message)

        logger.debug(
            "hl7.parsed",
            message_type=message.message_type,
            trigger=message.trigger_event,
            segments=len(lines),
            valid=message.is_valid,
        )
        return message

    def _parse_segment(self, line: str) -> HL7Segment:
        """Parse a single HL7 segment line into structured fields."""
        parts = line.split(self.field_sep)
        segment_type = parts[0]

        fields = []
        field_data = parts[1:] if segment_type == "MSH" else parts[1:]

        # For MSH, field 1 is the separator itself
        if segment_type == "MSH":
            fields.append(HL7Field(
                raw=self.field_sep,
                components=[self.field_sep],
            ))

        for raw_field in field_data:
            components = raw_field.split(self.component_sep)
            repetitions = raw_field.split(self.repeat_sep)
            fields.append(HL7Field(
                raw=raw_field,
                components=components,
                repetitions=repetitions,
            ))

        return HL7Segment(
            segment_type=segment_type,
            fields=fields,
            raw=line,
        )

    def _validate_structure(self, message: HL7Message) -> None:
        """Validate structural integrity of the parsed message."""
        if not message.message_type:
            message.errors.append("Missing message type in MSH-9")

        if not message.control_id:
            message.errors.append("Missing message control ID in MSH-10")

        # Validate expected segment combinations
        msg_type = message.message_type.upper()
        if msg_type == "ORU":
            if not message.get_segments("obr"):
                message.errors.append("ORU message missing OBR segment")
            if not message.get_segments("obx"):
                message.errors.append("ORU message missing OBX segment")
        elif msg_type == "ORM":
            if not message.get_segments("orc"):
                message.errors.append("ORM message missing ORC segment")

    @staticmethod
    def build_ack(
        original_control_id: str,
        ack_code: str = "AA",
        error_message: str = "",
    ) -> dict[str, str]:
        """Build an ACK response message.

        Args:
            original_control_id: MSH-10 from the original message.
            ack_code: AA (accept), AE (error), AR (reject).
            error_message: Optional error description for AE/AR.

        Returns:
            Dictionary with ACK fields.
        """
        now = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return {
            "message_type": "ACK",
            "timestamp": now,
            "original_control_id": original_control_id,
            "ack_code": ack_code,
            "error_message": error_message,
            "raw": (
                f"MSH|^~\\&|MAESTRIA|MIDDLEWARE||{now}||ACK|{now}|P|2.5.1\r"
                f"MSA|{ack_code}|{original_control_id}|{error_message}"
            ),
        }


# --- Convenience builder for test messages ---

class HL7MessageBuilder:
    """Fluent builder for constructing HL7v2 messages (useful for testing)."""

    def __init__(self) -> None:
        self._segments: list[str] = []
        self._msh_fields: dict[int, str] = {
            3: "MAESTRIA",
            4: "LAB",
            5: "",
            6: "",
            9: "ORU^R01",
            10: "",
            11: "P",
            12: "2.5.1",
        }

    def set_message_type(self, msg_type: str, trigger: str) -> HL7MessageBuilder:
        self._msh_fields[9] = f"{msg_type}^{trigger}"
        return self

    def set_sending(self, app: str, facility: str) -> HL7MessageBuilder:
        self._msh_fields[3] = app
        self._msh_fields[4] = facility
        return self

    def set_receiving(self, app: str, facility: str) -> HL7MessageBuilder:
        self._msh_fields[5] = app
        self._msh_fields[6] = facility
        return self

    def set_control_id(self, control_id: str) -> HL7MessageBuilder:
        self._msh_fields[10] = control_id
        return self

    def add_pid(
        self,
        patient_id: str,
        last_name: str = "",
        first_name: str = "",
        dob: str = "",
    ) -> HL7MessageBuilder:
        name = f"{last_name}^{first_name}" if last_name else ""
        self._segments.append(f"PID|1||{patient_id}||{name}||{dob}")
        return self

    def add_obr(
        self,
        set_id: str = "1",
        placer_order: str = "",
        test_code: str = "",
        test_name: str = "",
    ) -> HL7MessageBuilder:
        self._segments.append(
            f"OBR|{set_id}|{placer_order}||{test_code}^{test_name}"
        )
        return self

    def add_obx(
        self,
        set_id: str = "1",
        value_type: str = "NM",
        identifier: str = "",
        value: str = "",
        units: str = "",
        ref_range: str = "",
        flag: str = "",
    ) -> HL7MessageBuilder:
        self._segments.append(
            f"OBX|{set_id}|{value_type}|{identifier}||{value}|{units}|{ref_range}|{flag}|||F"
        )
        return self

    def add_orc(
        self,
        order_control: str = "NW",
        placer_order: str = "",
    ) -> HL7MessageBuilder:
        self._segments.append(f"ORC|{order_control}|{placer_order}")
        return self

    def build(self) -> str:
        """Build the raw HL7v2 message string."""
        now = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        control_id = self._msh_fields[10] or now

        msh = (
            f"MSH|^~\\&|{self._msh_fields[3]}|{self._msh_fields[4]}"
            f"|{self._msh_fields[5]}|{self._msh_fields[6]}"
            f"|{now}||{self._msh_fields[9]}|{control_id}"
            f"|{self._msh_fields[11]}|{self._msh_fields[12]}"
        )

        all_segments = [msh] + self._segments
        return "\r".join(all_segments)
