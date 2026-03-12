"""Interface Contract Management.

Defines, validates, and versions interface contracts between MAESTRIA-Lite
and connected systems (instruments, LIS, HIS). Contracts are JSON Schema-based
and ensure that all data exchanged conforms to agreed-upon specifications.

Supports:
- Contract definition with JSON Schema
- Versioning with semver + backward compatibility checks
- Runtime validation of inbound/outbound messages
- Contract audit trail
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ContractStatus(Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """A single contract validation issue."""
    path: str
    message: str
    severity: ValidationSeverity
    rule: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "message": self.message,
            "severity": self.severity.value,
            "rule": self.rule,
        }


@dataclass
class ValidationResult:
    """Aggregate result of contract validation."""
    contract_id: str
    version: str
    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    validated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == ValidationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == ValidationSeverity.WARNING)


@dataclass
class InterfaceContract:
    """An interface contract defining data exchange rules with a connected system.

    Attributes:
        contract_id: Unique identifier (e.g., 'lis-primary-oru-v2').
        name: Human-readable name.
        version: Semantic version string.
        system_id: The connected system this contract applies to.
        direction: 'inbound' (from system), 'outbound' (to system), or 'bidirectional'.
        message_types: HL7 message types covered by this contract.
        schema: JSON Schema defining the expected message structure.
        status: Current lifecycle status.
        checksum: SHA-256 of the schema for integrity verification.
        metadata: Additional contract metadata.
    """
    contract_id: str
    name: str
    version: str
    system_id: str
    direction: str  # inbound | outbound | bidirectional
    message_types: list[str]
    schema: dict[str, Any]
    status: ContractStatus = ContractStatus.DRAFT
    checksum: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.checksum:
            self.checksum = self._compute_checksum()

    def _compute_checksum(self) -> str:
        schema_bytes = json.dumps(self.schema, sort_keys=True).encode()
        return hashlib.sha256(schema_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "name": self.name,
            "version": self.version,
            "system_id": self.system_id,
            "direction": self.direction,
            "message_types": self.message_types,
            "status": self.status.value,
            "checksum": self.checksum,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ContractValidator:
    """Validates messages against interface contracts using JSON Schema.

    Performs both structural validation (schema conformance) and
    semantic validation (business rule checks).
    """

    def validate(
        self,
        message: dict[str, Any],
        contract: InterfaceContract,
    ) -> ValidationResult:
        """Validate a message against a contract's JSON Schema.

        Args:
            message: Parsed message data to validate.
            contract: The interface contract to validate against.

        Returns:
            ValidationResult with any issues found.
        """
        issues: list[ValidationIssue] = []

        # Schema-based validation
        try:
            import jsonschema
            validator = jsonschema.Draft7Validator(contract.schema)
            for error in validator.iter_errors(message):
                issues.append(ValidationIssue(
                    path="/".join(str(p) for p in error.absolute_path) or "/",
                    message=error.message,
                    severity=ValidationSeverity.ERROR,
                    rule="json_schema",
                ))
        except ImportError:
            # Fallback: basic key presence check
            issues.extend(self._basic_validate(message, contract.schema))

        # Semantic checks
        issues.extend(self._semantic_checks(message, contract))

        is_valid = all(i.severity != ValidationSeverity.ERROR for i in issues)

        result = ValidationResult(
            contract_id=contract.contract_id,
            version=contract.version,
            is_valid=is_valid,
            issues=issues,
        )

        logger.info(
            "contract.validated",
            contract_id=contract.contract_id,
            valid=is_valid,
            errors=result.error_count,
            warnings=result.warning_count,
        )
        return result

    def _basic_validate(
        self,
        message: dict[str, Any],
        schema: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Fallback validation when jsonschema is not available."""
        issues = []
        required = schema.get("required", [])
        for field_name in required:
            if field_name not in message:
                issues.append(ValidationIssue(
                    path=f"/{field_name}",
                    message=f"Required field '{field_name}' is missing",
                    severity=ValidationSeverity.ERROR,
                    rule="required_field",
                ))
        return issues

    def _semantic_checks(
        self,
        message: dict[str, Any],
        contract: InterfaceContract,
    ) -> list[ValidationIssue]:
        """Perform semantic business-rule validation."""
        issues = []

        # Check message type matches contract scope
        msg_type = message.get("message_type", "")
        if msg_type and contract.message_types:
            if msg_type not in contract.message_types:
                issues.append(ValidationIssue(
                    path="/message_type",
                    message=(
                        f"Message type '{msg_type}' not covered by contract "
                        f"(expected: {contract.message_types})"
                    ),
                    severity=ValidationSeverity.WARNING,
                    rule="message_type_scope",
                ))

        return issues


class ContractRegistry:
    """Registry of all interface contracts.

    Manages loading, versioning, and lookup of contracts
    from the filesystem or database.
    """

    def __init__(self) -> None:
        self._contracts: dict[str, InterfaceContract] = {}
        self._validator = ContractValidator()

    def register(self, contract: InterfaceContract) -> None:
        """Register or update a contract."""
        self._contracts[contract.contract_id] = contract
        logger.info(
            "contract.registered",
            contract_id=contract.contract_id,
            version=contract.version,
            status=contract.status.value,
        )

    def get(self, contract_id: str) -> InterfaceContract | None:
        return self._contracts.get(contract_id)

    def get_for_system(self, system_id: str) -> list[InterfaceContract]:
        return [
            c for c in self._contracts.values()
            if c.system_id == system_id and c.status == ContractStatus.ACTIVE
        ]

    def validate_message(
        self,
        message: dict[str, Any],
        contract_id: str,
    ) -> ValidationResult:
        """Validate a message against a registered contract."""
        contract = self.get(contract_id)
        if contract is None:
            return ValidationResult(
                contract_id=contract_id,
                version="unknown",
                is_valid=False,
                issues=[ValidationIssue(
                    path="/",
                    message=f"Contract '{contract_id}' not found",
                    severity=ValidationSeverity.ERROR,
                    rule="contract_exists",
                )],
            )
        return self._validator.validate(message, contract)

    def load_from_directory(self, directory: str | Path) -> int:
        """Load contracts from JSON files in a directory.

        Returns:
            Number of contracts loaded.
        """
        path = Path(directory)
        loaded = 0
        if not path.exists():
            logger.warning("contract.dir_not_found", directory=str(path))
            return 0

        for file in path.glob("*.json"):
            try:
                with open(file) as f:
                    data = json.load(f)
                contract = InterfaceContract(
                    contract_id=data["contract_id"],
                    name=data["name"],
                    version=data["version"],
                    system_id=data["system_id"],
                    direction=data.get("direction", "bidirectional"),
                    message_types=data.get("message_types", []),
                    schema=data.get("schema", {}),
                    status=ContractStatus(data.get("status", "active")),
                )
                self.register(contract)
                loaded += 1
            except (json.JSONDecodeError, KeyError) as exc:
                logger.error(
                    "contract.load_failed",
                    file=str(file),
                    error=str(exc),
                )

        logger.info("contract.loaded_from_directory", count=loaded, directory=str(path))
        return loaded

    def list_contracts(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self._contracts.values()]
