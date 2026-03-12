"""Configuration Management.

Loads, validates, and provides typed access to MAESTRIA-Lite configuration
from YAML files, environment variables, and CLI arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class EngineConfig:
    """Engine-level configuration."""
    instance_id: str = "MAESTRIA-DEV-001"
    worker_count: int = 4
    queue_backend: str = "memory"  # memory | redis
    queue_max_size: int = 10_000
    max_retries: int = 3
    drain_timeout_seconds: float = 30.0
    max_message_size: int = 1_048_576  # 1MB


@dataclass
class InterfacesConfig:
    """Interface and protocol configuration."""
    contract_dir: str = "config/contracts"
    strict_validation: bool = True
    hl7_version: str = "2.5.1"
    hl7_encoding: str = "unicode"
    field_separator: str = "|"


@dataclass
class SecurityConfig:
    """Security module configuration."""
    cve_scan_interval: int = 86400
    sbom_format: str = "cyclonedx"
    compliance_framework: str = "iec62443"
    tls_enabled: bool = True
    tls_min_version: str = "1.2"


@dataclass
class PatchConfig:
    """Patch management configuration."""
    cycle: str = "quarterly"
    require_signature: bool = True
    rollback_retention: int = 3


@dataclass
class MonitoringConfig:
    """Monitoring and observability configuration."""
    metrics_port: int = 9090
    health_port: int = 8080
    audit_format: str = "cef"


@dataclass
class MaestriaConfig:
    """Root configuration for the MAESTRIA-Lite middleware."""
    version: str = "2.4.1"
    environment: str = "development"
    engine: EngineConfig = field(default_factory=EngineConfig)
    interfaces: InterfacesConfig = field(default_factory=InterfacesConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    patches: PatchConfig = field(default_factory=PatchConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MaestriaConfig:
        """Create config from a dictionary (e.g., parsed YAML)."""
        maestria = data.get("maestria", data)
        return cls(
            version=maestria.get("version", "2.4.1"),
            environment=maestria.get("environment", "development"),
            engine=EngineConfig(**maestria.get("engine", {})),
            interfaces=InterfacesConfig(**maestria.get("interfaces", {})),
            security=SecurityConfig(**maestria.get("security", {})),
            patches=PatchConfig(**maestria.get("patches", {})),
            monitoring=MonitoringConfig(**maestria.get("monitoring", {})),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> MaestriaConfig:
        """Load config from a YAML file."""
        import yaml
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("config.file_not_found", path=str(path))
            return cls()
        with open(file_path) as f:
            data = yaml.safe_load(f) or {}
        config = cls.from_dict(data)
        logger.info("config.loaded", path=str(path), environment=config.environment)
        return config

    @classmethod
    def default(cls) -> MaestriaConfig:
        """Return default development configuration."""
        return cls()
