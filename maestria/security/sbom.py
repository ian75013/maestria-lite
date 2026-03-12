"""Software Bill of Materials (SBOM) Generator.

Generates SBOM in CycloneDX 1.5 format for regulatory compliance.
Catalogs all software components, dependencies, and their known
vulnerabilities for supply chain security transparency.

Reference: CycloneDX Specification v1.5 (OWASP)
Compliance: FDA Cybersecurity Guidance, EO 14028
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ComponentType(Enum):
    APPLICATION = "application"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    CONTAINER = "container"


class ComponentScope(Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    EXCLUDED = "excluded"


@dataclass
class ExternalReference:
    """External reference (URL) associated with a component."""
    ref_type: str  # vcs, website, documentation, license, etc.
    url: str


@dataclass
class License:
    """License information for a component."""
    license_id: str  # SPDX identifier (e.g., "MIT", "Apache-2.0")
    name: str = ""
    url: str = ""


@dataclass
class SBOMComponent:
    """A software component in the SBOM.

    Represents a dependency, library, or system component with
    full provenance and licensing information.
    """
    component_type: ComponentType
    name: str
    version: str
    group: str = ""
    description: str = ""
    scope: ComponentScope = ComponentScope.REQUIRED
    purl: str = ""  # Package URL (pkg:pypi/requests@2.31.0)
    cpe: str = ""   # Common Platform Enumeration
    licenses: list[License] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    external_refs: list[ExternalReference] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)

    @property
    def bom_ref(self) -> str:
        """Generate a unique BOM reference for this component."""
        key = f"{self.group}:{self.name}:{self.version}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def to_cyclonedx(self) -> dict[str, Any]:
        """Serialize to CycloneDX 1.5 component format."""
        component: dict[str, Any] = {
            "type": self.component_type.value,
            "bom-ref": self.bom_ref,
            "name": self.name,
            "version": self.version,
        }
        if self.group:
            component["group"] = self.group
        if self.description:
            component["description"] = self.description
        if self.scope != ComponentScope.REQUIRED:
            component["scope"] = self.scope.value
        if self.purl:
            component["purl"] = self.purl
        if self.cpe:
            component["cpe"] = self.cpe
        if self.licenses:
            component["licenses"] = [
                {"license": {"id": lic.license_id}} for lic in self.licenses
            ]
        if self.hashes:
            component["hashes"] = [
                {"alg": alg, "content": val}
                for alg, val in self.hashes.items()
            ]
        if self.external_refs:
            component["externalReferences"] = [
                {"type": ref.ref_type, "url": ref.url}
                for ref in self.external_refs
            ]
        return component


@dataclass
class SBOMMetadata:
    """SBOM document metadata."""
    tool_name: str = "maestria-lite-sbom"
    tool_version: str = "2.4.1"
    authors: list[str] = field(default_factory=list)
    supplier: str = ""
    manufacture_date: str = ""


class SBOMGenerator:
    """Generates Software Bill of Materials in CycloneDX format.

    Catalogs the middleware and all its dependencies for
    regulatory compliance and supply chain security.
    """

    def __init__(self, metadata: SBOMMetadata | None = None) -> None:
        self._components: list[SBOMComponent] = []
        self._dependencies: dict[str, list[str]] = {}  # ref -> [dep_refs]
        self._metadata = metadata or SBOMMetadata()

    def add_component(self, component: SBOMComponent) -> str:
        """Add a component to the SBOM. Returns the bom-ref."""
        self._components.append(component)
        logger.debug(
            "sbom.component_added",
            name=component.name,
            version=component.version,
            type=component.component_type.value,
        )
        return component.bom_ref

    def add_dependency(self, parent_ref: str, child_refs: list[str]) -> None:
        """Record a dependency relationship between components."""
        self._dependencies[parent_ref] = child_refs

    def generate(self) -> dict[str, Any]:
        """Generate the full CycloneDX 1.5 SBOM document.

        Returns:
            Complete SBOM as a dictionary matching CycloneDX 1.5 schema.
        """
        serial = f"urn:uuid:{uuid.uuid4()}"
        now = datetime.now(timezone.utc).isoformat()

        sbom: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": now,
                "tools": [{
                    "name": self._metadata.tool_name,
                    "version": self._metadata.tool_version,
                }],
                "component": {
                    "type": "application",
                    "name": "maestria-lite",
                    "version": self._metadata.tool_version,
                },
            },
            "components": [c.to_cyclonedx() for c in self._components],
        }

        if self._dependencies:
            sbom["dependencies"] = [
                {"ref": parent, "dependsOn": children}
                for parent, children in self._dependencies.items()
            ]

        logger.info(
            "sbom.generated",
            format="CycloneDX 1.5",
            components=len(self._components),
            serial=serial,
        )
        return sbom

    def generate_json(self, indent: int = 2) -> str:
        """Generate SBOM as a formatted JSON string."""
        return json.dumps(self.generate(), indent=indent)

    def load_from_requirements(self, requirements_text: str) -> int:
        """Parse a requirements.txt-style string and add components.

        Returns:
            Number of components added.
        """
        count = 0
        for line in requirements_text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Parse "package==version" or "package>=version"
            for sep in ["==", ">=", "<=", "~=", "!="]:
                if sep in line:
                    name, version = line.split(sep, 1)
                    self.add_component(SBOMComponent(
                        component_type=ComponentType.LIBRARY,
                        name=name.strip(),
                        version=version.strip(),
                        purl=f"pkg:pypi/{name.strip()}@{version.strip()}",
                        scope=ComponentScope.REQUIRED,
                    ))
                    count += 1
                    break
        return count

    @property
    def component_count(self) -> int:
        return len(self._components)

    def get_components_by_type(
        self, component_type: ComponentType,
    ) -> list[SBOMComponent]:
        return [
            c for c in self._components
            if c.component_type == component_type
        ]
