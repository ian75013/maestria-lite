"""Test suite for MAESTRIA-Lite middleware.

Covers: HL7 parsing, contract validation, CVE tracking,
patch management, event bus, monitoring, and pipeline.
"""

from __future__ import annotations

import asyncio
import json
import pytest
from datetime import datetime, timezone

# ─── HL7v2 Parser Tests ───

class TestHL7Parser:
    """Tests for HL7v2 message parsing."""

    def _sample_oru_message(self) -> str:
        return (
            "MSH|^~\\&|ANALYZER-01|LAB|LIS-PRIMARY|HOSPITAL"
            "|20240315120000||ORU^R01|MSG00001|P|2.5.1\r"
            "PID|1||PAT-12345||DOE^JOHN||19800101\r"
            "OBR|1|ORD-001||CBC^Complete Blood Count\r"
            "OBX|1|NM|WBC^White Blood Cells||7.5|10*3/uL|4.5-11.0|N|||F\r"
            "OBX|2|NM|RBC^Red Blood Cells||4.8|10*6/uL|4.2-5.9|N|||F\r"
            "OBX|3|NM|HGB^Hemoglobin||14.2|g/dL|12.0-17.5|N|||F"
        )

    def test_parse_valid_oru(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser

        parser = HL7v2Parser()
        msg = parser.parse(self._sample_oru_message())

        assert msg.is_valid
        assert msg.message_type == "ORU"
        assert msg.trigger_event == "R01"
        assert msg.version == "2.5.1"
        assert msg.sending_app == "ANALYZER-01"
        assert msg.sending_facility == "LAB"
        assert msg.control_id == "MSG00001"

    def test_extract_patient_id(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser

        parser = HL7v2Parser()
        msg = parser.parse(self._sample_oru_message())

        assert msg.get_patient_id() == "PAT-12345"

    def test_extract_observations(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser

        parser = HL7v2Parser()
        msg = parser.parse(self._sample_oru_message())

        observations = msg.get_observations()
        assert len(observations) == 3
        assert observations[0]["identifier"] == "WBC"
        assert observations[0]["value"] == "7.5"
        assert observations[0]["units"] == "10*3/uL"
        assert observations[2]["identifier"] == "HGB"

    def test_parse_empty_message(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser

        parser = HL7v2Parser()
        msg = parser.parse("")
        assert not msg.is_valid
        assert len(msg.errors) > 0

    def test_parse_invalid_start(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser

        parser = HL7v2Parser()
        msg = parser.parse("PID|1||12345")
        assert not msg.is_valid

    def test_build_ack(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser

        ack = HL7v2Parser.build_ack("MSG00001", "AA")
        assert ack["message_type"] == "ACK"
        assert ack["ack_code"] == "AA"
        assert ack["original_control_id"] == "MSG00001"
        assert "MSH" in ack["raw"]
        assert "MSA|AA|MSG00001" in ack["raw"]

    def test_message_builder(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser, HL7MessageBuilder

        raw = (
            HL7MessageBuilder()
            .set_message_type("ORM", "O01")
            .set_sending("MAESTRIA", "MIDDLEWARE")
            .set_receiving("ANALYZER", "LAB")
            .set_control_id("TEST-001")
            .add_pid("P-999", "SMITH", "JANE", "19900515")
            .add_orc("NW", "ORD-500")
            .build()
        )

        parser = HL7v2Parser()
        msg = parser.parse(raw)
        assert msg.message_type == "ORM"
        assert msg.trigger_event == "O01"
        assert msg.get_patient_id() == "P-999"

    def test_to_dict(self) -> None:
        from maestria.interfaces.hl7_parser import HL7v2Parser

        parser = HL7v2Parser()
        msg = parser.parse(self._sample_oru_message())
        d = msg.to_dict()

        assert d["message_type"] == "ORU"
        assert d["is_valid"] is True
        assert "msh" in d["segments"]


# ─── Interface Contract Tests ───

class TestContractValidation:
    """Tests for interface contract management."""

    def _make_contract(self) -> "InterfaceContract":
        from maestria.interfaces.contract import InterfaceContract, ContractStatus

        return InterfaceContract(
            contract_id="test-lis-oru-v1",
            name="LIS ORU Contract v1",
            version="1.0.0",
            system_id="lis-primary",
            direction="inbound",
            message_types=["ORU"],
            schema={
                "type": "object",
                "required": ["message_type", "segments"],
                "properties": {
                    "message_type": {"type": "string"},
                    "segments": {"type": "object"},
                },
            },
            status=ContractStatus.ACTIVE,
        )

    def test_contract_checksum(self) -> None:
        contract = self._make_contract()
        assert len(contract.checksum) == 64  # SHA-256 hex
        # Same schema → same checksum
        contract2 = self._make_contract()
        assert contract.checksum == contract2.checksum

    def test_validate_valid_message(self) -> None:
        from maestria.interfaces.contract import ContractValidator

        contract = self._make_contract()
        validator = ContractValidator()

        message = {"message_type": "ORU", "segments": {"msh": {}, "obx": {}}}
        result = validator.validate(message, contract)
        assert result.is_valid
        assert result.error_count == 0

    def test_validate_missing_required(self) -> None:
        from maestria.interfaces.contract import ContractValidator

        contract = self._make_contract()
        validator = ContractValidator()

        message = {"message_type": "ORU"}  # missing 'segments'
        result = validator.validate(message, contract)
        assert not result.is_valid
        assert result.error_count > 0

    def test_registry_operations(self) -> None:
        from maestria.interfaces.contract import ContractRegistry

        registry = ContractRegistry()
        contract = self._make_contract()
        registry.register(contract)

        assert registry.get("test-lis-oru-v1") is not None
        assert len(registry.get_for_system("lis-primary")) == 1
        assert len(registry.list_contracts()) == 1


# ─── CVE Tracker Tests ───

class TestCVETracker:
    """Tests for vulnerability tracking."""

    def _make_cve(self, cve_id: str = "CVE-2024-12345", score: float = 9.1) -> "CVEEntry":
        from maestria.security.cve_tracker import CVEEntry

        return CVEEntry(
            cve_id=cve_id,
            title="Critical RCE in component X",
            cvss_score=score,
            affected_component="openssl",
            affected_versions=["1.1.1a", "1.1.1b"],
        )

    def test_severity_classification(self) -> None:
        from maestria.security.cve_tracker import CVESeverity

        assert CVESeverity.from_score(9.5) == CVESeverity.CRITICAL
        assert CVESeverity.from_score(7.0) == CVESeverity.HIGH
        assert CVESeverity.from_score(5.5) == CVESeverity.MEDIUM
        assert CVESeverity.from_score(2.0) == CVESeverity.LOW
        assert CVESeverity.from_score(0.0) == CVESeverity.NONE

    def test_register_and_retrieve(self) -> None:
        from maestria.security.cve_tracker import CVETracker

        tracker = CVETracker()
        cve = self._make_cve()
        tracker.register(cve)

        retrieved = tracker.get("CVE-2024-12345")
        assert retrieved is not None
        assert retrieved.cvss_score == 9.1
        assert retrieved.severity.value == "critical"

    def test_sla_days(self) -> None:
        from maestria.security.cve_tracker import CVESeverity
        cve_critical = self._make_cve(score=9.5)
        cve_low = self._make_cve(cve_id="CVE-2024-99999", score=2.0)
        assert cve_critical.sla_days == 15
        assert cve_low.sla_days == 180

    def test_risk_score(self) -> None:
        from maestria.security.cve_tracker import CVETracker

        tracker = CVETracker()
        tracker.register(self._make_cve("CVE-1", 9.5))
        tracker.register(self._make_cve("CVE-2", 7.5))
        tracker.register(self._make_cve("CVE-3", 5.0))

        score = tracker.get_risk_score()
        assert score > 0
        assert score == min(25 + 10 + 3, 100)  # critical + high + medium

    def test_status_transition(self) -> None:
        from maestria.security.cve_tracker import CVETracker, CVEStatus

        tracker = CVETracker()
        tracker.register(self._make_cve())
        tracker.transition("CVE-2024-12345", CVEStatus.IN_REMEDIATION, "Patch in progress")

        cve = tracker.get("CVE-2024-12345")
        assert cve is not None
        assert cve.status == CVEStatus.IN_REMEDIATION
        assert len(cve.history) == 1

    def test_compliance_report(self) -> None:
        from maestria.security.cve_tracker import CVETracker

        tracker = CVETracker()
        tracker.register(self._make_cve("CVE-1", 9.5))
        tracker.register(self._make_cve("CVE-2", 4.0))

        report = tracker.generate_compliance_report()
        assert report["report_type"] == "vulnerability_compliance"
        assert report["summary"]["total_tracked"] == 2
        assert report["summary"]["risk_score"] > 0


# ─── Event Bus Tests ───

class TestEventBus:
    """Tests for the async event bus."""

    @pytest.mark.asyncio
    async def test_publish_subscribe(self) -> None:
        from maestria.core.event_bus import EventBus, Event, EventType

        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe(EventType.MESSAGE_RECEIVED, handler)
        await bus.start()

        event = Event(
            event_type=EventType.MESSAGE_RECEIVED,
            source="test",
            payload={"data": "hello"},
        )
        await bus.publish(event)
        await asyncio.sleep(0.1)  # Let dispatch loop process

        assert len(received) == 1
        assert received[0].payload["data"] == "hello"
        await bus.stop()

    @pytest.mark.asyncio
    async def test_wildcard_subscriber(self) -> None:
        from maestria.core.event_bus import EventBus, Event, EventType

        bus = EventBus()
        received: list[Event] = []

        async def handler(event: Event) -> None:
            received.append(event)

        bus.subscribe(None, handler)  # wildcard
        await bus.start()

        await bus.publish(Event(event_type=EventType.ENGINE_STARTED, source="test"))
        await bus.publish(Event(event_type=EventType.CVE_DETECTED, source="test"))
        await asyncio.sleep(0.1)

        assert len(received) == 2
        await bus.stop()

    def test_event_audit_record(self) -> None:
        from maestria.core.event_bus import Event, EventType

        event = Event(
            event_type=EventType.SECURITY_ALERT,
            source="cve_tracker",
            payload={"cve_id": "CVE-2024-001"},
        )
        record = event.to_audit_record()
        assert record["event_type"] == "security.alert"
        assert record["source"] == "cve_tracker"

    def test_event_history(self) -> None:
        from maestria.core.event_bus import EventBus, Event, EventType

        bus = EventBus(max_history=5)
        # Manually add events to history
        for i in range(10):
            bus._history.append(Event(
                event_type=EventType.MESSAGE_RECEIVED,
                source=f"test-{i}",
            ))
            if len(bus._history) > 5:
                bus._history = bus._history[-5:]

        history = bus.get_history(limit=100)
        assert len(history) == 5


# ─── Patch Manager Tests ───

class TestPatchManager:
    """Tests for patch lifecycle management."""

    def test_create_and_deploy(self) -> None:
        from maestria.patches.manager import (
            PatchManager, PatchSeverity, PatchCategory, PatchStatus,
        )

        mgr = PatchManager(require_signature=False)
        patch = mgr.create_patch(
            title="Security Fix Q1-2024",
            description="Addresses CVE-2024-001",
            version_from="2.4.0",
            version_to="2.4.1",
            severity=PatchSeverity.CRITICAL,
            category=PatchCategory.SECURITY,
            cve_ids=["CVE-2024-001"],
        )

        assert patch.status == PatchStatus.DRAFT
        mgr.approve_patch(patch.patch_id, "admin")
        assert patch.status == PatchStatus.APPROVED

        mgr.deploy_patch(patch.patch_id, "production", actor="deployer")
        assert patch.status == PatchStatus.DEPLOYED_PRODUCTION
        assert patch.deployed_at is not None

    def test_signed_changelog(self) -> None:
        from maestria.patches.manager import PatchManager, PatchSeverity

        mgr = PatchManager(require_signature=False)
        patch = mgr.create_patch(
            title="Test Patch",
            description="Test",
            version_from="1.0.0",
            version_to="1.0.1",
        )
        mgr.approve_patch(patch.patch_id, "admin")
        mgr.deploy_patch(patch.patch_id, "staging")

        changelog = mgr.get_signed_changelog()
        assert changelog["signature_algorithm"] == "SHA-256"
        assert len(changelog["signature"]) == 64

    def test_rollback(self) -> None:
        from maestria.patches.manager import PatchManager, PatchStatus

        mgr = PatchManager(require_signature=False)
        patch = mgr.create_patch("P", "D", "1.0", "1.1")
        mgr.approve_patch(patch.patch_id, "admin")
        mgr.deploy_patch(patch.patch_id, "production")
        mgr.rollback_patch(patch.patch_id, "Regression detected")

        assert patch.status == PatchStatus.ROLLED_BACK
        assert len(patch.audit_trail) == 3  # approved, deployed, rolled back

    def test_poam_generation(self) -> None:
        from maestria.patches.manager import PatchManager

        mgr = PatchManager()
        entry = mgr.generate_poam(
            weakness="Unpatched OpenSSL",
            control_id="IEC62443-SR-3.1",
            milestone="Apply OpenSSL 3.2.1 patch",
            scheduled_date="2024-06-30",
            responsible="security-team",
        )

        assert entry.poam_id.startswith("POAM-")
        report = mgr.get_poam_report()
        assert report["total_entries"] == 1


# ─── SBOM Tests ───

class TestSBOM:
    """Tests for SBOM generation."""

    def test_generate_cyclonedx(self) -> None:
        from maestria.security.sbom import (
            SBOMGenerator, SBOMComponent, ComponentType, License,
        )

        gen = SBOMGenerator()
        gen.add_component(SBOMComponent(
            component_type=ComponentType.LIBRARY,
            name="pyyaml",
            version="6.0.1",
            purl="pkg:pypi/pyyaml@6.0.1",
            licenses=[License(license_id="MIT")],
        ))
        gen.add_component(SBOMComponent(
            component_type=ComponentType.LIBRARY,
            name="cryptography",
            version="42.0.0",
            purl="pkg:pypi/cryptography@42.0.0",
        ))

        sbom = gen.generate()
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 2

    def test_load_from_requirements(self) -> None:
        from maestria.security.sbom import SBOMGenerator

        gen = SBOMGenerator()
        reqs = """
pyyaml==6.0.1
jsonschema==4.21.0
pydantic>=2.6.0
# comment
structlog==24.1.0
"""
        count = gen.load_from_requirements(reqs)
        assert count == 4
        assert gen.component_count == 4


# ─── Monitoring Tests ───

class TestMetrics:
    """Tests for the metrics collector."""

    def test_counter(self) -> None:
        from maestria.monitoring.metrics import MetricsCollector

        metrics = MetricsCollector()
        metrics.increment("requests")
        metrics.increment("requests")
        metrics.increment("requests", 3)
        assert metrics.get_counter("requests") == 5.0

    def test_gauge(self) -> None:
        from maestria.monitoring.metrics import MetricsCollector

        metrics = MetricsCollector()
        metrics.set_gauge("active_workers", 4)
        assert metrics.get_gauge("active_workers") == 4.0

    def test_histogram(self) -> None:
        from maestria.monitoring.metrics import MetricsCollector

        metrics = MetricsCollector()
        for val in [10, 20, 30, 40, 50]:
            metrics.observe("latency", val)
        stats = metrics.get_histogram_stats("latency")
        assert stats["count"] == 5
        assert stats["avg"] == 30.0

    def test_prometheus_export(self) -> None:
        from maestria.monitoring.metrics import MetricsCollector

        metrics = MetricsCollector(namespace="test")
        metrics._started_at = 1000.0
        metrics.increment("http_requests")
        metrics.set_gauge("connections", 42)
        output = metrics.export_prometheus()
        assert "test_http_requests" in output
        assert "test_connections 42" in output


# ─── Crypto Utils Tests ───

class TestCrypto:
    """Tests for cryptographic utilities."""

    def test_sha256(self) -> None:
        from maestria.utils.crypto import sha256_hex
        h = sha256_hex("hello")
        assert len(h) == 64
        assert h == sha256_hex("hello")  # deterministic
        assert h != sha256_hex("world")

    def test_hmac_sign_verify(self) -> None:
        from maestria.utils.crypto import hmac_sign, hmac_verify
        sig = hmac_sign("secret", "message")
        assert hmac_verify("secret", "message", sig)
        assert not hmac_verify("wrong", "message", sig)

    def test_integrity_check(self) -> None:
        from maestria.utils.crypto import sha256_hex, integrity_check
        content = "patch content v2.4.1"
        checksum = sha256_hex(content)
        assert integrity_check(content, checksum)
        assert not integrity_check("tampered content", checksum)


# ─── Configuration Tests ───

class TestConfig:
    """Tests for configuration management."""

    def test_default_config(self) -> None:
        from maestria.utils.config import MaestriaConfig
        cfg = MaestriaConfig.default()
        assert cfg.environment == "development"
        assert cfg.engine.worker_count == 4

    def test_from_dict(self) -> None:
        from maestria.utils.config import MaestriaConfig
        cfg = MaestriaConfig.from_dict({
            "maestria": {
                "environment": "production",
                "engine": {"worker_count": 8, "instance_id": "PROD-01"},
            }
        })
        assert cfg.environment == "production"
        assert cfg.engine.worker_count == 8
        assert cfg.engine.instance_id == "PROD-01"
