Copyright © 2026 Doctum Consilium – Yann Smatti.
All rights reserved.
Proprietary and confidential.
Unauthorized copying, modification, distribution, use, or reverse engineering is strictly prohibited.
# 🧬 MAESTRIA-Lite — Industrial Diagnostic Middleware

<p align="center">
  <img src="docs/architecture.svg" alt="MAESTRIA-Lite Architecture" width="700"/>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"/></a>
  <a href="#"><img src="https://img.shields.io/badge/HL7-v2.x-green.svg" alt="HL7 v2.x"/></a>
  <a href="#"><img src="https://img.shields.io/badge/IEC_62304-compliant-orange.svg" alt="IEC 62304"/></a>
  <a href="#"><img src="https://img.shields.io/badge/license-MIT-lightgrey.svg" alt="License: MIT"/></a>
  <a href="#"><img src="https://img.shields.io/badge/docker-ready-2496ED.svg" alt="Docker"/></a>
  <a href="#"><img src="https://img.shields.io/badge/CVE_Tracking-enabled-red.svg" alt="CVE Tracking"/></a>
</p>

---

**MAESTRIA-Lite** is an open-source, production-grade middleware designed for **in-vitro diagnostic (IVD) environments**. It acts as the integration backbone between laboratory instruments, Laboratory Information Systems (LIS), and hospital networks — handling message routing, protocol translation, interface contract validation, cybersecurity compliance, and patch lifecycle management.

Built with regulatory frameworks in mind (**IEC 62304**, **FDA 21 CFR Part 11**, **ISO 27001**), this project demonstrates the architecture patterns and operational rigor expected in a real-world IVD middleware.

---

## 🏗️ Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    MAESTRIA-Lite Core                     │
│                                                          │
│  ┌──────────┐   ┌───────────┐   ┌─────────────────────┐ │
│  │ HL7v2    │   │ Interface │   │  Message Router     │ │
│  │ Parser   │──▶│ Contract  │──▶│  & Orchestrator     │ │
│  │          │   │ Validator │   │                     │ │
│  └──────────┘   └───────────┘   └──────────┬──────────┘ │
│                                             │            │
│  ┌──────────┐   ┌───────────┐   ┌──────────▼──────────┐ │
│  │ Security │   │  Patch    │   │   Event Bus         │ │
│  │ Module   │   │  Manager  │   │   (async queues)    │ │
│  │ (CVE/    │   │ (POAM/    │   │                     │ │
│  │  SBOM)   │   │  trace)   │   │                     │ │
│  └──────────┘   └───────────┘   └─────────────────────┘ │
│                                                          │
│  ┌──────────────────────────────────────────────────────┐│
│  │              Monitoring & Observability               ││
│  │         (Prometheus metrics / Health checks)          ││
│  └──────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────┘
         │                    │                    │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │Analyzer │         │  LIS    │         │ Hospital│
    │Instruments│       │ Systems │         │  HIS    │
    └─────────┘         └─────────┘         └─────────┘
```

## ✨ Key Features

### 🔌 Interface Contract Management
- JSON Schema-based contract definitions for each connected system
- Automatic validation of inbound/outbound messages against contracts
- Contract versioning with backward compatibility checks
- Audit trail for all contract changes

### 🧪 HL7v2 Message Processing
- Full HL7v2 parser (ORM, ORU, ADT, ACK message types)
- Segment-level parsing with field extraction (MSH, PID, OBR, OBX, etc.)
- Message transformation & enrichment pipeline
- Configurable routing rules per message type

### 🔒 Cybersecurity Module
- **CVE Tracker**: Automated vulnerability scanning against NVD database
- **SBOM Generator**: Software Bill of Materials in CycloneDX format
- **Compliance Engine**: Checks against IEC 62443 / ISO 27001 controls
- **Remediation Workflow**: Track vulnerability lifecycle from detection to closure

### 📦 Patch Management
- Quarterly patch cycle support with full traceability
- Plan of Action & Milestones (POA&M) generation
- Rollback capability with state snapshots
- Change log with cryptographic signatures (SHA-256)

### 📊 Monitoring & Observability
- Prometheus-compatible metrics endpoint
- Real-time health checks for all connected systems
- Message throughput & latency tracking
- Security event logging (SIEM-ready format)

### 🐳 DevOps Ready
- Multi-stage Docker builds
- Docker Compose for full stack deployment
- GitHub Actions CI/CD pipeline
- Infrastructure as Code patterns

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose (optional)
- Redis (optional, for production queue backend)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/maestria-lite.git
cd maestria-lite

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run the middleware
maestria-lite start --config config/maestria.yaml
```

### Docker Deployment

```bash
# Build and start all services
docker compose up -d

# Check service health
docker compose ps
curl http://localhost:8080/health

# View logs
docker compose logs -f maestria-core
```

### Run Tests

```bash
# Unit tests
pytest tests/ -v --cov=maestria --cov-report=html

# Security scan
maestria-lite security scan --format cyclonedx

# Contract validation
maestria-lite contracts validate --dir config/contracts/
```

---

## 📁 Project Structure

```
maestria-lite/
├── maestria/                    # Core middleware package
│   ├── core/                    # Engine, router, event bus
│   │   ├── engine.py            # Main middleware engine
│   │   ├── router.py            # Message routing & orchestration
│   │   ├── event_bus.py         # Async event bus (pub/sub)
│   │   └── pipeline.py          # Message processing pipeline
│   ├── interfaces/              # Interface contract management
│   │   ├── contract.py          # Contract definition & validation
│   │   ├── hl7_parser.py        # HL7v2 message parser
│   │   ├── registry.py          # Connected system registry
│   │   └── schemas/             # JSON Schema contract definitions
│   ├── security/                # Cybersecurity module
│   │   ├── cve_tracker.py       # CVE vulnerability tracking
│   │   ├── sbom.py              # SBOM generation (CycloneDX)
│   │   ├── compliance.py        # Regulatory compliance checks
│   │   └── remediation.py       # Vulnerability remediation workflow
│   ├── patches/                 # Patch management
│   │   ├── manager.py           # Patch lifecycle manager
│   │   ├── poam.py              # POA&M generation
│   │   └── changelog.py         # Signed change log
│   ├── monitoring/              # Observability
│   │   ├── metrics.py           # Prometheus metrics
│   │   ├── health.py            # Health check endpoints
│   │   └── audit.py             # Audit logging (SIEM-ready)
│   └── utils/                   # Shared utilities
│       ├── crypto.py            # Cryptographic helpers
│       └── config.py            # Configuration management
├── tests/                       # Test suite
├── config/                      # Configuration files
│   ├── maestria.yaml            # Main configuration
│   └── contracts/               # Interface contract schemas
├── dashboard/                   # Monitoring dashboard (HTML)
├── scripts/                     # Operational scripts
├── docs/                        # Documentation
├── .github/workflows/           # CI/CD pipelines
├── Dockerfile                   # Multi-stage Docker build
├── docker-compose.yml           # Full stack deployment
├── pyproject.toml               # Python project config
└── README.md
```

---

## 🔧 Configuration

```yaml
# config/maestria.yaml
maestria:
  instance_id: "MAESTRIA-PROD-001"
  version: "2.4.1"
  environment: production

  engine:
    worker_count: 4
    queue_backend: redis    # memory | redis
    max_message_size: 1048576

  interfaces:
    contract_dir: config/contracts/
    strict_validation: true
    hl7:
      version: "2.5.1"
      encoding: "unicode"
      field_separator: "|"

  security:
    cve_scan_interval: 86400   # daily
    sbom_format: cyclonedx
    compliance_framework: iec62443
    tls:
      enabled: true
      min_version: "1.2"

  patches:
    cycle: quarterly
    require_signature: true
    rollback_retention: 3

  monitoring:
    metrics_port: 9090
    health_port: 8080
    audit_format: cef     # Common Event Format
```

---

## 📋 Regulatory Compliance

| Standard | Coverage | Status |
|----------|----------|--------|
| IEC 62304 | Software lifecycle | ✅ Implemented |
| FDA 21 CFR Part 11 | Electronic records | ✅ Audit trail |
| ISO 27001 | Information security | ✅ Controls mapped |
| IEC 62443 | Industrial cybersecurity | ✅ Compliance engine |
| HIPAA | Patient data protection | ✅ Encryption & access |

---

## 🤝 Contributing

Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <i>Built with ❤️ for the IVD community — Demonstrating middleware engineering best practices for diagnostic environments.</i>
</p>
