# Contributing to MAESTRIA-Lite

Thank you for your interest in contributing to MAESTRIA-Lite! This document provides guidelines for contributing to the project.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/your-username/maestria-lite.git
cd maestria-lite

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Code Quality

Before submitting a PR, ensure your code passes all quality checks:

```bash
# Lint
ruff check maestria/ tests/

# Type check
mypy maestria/ --ignore-missing-imports

# Tests with coverage
pytest tests/ -v --cov=maestria --cov-fail-under=80

# Security scan
bandit -r maestria/
```

## Branch Naming

- `feature/description` — New features
- `fix/description` — Bug fixes
- `security/description` — Security patches
- `docs/description` — Documentation updates

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(parser): add HL7v2 ADT message support
fix(router): handle null endpoint gracefully
security(cve): update CVE-2024-001 remediation
docs: update architecture diagram
```

## Pull Request Process

1. Create a feature branch from `develop`
2. Make your changes with tests
3. Ensure all CI checks pass
4. Request review from at least one maintainer
5. Squash and merge after approval

## Regulatory Considerations

Given the IVD context of this project, all changes must:

- Include appropriate test coverage (minimum 80%)
- Document any security implications
- Update SBOM if adding/removing dependencies
- Follow IEC 62304 software lifecycle practices
- Include audit-relevant logging for security changes

## Code of Conduct

Be respectful, inclusive, and constructive. We are committed to providing a welcoming environment for everyone.
