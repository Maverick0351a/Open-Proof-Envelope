# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
- (placeholder)

## [0.9.0] - 2025-08-24
### Added
- Canonical JSON serialization & CID (`sha256:<hex>`) computation.
- Envelope construction & Ed25519 signing (`"{cid}|{trace_id}|{ts}"`).
- Bundle model with receipt chain validation and bundle signing.
- Temporal validation: skew window, `not_before`, `expires_at`.
- Rich exception hierarchy + `ReasonCode` enum & mapping helper.
- CLI (`odin-ope`) with JSON output, strict mode, temporal flags.
- Dataclass models (`EnvelopeModel`, `BundleModel`, `ReceiptModel`).
- SBOM generation script (CycloneDX) and provenance attestation workflow step.
- Comprehensive pytest + Hypothesis test suite (>90% coverage target).
- Security, contributing, releasing, and code-of-conduct documentation.

### Changed
- License metadata normalized to SPDX string form; removed deprecated classifier.
- Dynamic `__version__` resolution via importlib.metadata.

### Security
- Input validation hardening & deterministic canonicalization safeguards.
- Supply chain: automated build, SBOM artifact, provenance attestation.

### Misc
- Pre-commit, Ruff, Black, mypy integration.
- GitHub Actions publish workflow with quality gates.

---

[0.9.0]: https://github.com/odin-protocol/odin-ope/releases/tag/v0.9.0
