# Security Policy

## Supported Versions

Until 1.0.0 the project follows "best effort" security support for the latest released minor version.
After 1.0.0 we will backport critical security fixes to the last two minor versions.

| Version | Supported |
|---------|-----------|
| < 1.0.0 | Latest only |

## Reporting a Vulnerability

Please email **security@odinprotocol.dev** with details. Include:
- A concise description of the issue and potential impact.
- Steps to reproduce or proof-of-concept if available.
- Any relevant logs or environment details.

You'll receive an acknowledgement within 72 hours. We'll coordinate a fix & disclosure timeline; please do not open a public issue until a patch is released.

## Cryptography Scope & Threat Model (High-Level)

This library provides:
- Canonical JSON serialization
- Content identifiers (SHA-256 based)
- Ed25519 signatures over selected envelope fields
- Optional timestamp and validity window checks

Out of scope:
- Confidentiality / encryption
- Transport security (use TLS etc.)
- Replay protection beyond configurable timestamp skew + temporal validity
- Key management beyond simple local seed (cloud KMS integrations optional extras)

Assumptions:
- Signer private keys are stored and accessed securely
- System clocks are approximately accurate (or skew checking disabled knowingly)

## Key Compromise Guidance
If a private key is suspected compromised:
1. Revoke / retire the key in your distribution channel.
2. Stop trusting envelopes/bundles signed with the old key going forward.
3. Rotate to a new key and update your JWKS distribution.

## Disclosure Timeline
We prefer a coordinated disclosure: embargo until a fixed version is available on PyPI + advisory published.

