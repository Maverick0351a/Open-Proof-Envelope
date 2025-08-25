<div align="center">

# ODIN OPE – Open Proof Envelope

Robust, lightweight primitives for **verifiable payload exchange** across AI agents, services, and humans.

[![PyPI Version](https://img.shields.io/pypi/v/odin-ope.svg)](https://pypi.org/project/odin-ope/)
[![Python Versions](https://img.shields.io/pypi/pyversions/odin-ope.svg)](https://pypi.org/project/odin-ope/)
[![License: Apache-2.0](https://img.shields.io/pypi/l/odin-ope.svg)](./LICENSE)
[![Status: Production Ready](https://img.shields.io/badge/status-production--ready-green)](#)
[![Type Hints](https://img.shields.io/badge/types-PEP%20484-blue)](#)
[![Website](https://img.shields.io/badge/site-odinsecure.ai-0a84ff)](https://odinsecure.ai)
[![CI](https://github.com/maverick0351a/Open-Proof-Envelope/actions/workflows/publish.yml/badge.svg?branch=main&event=push)](https://github.com/maverick0351a/Open-Proof-Envelope/actions/workflows/publish.yml)

</div>

---

## What Is OPE?

**OPE (Open Proof Envelope)** is a minimal, deterministic container + signing scheme:

1. Canonicalize a JSON payload (stable key ordering & encoding)
2. Compute a **CID** (`sha256:<hex>` of canonical bytes)
3. Assemble an **envelope** with metadata (`payload_type`, `target_type`, `trace_id`, timestamps)
4. Sign a compact string representation with **Ed25519** (`"{cid}|{trace_id}|{ts}"`)
5. Distribute or bundle these signed envelopes; receivers can verify and obtain fine‑grained failure reason codes.

It gives you a tamper‑evident, portable, and tool‑friendly way to prove *exactly* what JSON was processed or exchanged—ideal for audit trails, agent hand‑offs, chain‑of‑thought checkpoints, compliance artifacts, or marketplace receipts.

> Project Website: https://odinsecure.ai

### Key Guarantees
| Property | Description |
|----------|-------------|
| Determinism | Canonical serialization yields stable hashes & signatures |
| Integrity | Payload changes ⇒ different CID ⇒ verification fails |
| Authenticity | Ed25519 signatures tied to a `kid` (public key) in a JWKS |
| Temporal controls | Optional `not_before`, `expires_at`, skew bounds |
| Trace continuity | `trace_id` threads envelopes and bundles |
| Explainability | Structured reason codes on failure |

---

## Architecture Overview

Below are multiple focused views (pick the one you need). Each avoids visual noise while conveying core intent.

### 1. Layered Flow (System Perspective)
```mermaid
flowchart TB
    %% Simplified for GitHub Mermaid (avoid multiline + unicode arrows)
    subgraph Ingestion [Producer]
        A[Raw JSON] --> B[Canonicalize]
        B --> C[Hash sha256 -> CID]
        C --> D[Assemble Envelope]
        D --> E[Sign Ed25519]
        E --> SE((Signed Envelope))
    end
    SE --> BNDQ{Multiple?}
    BNDQ -->|yes| R[Collect Receipts]
    R --> SB[Sign Bundle]
    SB --> SBB((Signed Bundle))
    SE --> V[Verify]
    SBB --> V
    subgraph Validation [Consumer]
        V -->|ok| OK[Accept]
        V -->|fail| RC[Reason Code]
    end
    %% Minimal styling only (GitHub safe)
    classDef artifact fill:#eef5ff,stroke:#0a84ff,color:#0a84ff,stroke-width:1px;
    classDef decision fill:#fff5e6,stroke:#ff9f00,color:#8a5500,stroke-width:1px;
    classDef result fill:#e9f9f0,stroke:#16a34a,color:#14532d,stroke-width:1px;
    classDef error fill:#fdecec,stroke:#dc2626,color:#7f1d1d,stroke-width:1px;
    class SE,SBB artifact;
    class BNDQ decision;
    class OK result;
    class RC error;
```

### 2. Lifecycle State Machine
```mermaid
stateDiagram-v2
    [*] --> Raw
    Raw --> Canonical: canonicalize()
    Canonical --> Hashed: sha256()
    Hashed --> Composed: build_envelope()
    Composed --> SignedEnvelope: sign_envelope()
    SignedEnvelope --> Verified: verify_envelope()
    SignedEnvelope --> Rejected: verify_envelope() fail
    Verified --> Bundled: add to bundle (optional)
    Bundled --> SignedBundle: sign_bundle()
    SignedBundle --> VerifiedBundle: verify_bundle()
    SignedBundle --> Rejected: verify_bundle() fail
    Rejected --> [*]
    VerifiedBundle --> [*]
```

### 3. Data Model (Conceptual)
```mermaid
classDiagram
    class Envelope {
        +string cid
        +dict payload
        +string payload_type
        +string target_type
        +string trace_id
        +int ts
        +int not_before?
        +int expires_at?
        +string sender_sig?
        +string kid?
    }
    class Bundle {
        +string bundle_cid
        +int exported_at
        +Envelope[] receipts
        +string bundle_sig?
        +string kid?
    }
    class Signer {
        +string kid
        +sign(data)->signature
        +public_jwk()->dict
    }
    class JWKS {
        +keys: JWK[]
    }
    Envelope --> Signer : signed by
    Signer --> JWKS : published to
    Bundle o-- Envelope : aggregates
```

### 4. Minimal Exchange Sequence
```mermaid
sequenceDiagram
    participant P as Producer
    participant C as Consumer
    P->>P: canonicalize + hash → CID
    P->>P: build + sign envelope
    P-->>C: envelope (JSON)
    C->>C: re-hash compare CID
    C->>C: lookup kid → verify sig
    C->>C: temporal / schema checks
    alt valid
        C-->>P: accept (optional ack)
    else invalid
        C-->>P: reason code
    end
```

<details>
<summary>Why multiple views?</summary>

Different stakeholders scan for different dimensions: the layered flow helps onboarding; the state machine clarifies transitions & failure exits; the data model anchors naming; the sequence highlights network-facing steps.

</details>

---

## Installation
```bash
pip install odin-ope
# Extras (cloud KMS signers)
pip install "odin-ope[gcpkms]"
pip install "odin-ope[awskms]"
pip install "odin-ope[azurekv]"
```

---

## Quick Start
```python
from odin_ope.signers import FileSigner
from odin_ope.envelope import build_envelope, sign_envelope
from odin_ope.verify import verify_envelope, build_jwks_for_signers

seed_b64u = "A" * 43  # demo seed (base64url for 32 bytes). Use a secure random seed in production.
signer = FileSigner(seed_b64u=seed_b64u)

payload = {"invoice_id": "INV-1", "amount": 100.25, "currency": "USD"}
env = build_envelope(
        payload,
        payload_type="openai.tooluse.invoice.v1",
        target_type="invoice.iso20022.v1",
)
signed_env = sign_envelope(env, signer)

jwks = build_jwks_for_signers([signer])
ok, reason = verify_envelope(signed_env, jwks)
assert ok, reason
```
See `examples/end_to_end.py` for an extended demonstration (including bundles and receipts).

---

## CLI
After installation a `odin-ope` CLI is available:
```bash
odin-ope sign-envelope \
    --payload payload.json \
    --payload-type my.type.v1 \
    --target-type my.target.v1 \
    --seed <base64url-seed> \
    --not-before "+0" --expires-at "+3600"

odin-ope verify-envelope --envelope env.json --jwks jwks.json --json --strict --max-skew 300
```
Flags:
- `--json` structured output (machine friendly)
- `--strict` enforces schema & required fields
- `--no-skew` disables clock skew tolerance
- `--max-skew` override default skew seconds

---

## Reason Codes
| Code | Meaning |
|------|---------|
| cid_mismatch | Payload hash changed after signing |
| missing_sig_or_kid | Envelope missing sender_sig or kid |
| kid_not_found | KID not present in supplied JWKS |
| signature_invalid | Signature verification failed |
| timestamp_skew | ts outside allowed skew window |
| schema_error | Structural or field validation error |
| not_yet_valid | not_before is in the future |
| expired | expires_at is in the past |

Use `verify_envelope_or_raise` for exceptions; map to enumerated `ReasonCode` for analytics.

---

## FAQ
**ModuleNotFoundError**: Ensure installation succeeded (`pip show odin-ope`) or use editable install: `pip install -e .`.

**Bad seed length**: Ed25519 seed must decode to exactly 32 bytes (base64url without padding).

**CID mismatch**: The payload mutated post-signing—never modify a signed envelope's `payload` or `cid`.

**Generating a seed**:
```python
import os, base64
seed = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
```

---

## Development
```bash
pip install -e .[dev]
pytest -q
mypy src/odin_ope
python scripts/gen_sbom.py --out sbom.json  # CycloneDX SBOM
```
Programmatic version:
```python
import odin_ope; print(odin_ope.__version__)
```

---

## Publishing (Automation Ready)
GitHub Actions workflow (`.github/workflows/publish.yml`) supports: lint, type-check, tests (coverage), build, SBOM, provenance attestation, PyPI publish. Add a `PYPI_API_TOKEN` secret and push a signed tag (e.g. `v0.9.0`).

### Links
- Website: https://odinsecure.ai
- PyPI: https://pypi.org/project/odin-ope/
- GitHub: https://github.com/maverick0351a/Open-Proof-Envelope

---

## Security & Integrity
- Ed25519 only (modern, fast, deterministic)
- Canonical JSON prevents hash ambiguity
- Temporal fields (`not_before`, `expires_at`, skew) mitigate replay
- SBOM + provenance to strengthen supply chain trust
See `SECURITY.md` for coordinated disclosure process.

---

## Roadmap (Selected)
- Multi-signer envelopes
- Streaming / large-payload hashing adapters
- Pluggable policy hooks (custom temporal / business rules)
- Threat model & formal spec doc

---

## Contributing
Issues & PRs welcome. See `CONTRIBUTING.md` and follow the style / type hints / tests guidelines.

---

## License
Apache-2.0
