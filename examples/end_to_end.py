"""
End-to-end example: envelope and bundle signing/verification

This script demonstrates:
- Creating and signing an envelope
- Verifying the envelope
- Creating a bundle and signing it
- Verifying the bundle

All steps are documented inline.
"""

from odin_ope.bundle import build_bundle, sign_bundle, verify_bundle
from odin_ope.envelope import build_envelope, sign_envelope
from odin_ope.signers import FileSigner
from odin_ope.verify import build_jwks_for_signers, verify_envelope

# 1. Create a signer (Ed25519, deterministic seed for demo)
seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 32 zero bytes, base64url
signer = FileSigner(seed_b64u)

# 2. Build an envelope with a payload
payload = {"user": "alice", "amount": 42}
envelope = build_envelope(payload, payload_type="demo.v1", target_type="example.v1")
print("Envelope:", envelope)

# 3. Sign the envelope
signed_env = sign_envelope(envelope, signer)
print("Signed envelope:", signed_env)

# 4. Build JWKS for verification
jwks = build_jwks_for_signers([signer])

# 5. Verify the signed envelope
ok, reason = verify_envelope(signed_env, jwks)
print("Envelope verification:", ok, reason)

# 6. Create a bundle of receipts
receipts = [
    {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None},
    {"hop": 1, "receipt_hash": "h1", "prev_receipt_hash": "h0"},
]
bundle = build_bundle(trace_id="trace-123", receipts=receipts)
print("Bundle:", bundle)

# 7. Sign the bundle
bundle_sig = sign_bundle(bundle, signer)
print("Bundle signature:", bundle_sig)

# 8. Verify the bundle signature
ok, reason = verify_bundle(bundle, bundle_sig, jwks, signer.kid)
print("Bundle verification:", ok, reason)
