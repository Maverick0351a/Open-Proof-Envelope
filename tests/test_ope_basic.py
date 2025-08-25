from __future__ import annotations
from odin_ope.cid import canonical_json, compute_cid
from odin_ope.signers import FileSigner
from odin_ope.envelope import build_envelope, sign_envelope
from odin_ope.verify import verify_envelope, build_jwks_for_signers, verify_envelope_or_raise
from odin_ope.bundle import build_bundle, sign_bundle, verify_bundle, verify_bundle_or_raise
from odin_ope.exceptions import (
    CidMismatch,
    MissingSigOrKid,
    KidNotFound,
    SignatureInvalid,
    TimestampSkew,
    SchemaError,
    NotYetValid,
    Expired,
)
from odin_ope.models import EnvelopeModel, BundleModel
import json, pathlib
from datetime import datetime, timezone

def test_canonical_and_cid_deterministic():
    obj = {"b":2, "a":1}
    b1 = canonical_json(obj)
    b2 = canonical_json({"a":1, "b":2})
    assert b1 == b2
    cid = compute_cid(obj)
    assert cid.startswith("sha256:")

def test_sign_and_verify_envelope():
    # Use a fixed seed for determinism: 32 zero bytes -> base64url "AAAAAAAA..."
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    payload = {"x": 1, "y": "z"}
    env = build_envelope(payload, "vendor.v1", "canon.v1")
    env = sign_envelope(env, signer)
    jwks = build_jwks_for_signers([signer])
    ok, reason = verify_envelope(env, jwks)
    assert ok, reason
    # Model round-trip
    model = EnvelopeModel.from_dict(env)
    assert model.cid == env["cid"]
    assert model.to_dict()["cid"] == env["cid"]

def test_bundle_sign_verify():
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    receipts = [
        {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None},
        {"hop": 1, "receipt_hash": "h1", "prev_receipt_hash": "h0"},
    ]
    bundle = build_bundle("trace-1", receipts)
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    ok, reason = verify_bundle(bundle, sig, jwks, signer.kid)
    assert ok, reason
    # Bundle model round trip
    bm = BundleModel.from_dict(bundle)
    assert bm.trace_id == bundle["trace_id"]
    assert bm.to_dict()["trace_id"] == bundle["trace_id"]


# --- Additional edge case and property-based tests ---
import pytest
from hypothesis import given, strategies as st

def test_canonical_json_empty():
    # Edge: empty dict/list
    assert canonical_json({}) == b"{}"
    assert canonical_json([]) == b"[]"

def test_canonical_json_non_ascii():
    # Edge: non-ASCII chars
    obj = {"msg": "café"}
    out = canonical_json(obj)
    assert b"cafe" not in out  # should preserve accents
    assert out.startswith(b"{\"msg\":\"")

def test_build_envelope_missing_fields():
    # Edge: missing/empty payload
    env = build_envelope({}, "t", "tgt")
    assert env["payload"] == {}
    assert "cid" in env and env["cid"].startswith("sha256:")

def test_signer_invalid_seed():
    # Edge: wrong seed length
    with pytest.raises(ValueError):
        FileSigner("AA")

def test_verify_envelope_missing_sig():
    # Edge: missing signature/kid
    env = build_envelope({"x":1}, "t", "tgt")
    ok, reason = verify_envelope(env, {"keys": []})
    assert not ok and reason == "missing_sig_or_kid"

def test_verify_envelope_kid_not_found():
    # Edge: kid not in jwks
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    env = build_envelope({"x":1}, "t", "tgt")
    env = sign_envelope(env, signer)
    ok, reason = verify_envelope(env, {"keys": []})
    assert not ok and reason == "kid_not_found"

def test_verify_envelope_cid_mismatch():
    # Edge: tampered payload
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    env = build_envelope({"x":1}, "t", "tgt")
    env = sign_envelope(env, signer)
    env["payload"] = {"x":2}
    jwks = build_jwks_for_signers([signer])
    ok, reason = verify_envelope(env, jwks)
    assert not ok and reason == "cid_mismatch"

def test_verify_envelope_or_raise_exceptions():
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    env = build_envelope({"x":1}, "t", "tgt")
    env_bad = sign_envelope(env, signer)
    env_bad["payload"] = {"x":2}  # tamper
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(CidMismatch):
        verify_envelope_or_raise(env_bad, jwks)

def test_verify_envelope_timestamp_skew():
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    # Force old timestamp
    env = build_envelope({"x":1}, "t", "tgt", ts="2000-01-01T00:00:00+00:00")
    env = sign_envelope(env, signer)
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(TimestampSkew):
        verify_envelope_or_raise(env, jwks, max_skew_seconds=10)

def test_verify_bundle_or_raise():
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    receipts = [
        {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None},
    ]
    bundle = build_bundle("trace-1", receipts)
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    # Should not raise
    verify_bundle_or_raise(bundle, sig, jwks, signer.kid)

def test_vector_basic():
    vector_path = pathlib.Path(__file__).parent / 'vectors' / 'basic_vector.json'
    data = json.loads(vector_path.read_text())
    # Recreate signer and envelope
    signer = FileSigner(data['seed_b64u'])
    env = {
        'payload': data['payload'],
        'payload_type': data['envelope']['payload_type'],
        'target_type': data['envelope']['target_type'],
        'cid': data['envelope']['cid'],
        'trace_id': data['envelope']['trace_id'],
        'ts': data['envelope']['ts'],
        'sender_sig': data['envelope_signature'],
        'kid': data['kid'],
    }
    jwks = data['jwks']
    ok, reason = verify_envelope(env, jwks)
    assert ok, reason
    # Bundle
    bundle = data['bundle']
    ok2, reason2 = verify_bundle(bundle, data['bundle_signature'], jwks, data['kid'])
    assert ok2, reason2

def test_bundle_hop_continuity_validation():
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    # Broken hop order
    receipts = [
        {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None},
        {"hop": 2, "receipt_hash": "h2", "prev_receipt_hash": "h0"},
    ]
    bundle = build_bundle("trace-xyz", receipts)
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(SchemaError):
        verify_bundle_or_raise(bundle, sig, jwks, signer.kid)

def test_bundle_prev_hash_chain_validation():
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    receipts = [
        {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None},
        {"hop": 1, "receipt_hash": "h1", "prev_receipt_hash": "WRONG"},
    ]
    bundle = build_bundle("trace-xyz", receipts)
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(SchemaError):
        verify_bundle_or_raise(bundle, sig, jwks, signer.kid)

def test_envelope_not_before_and_expired():
    seed_b64u = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    signer = FileSigner(seed_b64u)
    past_ts = "2025-01-01T00:00:00+00:00"
    env = build_envelope({"x":1}, "t", "tgt", ts=past_ts)
    env["not_before"] = "2100-01-01T00:00:00+00:00"  # future
    env = sign_envelope(env, signer)
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(NotYetValid):
        verify_envelope_or_raise(env, jwks)
    # Expired
    env2 = build_envelope({"x":1}, "t", "tgt", ts=past_ts)
    env2["expires_at"] = "2025-01-01T00:00:01+00:00"
    env2 = sign_envelope(env2, signer)
    with pytest.raises(Expired):
        verify_envelope_or_raise(env2, jwks, now=datetime(2025,1,1,0,0,2,tzinfo=timezone.utc))

from hypothesis import settings, HealthCheck

@settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
@given(st.dictionaries(
    st.text(min_size=1, max_size=8),
    st.one_of(
        st.integers(min_value=-1000, max_value=1000),
        st.text(min_size=0, max_size=16),
        st.floats(allow_nan=False, allow_infinity=False, width=16),
        st.booleans(),
        st.none()
    ),
    max_size=3
))
def test_canonical_json_stability(obj):
    # Property: canonical_json is deterministic and stable
    b1 = canonical_json(obj)
    b2 = canonical_json(obj)
    assert b1 == b2
    # Property: compute_cid is deterministic
    cid1 = compute_cid(obj)
    cid2 = compute_cid(obj)
    assert cid1 == cid2
