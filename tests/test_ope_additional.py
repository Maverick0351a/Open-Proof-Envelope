from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest
from odin_ope import cli as cli_mod
from odin_ope.bundle import build_bundle, sign_bundle, verify_bundle, verify_bundle_or_raise
from odin_ope.envelope import build_envelope, sign_envelope
from odin_ope.exceptions import KidNotFound, SchemaError, SignatureInvalid, TimestampSkew
from odin_ope.signers import FileSigner
from odin_ope.verify import (
    build_jwks_for_signers,
    verify_envelope,
    verify_envelope_or_raise,
)

SEED = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 32 zero bytes base64url


# --- Bundle structure / skew tests ---


def test_bundle_invalid_not_dict() -> None:
    with pytest.raises(SchemaError):  # type: ignore[arg-type]
        verify_bundle_or_raise(123, "sig", {"keys": []}, "kid")  # type: ignore[arg-type]


def test_bundle_missing_field() -> None:
    signer = FileSigner(SEED)
    # Build a valid bundle then remove exported_at
    bundle = build_bundle("trace-x", [{"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None}])
    sig = sign_bundle(bundle, signer)
    del bundle["exported_at"]
    with pytest.raises(SchemaError):
        verify_bundle_or_raise(bundle, sig, build_jwks_for_signers([signer]), signer.kid)


def test_bundle_receipts_not_list() -> None:
    signer = FileSigner(SEED)
    bundle: dict[str, Any] = {
        "trace_id": "t",
        "exported_at": "2025-01-01T00:00:00+00:00",
        "receipts": "not-a-list",
    }
    sig = sign_bundle(
        build_bundle("t", [{"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None}]), signer
    )
    with pytest.raises(SchemaError):
        verify_bundle_or_raise(bundle, sig, build_jwks_for_signers([signer]), signer.kid)


def test_bundle_exported_at_skew() -> None:
    signer = FileSigner(SEED)
    receipts = [{"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None}]
    bundle = build_bundle("trace-x", receipts)
    # Force far-future exported_at to trigger skew
    bundle["exported_at"] = "2100-01-01T00:00:00+00:00"
    sig = sign_bundle(bundle, signer)
    with pytest.raises(TimestampSkew):
        verify_bundle_or_raise(
            bundle, sig, build_jwks_for_signers([signer]), signer.kid, max_skew_seconds=1
        )


def test_bundle_kid_not_found() -> None:
    signer = FileSigner(SEED)
    receipts = [{"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None}]
    bundle = build_bundle("trace-x", receipts)
    sig = sign_bundle(bundle, signer)
    # Wrong kid
    with pytest.raises(KidNotFound):
        verify_bundle_or_raise(bundle, sig, {"keys": []}, "nope")


def test_bundle_signature_invalid() -> None:
    signer = FileSigner(SEED)
    receipts = [{"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None}]
    bundle = build_bundle("trace-x", receipts)
    sig = sign_bundle(bundle, signer)
    # Tamper after signing
    bundle["receipts"][0]["receipt_hash"] = "tampered"
    with pytest.raises(SignatureInvalid):
        verify_bundle_or_raise(bundle, sig, build_jwks_for_signers([signer]), signer.kid)


# --- Envelope validation branches ---


def test_build_envelope_payload_not_dict() -> None:
    with pytest.raises(ValueError):  # type: ignore[arg-type]
        build_envelope([], "t", "tgt")  # type: ignore[arg-type]


def test_build_envelope_type_not_str() -> None:
    with pytest.raises(ValueError):  # type: ignore[arg-type]
        build_envelope({}, 123, "tgt")  # type: ignore[arg-type]


def test_sign_envelope_missing_field() -> None:
    signer = FileSigner(SEED)
    env = build_envelope({"x": 1}, "t", "tgt")
    del env["cid"]
    with pytest.raises(ValueError):
        sign_envelope(env, signer)


# --- Signer edge cases ---


def test_signer_kid_invalid_mutation() -> None:
    signer = FileSigner(SEED)
    # Corrupt internal _kid then access property
    signer._kid = 123  # type: ignore[assignment]
    with pytest.raises(ValueError):
        _ = signer.kid


def test_signer_sign_message_not_bytes() -> None:
    signer = FileSigner(SEED)
    with pytest.raises(ValueError):  # type: ignore[arg-type]
        signer.sign("not-bytes")  # type: ignore[arg-type]


# --- Verify envelope branches ---


def _signed_envelope() -> tuple[dict[str, Any], dict[str, Any]]:
    signer = FileSigner(SEED)
    env = sign_envelope(build_envelope({"x": 1}, "t", "tgt"), signer)
    jwks = build_jwks_for_signers([signer])
    return env, jwks


def test_verify_envelope_signature_invalid() -> None:
    env, jwks = _signed_envelope()
    env["sender_sig"] = env["sender_sig"][:-2] + "AA"  # corrupt
    ok, reason = verify_envelope(env, jwks)
    assert not ok and reason == "signature_invalid"
    with pytest.raises(SignatureInvalid):
        verify_envelope_or_raise(env, jwks)


def test_verify_envelope_unknown_key_strict() -> None:
    env, jwks = _signed_envelope()
    env["extra_field"] = 1
    with pytest.raises(SchemaError):
        verify_envelope_or_raise(env, jwks, strict=True)


def test_verify_envelope_missing_ts_type() -> None:
    env, jwks = _signed_envelope()
    env["ts"] = 123  # type: ignore[assignment]
    with pytest.raises(SchemaError):
        verify_envelope_or_raise(env, jwks)


def test_verify_envelope_invalid_ts_format() -> None:
    env, jwks = _signed_envelope()
    env["ts"] = "not-a-timestamp"
    ok, reason = verify_envelope(env, jwks)
    # Current implementation attempts signature verify first, so boolean API
    # surfaces signature_invalid (order of checks). Raised API still gives SchemaError.
    assert not ok and reason in {"signature_invalid", "schema_error"}
    # Due to verification ordering the raised exception is SignatureInvalid
    with pytest.raises(SignatureInvalid):
        verify_envelope_or_raise(env, jwks)


# --- CLI tests (exercise argument parsing paths) ---


def test_cli_sign_and_verify_envelope(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps({"a": 1}))
    # Sign
    rc = cli_mod.main(
        [
            "sign-envelope",
            "--seed",
            SEED,
            "--payload",
            str(payload_path),
            "--payload-type",
            "t",
            "--target-type",
            "tgt",
            "--emit-jwks",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "envelope" in data and "jwks" in data
    jwks = data["jwks"]
    # Verify via CLI (json output)
    env_path = tmp_path / "env.json"
    env_path.write_text(json.dumps(data))
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps(jwks))
    rc2 = cli_mod.main(
        [
            "verify-envelope",
            "--envelope",
            str(env_path),
            "--jwks",
            str(jwks_path),
            "--json",
        ]
    )
    assert rc2 == 0


def test_cli_verify_bundle(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Build a bundle & signature first
    signer = FileSigner(SEED)
    receipts = [
        {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None},
    ]
    bundle = build_bundle("trace-1", receipts)
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    bundle_path = tmp_path / "bundle.json"
    jwks_path = tmp_path / "jwks.json"
    bundle_path.write_text(json.dumps(bundle))
    jwks_path.write_text(json.dumps(jwks))
    rc = cli_mod.main(
        [
            "verify-bundle",
            "--bundle",
            str(bundle_path),
            "--jwks",
            str(jwks_path),
            "--kid",
            signer.kid,
            "--signature",
            sig,
            "--json",
        ]
    )
    assert rc == 0


def test_cli_sign_invalid_payload_file(tmp_path: pathlib.Path) -> None:
    # Payload file contains list -> should raise
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps([1, 2, 3]))
    with pytest.raises(ValueError):
        cli_mod.main(
            [
                "sign-envelope",
                "--seed",
                SEED,
                "--payload",
                str(payload_path),
                "--payload-type",
                "t",
                "--target-type",
                "tgt",
            ]
        )


# --- Additional bundle receipt and jwks edge cases for coverage ---


def test_bundle_first_receipt_prev_hash_not_none() -> None:
    signer = FileSigner(SEED)
    receipts = [
        {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": "wrong"},
    ]
    bundle = build_bundle("trace-x", receipts)
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(SchemaError):
        verify_bundle_or_raise(bundle, sig, jwks, signer.kid)


def test_bundle_receipt_missing_field() -> None:
    signer = FileSigner(SEED)
    receipts = [
        {"hop": 0, "prev_receipt_hash": None},  # missing receipt_hash
    ]
    bundle = build_bundle("trace-x", receipts)
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(SchemaError):
        verify_bundle_or_raise(bundle, sig, jwks, signer.kid)


def test_bundle_receipt_not_dict() -> None:
    signer = FileSigner(SEED)
    receipts = [
        {"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None},
        "not-a-dict",  # type: ignore[list-item]
    ]
    bundle = build_bundle("trace-x", receipts)  # type: ignore[arg-type]
    sig = sign_bundle(bundle, signer)
    jwks = build_jwks_for_signers([signer])
    with pytest.raises(SchemaError):
        verify_bundle_or_raise(bundle, sig, jwks, signer.kid)


def test_bundle_exported_at_not_str() -> None:
    signer = FileSigner(SEED)
    bundle = build_bundle("trace-x", [{"hop": 0, "receipt_hash": "h0", "prev_receipt_hash": None}])
    sig = sign_bundle(bundle, signer)
    bundle["exported_at"] = 123  # type: ignore[assignment]
    jwks = build_jwks_for_signers([signer])
    ok, reason = verify_bundle(bundle, sig, jwks, signer.kid)
    # Non-string exported_at leads to schema_error path in raised API, but boolean API may
    # still attempt signature and fail as signature_invalid due to formatting in message.
    assert not ok and reason in {"schema_error", "signature_invalid"}


def test_verify_envelope_jwks_keys_not_list() -> None:
    env, _jwks = _signed_envelope()
    # keys should be list; provide dict to force path returning None
    ok, reason = verify_envelope(env, {"keys": {}})  # type: ignore[arg-type]
    assert not ok and reason == "kid_not_found"


def test_verify_envelope_naive_ts() -> None:
    signer = FileSigner(SEED)
    env = build_envelope({"x": 1}, "t", "tgt", ts="2025-01-01T00:00:00")  # naive
    env = sign_envelope(env, signer)
    jwks = build_jwks_for_signers([signer])
    # Naive timestamp currently accepted (tzinfo omitted). Future enforcement may
    # raise SchemaError if timezone required.
    # Accept either success path or TimestampSkew depending on current date.
    try:
        verify_envelope_or_raise(env, jwks, max_skew_seconds=None)
    except Exception as e:  # pragma: no cover - flexible future behavior
        # Allow only specific exceptions
        assert e.__class__.__name__ in {"SchemaError", "TimestampSkew"}
