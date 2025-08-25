from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .cid import compute_cid
from .exceptions import (
    CidMismatch,
    Expired,
    KidNotFound,
    MissingSigOrKid,
    NotYetValid,
    SchemaError,
    SignatureInvalid,
    TimestampSkew,
    reason_code_for_exception,
)
from .utils import b64u_decode


def _find_jwk(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
    keys_obj = jwks.get("keys")
    if not isinstance(keys_obj, list):  # defensive
        return None
    for k in keys_obj:
        if isinstance(k, dict) and k.get("kid") == kid:
            # Dict is acceptable return type per signature
            return k
    return None


def _verify_sig_ed25519(jwk: dict[str, Any], message: bytes, sig_b64u: str) -> bool:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False
    x = b64u_decode(jwk["x"])
    pub = Ed25519PublicKey.from_public_bytes(x)
    try:
        pub.verify(b64u_decode(sig_b64u), message)
        return True
    except Exception:
        return False


def verify_envelope(
    envelope: dict[str, Any],
    jwks: dict[str, Any],
) -> tuple[bool, str | None]:
    """Backward-compatible boolean API.

    For richer error handling prefer :func:`verify_envelope_or_raise`.
    Returns (ok, reason) where reason is a short string when not ok.
    """
    try:
        verify_envelope_or_raise(envelope, jwks)
        return True, None
    except Exception as e:
        return False, reason_code_for_exception(e)


ALLOWED_ENVELOPE_KEYS = {
    "payload",
    "payload_type",
    "target_type",
    "cid",
    "trace_id",
    "ts",
    "sender_sig",
    "kid",
    "not_before",
    "expires_at",
}


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _enforce_schema(envelope: dict[str, Any], *, strict: bool) -> None:
    if strict or os.getenv("ODIN_OPE_STRICT") == "1":
        unknown = set(envelope.keys()) - ALLOWED_ENVELOPE_KEYS
        if unknown:
            raise SchemaError(f"unknown envelope keys: {sorted(unknown)}")


def _check_cid(envelope: dict[str, Any]) -> None:
    actual_cid = compute_cid(envelope.get("payload"))
    if envelope.get("cid") != actual_cid:
        raise CidMismatch("cid mismatch")


def _extract_sig_kid(envelope: dict[str, Any]) -> tuple[str, str]:
    sig = envelope.get("sender_sig")
    kid = envelope.get("kid")
    if not sig or not kid:
        raise MissingSigOrKid("missing sender_sig or kid")
    return sig, kid


def _check_timestamp(ts: str, *, max_skew_seconds: int | None, now: datetime | None) -> None:
    if max_skew_seconds is None:
        return
    _now = now or datetime.now(timezone.utc)
    try:
        ts_dt = _parse_ts(ts)
    except Exception as e:  # pragma: no cover - defensive
        raise SchemaError(f"invalid ts format: {e}") from e
    if ts_dt.tzinfo is None:
        raise SchemaError("ts must be timezone-aware")
    skew = abs((_now - ts_dt).total_seconds())
    if skew > max_skew_seconds:
        raise TimestampSkew(f"timestamp skew {skew:.1f}s > {max_skew_seconds}s")


def _check_temporal_validity(envelope: dict[str, Any], *, now: datetime | None) -> None:
    nb = envelope.get("not_before")
    exp = envelope.get("expires_at")
    if not nb and not exp:
        return
    _now = now or datetime.now(timezone.utc)
    if nb:
        try:
            nb_dt = _parse_ts(nb)
        except Exception as e:  # pragma: no cover - defensive
            raise SchemaError(f"invalid not_before: {e}") from e
        if nb_dt > _now:
            raise NotYetValid("envelope not yet valid")
    if exp:
        try:
            exp_dt = _parse_ts(exp)
        except Exception as e:  # pragma: no cover - defensive
            raise SchemaError(f"invalid expires_at: {e}") from e
        if exp_dt <= _now:
            raise Expired("envelope expired")


def _verify_signature(envelope: dict[str, Any], jwk: dict[str, Any], sig: str) -> None:
    message = f"{envelope['cid']}|{envelope['trace_id']}|{envelope['ts']}".encode()
    if not _verify_sig_ed25519(jwk, message, sig):
        raise SignatureInvalid("signature invalid")


def verify_envelope_or_raise(
    envelope: dict[str, Any],
    jwks: dict[str, Any],
    *,
    max_skew_seconds: int | None = None,
    now: datetime | None = None,
    strict: bool = False,
) -> None:
    """Verify an envelope or raise a typed exception."""
    if not isinstance(envelope, dict):
        raise SchemaError("envelope must be dict")
    _enforce_schema(envelope, strict=strict)
    _check_cid(envelope)
    sig, kid = _extract_sig_kid(envelope)
    jwk = _find_jwk(jwks, kid)
    if not jwk:
        raise KidNotFound(f"kid not found: {kid}")
    ts = envelope.get("ts")
    if not isinstance(ts, str):
        raise SchemaError("ts missing or not str")
    _check_timestamp(ts, max_skew_seconds=max_skew_seconds, now=now)
    _check_temporal_validity(envelope, now=now)
    _verify_signature(envelope, jwk, sig)


def build_jwks_for_signers(signers: Iterable) -> dict[str, Any]:
    return {"keys": [s.public_jwk() for s in signers]}
