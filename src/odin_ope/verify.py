from __future__ import annotations
from typing import Dict, Any, Tuple, Iterable, Optional
import os
from datetime import datetime, timezone
from .exceptions import (
    CidMismatch,
    MissingSigOrKid,
    KidNotFound,
    SignatureInvalid,
    TimestampSkew,
    SchemaError,
    NotYetValid,
    Expired,
    reason_code_for_exception,
)
from .constants import MESSAGE_FORMAT_VERSION
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .utils import b64u_decode
from .cid import compute_cid

def _find_jwk(jwks: Dict[str, Any], kid: str) -> Dict[str, Any] | None:
    keys = jwks.get("keys") or []
    for k in keys:
        if k.get("kid") == kid:
            return k
    return None

def _verify_sig_ed25519(jwk: Dict[str, Any], message: bytes, sig_b64u: str) -> bool:
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
    envelope: Dict[str, Any],
    jwks: Dict[str, Any],
) -> Tuple[bool, str | None]:
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

def verify_envelope_or_raise(
    envelope: Dict[str, Any],
    jwks: Dict[str, Any],
    *,
    max_skew_seconds: Optional[int] = None,
    now: Optional[datetime] = None,
    strict: bool = False,
) -> None:
    """Verify an envelope or raise a typed exception.

    Args:
        envelope: envelope dict produced by build_envelope + sign_envelope
        jwks: JWKS dict ( {"keys": [ {kid,...}, ... ]} )
        max_skew_seconds: if provided, ensure |now - ts| <= max_skew_seconds
        now: override current time (UTC) for deterministic tests
        strict: if True (or env ODIN_OPE_STRICT=1) enforce schema (no unknown keys)

    Raises:
        CidMismatch, MissingSigOrKid, KidNotFound, SignatureInvalid, TimestampSkew, SchemaError
    """
    if not isinstance(envelope, dict):  # fast path
        raise SchemaError("envelope must be dict")
    if strict or os.getenv("ODIN_OPE_STRICT") == "1":
        unknown = set(envelope.keys()) - ALLOWED_ENVELOPE_KEYS
        if unknown:
            raise SchemaError(f"unknown envelope keys: {sorted(unknown)}")
    # CID check
    actual_cid = compute_cid(envelope.get("payload"))
    if envelope.get("cid") != actual_cid:
        raise CidMismatch("cid mismatch")
    sig = envelope.get("sender_sig")
    kid = envelope.get("kid")
    if not sig or not kid:
        raise MissingSigOrKid("missing sender_sig or kid")
    jwk = _find_jwk(jwks, kid)
    if not jwk:
        raise KidNotFound(f"kid not found: {kid}")
    ts = envelope.get("ts")
    if not isinstance(ts, str):
        raise SchemaError("ts missing or not str")
    if max_skew_seconds is not None:
        _now = now or datetime.now(timezone.utc)
        try:
            ts_dt = _parse_ts(ts)
        except Exception as e:
            raise SchemaError(f"invalid ts format: {e}") from e
        if ts_dt.tzinfo is None:
            raise SchemaError("ts must be timezone-aware")
        skew = abs((_now - ts_dt).total_seconds())
        if skew > max_skew_seconds:
            raise TimestampSkew(f"timestamp skew {skew:.1f}s > {max_skew_seconds}s")
    # Optional not_before / expires_at checks
    nb = envelope.get("not_before")
    exp = envelope.get("expires_at")
    if nb or exp:
        _now = now or datetime.now(timezone.utc)
        if nb:
            try:
                nb_dt = _parse_ts(nb)
            except Exception as e:
                raise SchemaError(f"invalid not_before: {e}") from e
            if nb_dt > _now:
                raise NotYetValid("envelope not yet valid")
        if exp:
            try:
                exp_dt = _parse_ts(exp)
            except Exception as e:
                raise SchemaError(f"invalid expires_at: {e}") from e
            if exp_dt <= _now:
                raise Expired("envelope expired")
    message = f"{envelope['cid']}|{envelope['trace_id']}|{ts}".encode("utf-8")
    if not _verify_sig_ed25519(jwk, message, sig):
        raise SignatureInvalid("signature invalid")


def build_jwks_for_signers(signers: Iterable) -> Dict[str, Any]:
    return {"keys": [s.public_jwk() for s in signers]}
