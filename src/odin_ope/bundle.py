from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, Protocol

from .cid import compute_cid
from .exceptions import KidNotFound, SchemaError, SignatureInvalid, TimestampSkew
from .verify import _find_jwk, _verify_sig_ed25519


def build_bundle(trace_id: str, receipts: list[dict]) -> dict[str, Any]:
    from .utils import now_utc_iso

    return {
        "trace_id": trace_id,
        "exported_at": now_utc_iso(),
        "receipts": receipts,
    }


def compute_bundle_cid(bundle: dict[str, Any]) -> str:
    # CID over the whole bundle (trace_id + exported_at + receipts)
    return compute_cid(bundle)


class _SignerLike(Protocol):  # minimal protocol for signer
    def sign(self: _SignerLike, msg: bytes) -> str: ...  # noqa: D401 - simple protocol


def sign_bundle(bundle: dict[str, Any], signer: _SignerLike) -> str:
    cid = compute_bundle_cid(bundle)
    msg = f"{cid}|{bundle['trace_id']}|{bundle['exported_at']}".encode()
    return signer.sign(msg)


def verify_bundle(
    bundle: dict[str, Any], signature_b64u: str, jwks: dict[str, Any], kid: str
) -> tuple[bool, str | None]:
    try:
        verify_bundle_or_raise(bundle, signature_b64u, jwks, kid)
        return True, None
    except KidNotFound:
        return False, "kid_not_found"
    except SignatureInvalid:
        return False, "signature_invalid"
    except TimestampSkew:
        return False, "timestamp_skew"
    except SchemaError:
        return False, "schema_error"


def _validate_receipts(receipts: Sequence[dict[str, Any]]) -> None:
    prev_hash: str | None = None
    for idx, r in enumerate(receipts):
        if not isinstance(r, dict):
            raise SchemaError("receipt must be dict")
        required = {"hop", "receipt_hash", "prev_receipt_hash"}
        if required - set(r):
            raise SchemaError("receipt missing required fields")
        if r["hop"] != idx:
            raise SchemaError(f"hop continuity error at index {idx}: got {r['hop']}")
        if idx == 0:
            if r["prev_receipt_hash"] not in (None, ""):
                raise SchemaError("first receipt prev_receipt_hash must be None or empty")
        else:
            if r["prev_receipt_hash"] != prev_hash:
                raise SchemaError(f"prev_receipt_hash mismatch at hop {idx}")
        prev_hash = r["receipt_hash"]


def _validate_bundle_structure(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(bundle, dict):
        raise SchemaError("bundle must be dict")
    for f in ("trace_id", "exported_at", "receipts"):
        if f not in bundle:
            raise SchemaError(f"bundle missing field {f}")
    receipts_local = bundle.get("receipts")
    if not isinstance(receipts_local, list):
        raise SchemaError("receipts must be list")
    _validate_receipts(receipts_local)
    return receipts_local


def _check_exported_at_skew(
    exported_at_val: str | None, *, max_skew_seconds: int | None, now: datetime | None
) -> None:
    if max_skew_seconds is None:
        return
    if not isinstance(exported_at_val, str):
        raise SchemaError("exported_at must be str ISO8601")
    try:
        ea_dt = datetime.fromisoformat(exported_at_val.replace("Z", "+00:00"))
    except Exception as e:  # pragma: no cover - defensive
        raise SchemaError("invalid exported_at") from e
    if ea_dt.tzinfo is None:
        raise SchemaError("exported_at must be timezone-aware")
    _now = now or datetime.now(timezone.utc)
    skew = abs((_now - ea_dt).total_seconds())
    if skew > max_skew_seconds:
        raise TimestampSkew(f"exported_at skew {skew:.1f}s > {max_skew_seconds}s")


def verify_bundle_or_raise(
    bundle: dict[str, Any],
    signature_b64u: str,
    jwks: dict[str, Any],
    kid: str,
    *,
    max_skew_seconds: int | None = None,
    now: datetime | None = None,
) -> None:
    _validate_bundle_structure(bundle)
    jwk = _find_jwk(jwks, kid)
    if not jwk:
        raise KidNotFound(f"kid not found: {kid}")
    exported_at = bundle.get("exported_at")
    _check_exported_at_skew(exported_at, max_skew_seconds=max_skew_seconds, now=now)
    cid = compute_bundle_cid(bundle)
    msg = f"{cid}|{bundle['trace_id']}|{exported_at}".encode()
    if not _verify_sig_ed25519(jwk, msg, signature_b64u):
        raise SignatureInvalid("bundle signature invalid")
