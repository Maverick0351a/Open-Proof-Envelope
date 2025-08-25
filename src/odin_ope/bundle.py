from __future__ import annotations
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone
from .exceptions import KidNotFound, SignatureInvalid, TimestampSkew, SchemaError
from .cid import compute_cid
from .verify import _find_jwk, _verify_sig_ed25519

def build_bundle(trace_id: str, receipts: list[dict]) -> Dict[str, Any]:
    from .utils import now_utc_iso
    return {
        "trace_id": trace_id,
        "exported_at": now_utc_iso(),
        "receipts": receipts,
    }

def compute_bundle_cid(bundle: Dict[str, Any]) -> str:
    # CID over the whole bundle (trace_id + exported_at + receipts)
    return compute_cid(bundle)

def sign_bundle(bundle: Dict[str, Any], signer) -> str:
    cid = compute_bundle_cid(bundle)
    msg = f"{cid}|{bundle['trace_id']}|{bundle['exported_at']}".encode("utf-8")
    return signer.sign(msg)

def verify_bundle(bundle: Dict[str, Any], signature_b64u: str, jwks: Dict[str, Any], kid: str) -> Tuple[bool, str | None]:
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

def verify_bundle_or_raise(
    bundle: Dict[str, Any],
    signature_b64u: str,
    jwks: Dict[str, Any],
    kid: str,
    *,
    max_skew_seconds: Optional[int] = None,
    now: Optional[datetime] = None,
) -> None:
    if not isinstance(bundle, dict):
        raise SchemaError("bundle must be dict")
    for f in ("trace_id", "exported_at", "receipts"):
        if f not in bundle:
            raise SchemaError(f"bundle missing field {f}")
    receipts = bundle.get("receipts")
    if not isinstance(receipts, list):
        raise SchemaError("receipts must be list")
    # Hop continuity & prev hash linkage
    prev_hash = None
    for idx, r in enumerate(receipts):
        if not isinstance(r, dict):
            raise SchemaError("receipt must be dict")
        if 'hop' not in r or 'receipt_hash' not in r or 'prev_receipt_hash' not in r:
            raise SchemaError("receipt missing required fields")
        if r['hop'] != idx:
            raise SchemaError(f"hop continuity error at index {idx}: got {r['hop']}")
        if idx == 0:
            if r['prev_receipt_hash'] not in (None, ''):
                raise SchemaError("first receipt prev_receipt_hash must be None or empty")
        else:
            if r['prev_receipt_hash'] != prev_hash:
                raise SchemaError(f"prev_receipt_hash mismatch at hop {idx}")
        prev_hash = r['receipt_hash']
    jwk = _find_jwk(jwks, kid)
    if not jwk:
        raise KidNotFound(f"kid not found: {kid}")
    exported_at = bundle.get("exported_at")
    if max_skew_seconds is not None:
        if not isinstance(exported_at, str):
            raise SchemaError("exported_at must be str ISO8601")
        try:
            ea_dt = datetime.fromisoformat(exported_at.replace("Z", "+00:00"))
        except Exception as e:
            raise SchemaError("invalid exported_at") from e
        if ea_dt.tzinfo is None:
            raise SchemaError("exported_at must be timezone-aware")
        _now = now or datetime.now(timezone.utc)
        skew = abs((_now - ea_dt).total_seconds())
        if skew > max_skew_seconds:
            raise TimestampSkew(f"exported_at skew {skew:.1f}s > {max_skew_seconds}s")
    cid = compute_bundle_cid(bundle)
    msg = f"{cid}|{bundle['trace_id']}|{exported_at}".encode("utf-8")
    if not _verify_sig_ed25519(jwk, msg, signature_b64u):
        raise SignatureInvalid("bundle signature invalid")
