"""Custom exception hierarchy for odin_ope verification errors."""
from __future__ import annotations

class OdinOPEError(Exception):
    """Base class for all odin_ope errors."""

class CidMismatch(OdinOPEError):
    pass

class MissingSigOrKid(OdinOPEError):
    pass

class KidNotFound(OdinOPEError):
    pass

class SignatureInvalid(OdinOPEError):
    pass

class TimestampSkew(OdinOPEError):
    pass

class SchemaError(OdinOPEError):
    pass

class NotYetValid(OdinOPEError):
    pass

class Expired(OdinOPEError):
    pass

try:  # Python 3.11+ Enum available always
    from enum import Enum
except Exception:  # pragma: no cover
    Enum = object  # type: ignore

class ReasonCode(str, Enum):
    """Normalized reason codes for boolean / CLI interfaces."""
    CID_MISMATCH = "cid_mismatch"
    MISSING_SIG_OR_KID = "missing_sig_or_kid"
    KID_NOT_FOUND = "kid_not_found"
    SIGNATURE_INVALID = "signature_invalid"
    TIMESTAMP_SKEW = "timestamp_skew"
    SCHEMA_ERROR = "schema_error"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"

EXC_TO_REASON = {
    CidMismatch: ReasonCode.CID_MISMATCH,
    MissingSigOrKid: ReasonCode.MISSING_SIG_OR_KID,
    KidNotFound: ReasonCode.KID_NOT_FOUND,
    SignatureInvalid: ReasonCode.SIGNATURE_INVALID,
    TimestampSkew: ReasonCode.TIMESTAMP_SKEW,
    SchemaError: ReasonCode.SCHEMA_ERROR,
    NotYetValid: ReasonCode.NOT_YET_VALID,
    Expired: ReasonCode.EXPIRED,
}

def reason_code_for_exception(exc: Exception) -> str:
    for et, rc in EXC_TO_REASON.items():
        if isinstance(exc, et):
            return rc.value
    return exc.__class__.__name__.lower()
