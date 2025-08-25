from .cid import canonical_json, compute_cid
from .signers import FileSigner, BaseSigner
from .envelope import build_envelope, sign_envelope
from .verify import verify_envelope, build_jwks_for_signers, verify_envelope_or_raise
from .bundle import build_bundle, sign_bundle, verify_bundle, verify_bundle_or_raise
from .exceptions import (
    OdinOPEError,
    CidMismatch,
    MissingSigOrKid,
    KidNotFound,
    SignatureInvalid,
    TimestampSkew,
    SchemaError,
    NotYetValid,
    Expired,
    ReasonCode,
    reason_code_for_exception,
)
from .constants import MESSAGE_FORMAT_VERSION
from .models import EnvelopeModel, BundleModel, ReceiptModel

__all__ = [
    "canonical_json",
    "compute_cid",
    "FileSigner",
    "BaseSigner",
    "build_envelope",
    "sign_envelope",
    "verify_envelope",
    "verify_envelope_or_raise",
    "build_jwks_for_signers",
    "build_bundle",
    "sign_bundle",
    "verify_bundle",
    "verify_bundle_or_raise",
    # exceptions
    "OdinOPEError",
    "CidMismatch",
    "MissingSigOrKid",
    "KidNotFound",
    "SignatureInvalid",
    "TimestampSkew",
    "SchemaError",
    "NotYetValid",
    "Expired",
    "ReasonCode",
    "reason_code_for_exception",
    "MESSAGE_FORMAT_VERSION",
    "EnvelopeModel",
    "BundleModel",
    "ReceiptModel",
    "__version__",
]
try:  # prefer single source of truth from installed metadata
    from importlib.metadata import version as _pkg_version  # Python 3.8+
    __version__ = _pkg_version("odin-ope")  # type: ignore
except Exception:  # pragma: no cover
    __version__ = "0.0.0"
