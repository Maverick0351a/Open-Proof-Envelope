from .bundle import build_bundle, sign_bundle, verify_bundle, verify_bundle_or_raise
from .cid import canonical_json, compute_cid
from .constants import MESSAGE_FORMAT_VERSION
from .envelope import build_envelope, sign_envelope
from .exceptions import (
    CidMismatch,
    Expired,
    KidNotFound,
    MissingSigOrKid,
    NotYetValid,
    OdinOPEError,
    ReasonCode,
    SchemaError,
    SignatureInvalid,
    TimestampSkew,
    reason_code_for_exception,
)
from .models import BundleModel, EnvelopeModel, ReceiptModel
from .signers import BaseSigner, FileSigner
from .verify import build_jwks_for_signers, verify_envelope, verify_envelope_or_raise

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

    __version__ = _pkg_version("odin-ope")
except Exception:  # pragma: no cover
    __version__ = "0.0.0"
