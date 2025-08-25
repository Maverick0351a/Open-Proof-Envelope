from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .utils import b64u_decode, b64u_encode, sha256_hex


class BaseSigner:
    @property
    def kid(self: BaseSigner) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def sign(self: BaseSigner, message: bytes) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def public_jwk(self: BaseSigner) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class FileSigner(BaseSigner):
    """
    Ed25519 signer from a 32-byte seed (base64url, no padding).
    If `kid` not provided, it's derived from the public key: `ed25519-<sha256(pub)[:8]>`.

    Args:
        seed_b64u: Ed25519 seed, base64url (no padding), 32 bytes when decoded.
        _kid: Optional override for key ID. If not set, derived as above.

    KID format: 'ed25519-<sha256(pub)[:8]>'
    Signature format: base64url-encoded Ed25519 signature (no padding)
    """

    seed_b64u: str
    _kid: str | None = None
    # Internal key objects (set in __post_init__)
    _priv: Ed25519PrivateKey = field(init=False, repr=False)
    _pub: Ed25519PublicKey = field(init=False, repr=False)

    def __post_init__(self: FileSigner) -> None:
        if not isinstance(self.seed_b64u, str):
            raise ValueError("seed_b64u must be a base64url string")
        seed = b64u_decode(self.seed_b64u)
        if len(seed) != 32:
            # Use f-string (ruff UP031: prefer format specifiers over percent formatting)
            raise ValueError(f"Ed25519 seed must be 32 bytes (got {len(seed)})")
        self._priv = Ed25519PrivateKey.from_private_bytes(seed)
        self._pub = self._priv.public_key()
        if self._kid is None:
            pub_raw = self._pub.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
            self._kid = f"ed25519-{sha256_hex(pub_raw)[:8]}"

    @property
    def kid(self: FileSigner) -> str:
        if not self._kid or not isinstance(self._kid, str):
            raise ValueError("Invalid or missing KID")
        return self._kid

    def sign(self: FileSigner, message: bytes) -> str:
        if not isinstance(message, bytes):
            raise ValueError("Message to sign must be bytes")
        sig = self._priv.sign(message)
        return b64u_encode(sig)

    def public_jwk(self: FileSigner) -> dict[str, Any]:
        x = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(x), "kid": self.kid}
