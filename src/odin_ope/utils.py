from __future__ import annotations
import base64, hashlib, uuid
from datetime import datetime, timezone

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def new_trace_id() -> str:
    return uuid.uuid4().hex

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
