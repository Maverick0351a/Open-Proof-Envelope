from __future__ import annotations

from typing import Any, Protocol

from .cid import compute_cid
from .utils import new_trace_id, now_utc_iso


def build_envelope(
    payload: dict[str, Any],
    payload_type: str,
    target_type: str,
    trace_id: str | None = None,
    ts: str | None = None,
) -> dict[str, Any]:
    """
    Create an unsigned envelope with computed CID.

    Args:
        payload: dict payload to wrap (must be dict)
        payload_type: string type label
        target_type: string type label
        trace_id: optional string trace ID
        ts: optional ISO8601 timestamp

    Returns:
        dict with keys: payload, payload_type, target_type, cid, trace_id, ts

    CID format: 'sha256:<hex>'
    """
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    if not isinstance(payload_type, str) or not isinstance(target_type, str):
        raise ValueError("payload_type and target_type must be strings")
    env = {
        "payload": payload,
        "payload_type": payload_type,
        "target_type": target_type,
    }
    env["cid"] = compute_cid(payload)
    env["trace_id"] = trace_id or new_trace_id()
    env["ts"] = ts or now_utc_iso()
    return env


def _message_for_envelope(envelope: dict[str, Any]) -> bytes:
    return f"{envelope['cid']}|{envelope['trace_id']}|{envelope['ts']}".encode()


class _SignerProto(Protocol):  # minimal protocol for envelope signer
    kid: str

    def sign(self, msg: bytes) -> str: ...


def sign_envelope(envelope: dict[str, Any], signer: _SignerProto) -> dict[str, Any]:
    """
    Attach sender signature and kid to an envelope. Returns a new dict.

    Args:
        envelope: dict as from build_envelope
        signer: object with .sign(bytes) and .kid

    Returns:
        dict with added 'sender_sig' (base64url) and 'kid' (str)

    Raises:
        ValueError if envelope is missing required fields
    """
    if not isinstance(envelope, dict):
        raise ValueError("envelope must be a dict")
    for field in ("cid", "trace_id", "ts"):
        if field not in envelope:
            raise ValueError(f"envelope missing required field: {field}")
    env = dict(envelope)
    msg = _message_for_envelope(env)
    env["sender_sig"] = signer.sign(msg)
    env["kid"] = signer.kid
    return env
