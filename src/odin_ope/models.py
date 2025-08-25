"""Typed models for higher-level usage (optional, zero-runtime overhead)."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


@dataclass(slots=True)
class EnvelopeModel:
    payload: Dict[str, Any]
    payload_type: str
    target_type: str
    cid: str
    trace_id: str
    ts: str
    sender_sig: Optional[str] = None
    kid: Optional[str] = None
    not_before: Optional[str] = None
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EnvelopeModel":
        return cls(
            payload=d["payload"],
            payload_type=d["payload_type"],
            target_type=d["target_type"],
            cid=d["cid"],
            trace_id=d["trace_id"],
            ts=d["ts"],
            sender_sig=d.get("sender_sig"),
            kid=d.get("kid"),
            not_before=d.get("not_before"),
            expires_at=d.get("expires_at"),
        )

    def to_dict(self) -> Dict[str, Any]:  # keep ordering minimal
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass(slots=True)
class ReceiptModel:
    hop: int
    receipt_hash: str
    prev_receipt_hash: Optional[str]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ReceiptModel":
        return cls(d["hop"], d["receipt_hash"], d.get("prev_receipt_hash"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hop": self.hop,
            "receipt_hash": self.receipt_hash,
            "prev_receipt_hash": self.prev_receipt_hash,
        }


@dataclass(slots=True)
class BundleModel:
    trace_id: str
    receipts: List[ReceiptModel] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BundleModel":
        return cls(
            trace_id=d["trace_id"],
            receipts=[ReceiptModel.from_dict(r) for r in d.get("receipts", [])],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {"trace_id": self.trace_id, "receipts": [r.to_dict() for r in self.receipts]}
