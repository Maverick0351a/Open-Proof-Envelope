from __future__ import annotations
import json
from typing import Any
from .utils import sha256_hex

def canonical_json(obj: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes with sorted keys and no extra spaces."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def compute_cid(obj: Any) -> str:
    """Compute content identifier as 'sha256:<hex>' over canonical JSON bytes."""
    return f"sha256:{sha256_hex(canonical_json(obj))}"
