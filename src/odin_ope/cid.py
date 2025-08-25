from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from .utils import sha256_hex

JsonScalar = str | int | float | bool | None
JsonType = JsonScalar | Mapping[str, "JsonType"] | Sequence["JsonType"]  # recursive alias


def canonical_json(obj: JsonType) -> bytes:
    """Return deterministic UTF-8 JSON bytes with sorted keys and no extra spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def compute_cid(obj: JsonType) -> str:
    """Compute content identifier as 'sha256:<hex>' over canonical JSON bytes."""
    return f"sha256:{sha256_hex(canonical_json(obj))}"
