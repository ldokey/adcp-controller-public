"""Strict canonical JSON and SHA-256 primitives for ADCP payloads."""

from __future__ import annotations

import hashlib
import json
from typing import Any


CANONICAL_JSON_VERSION = 1


class CanonicalizationError(ValueError):
    """A fail-closed error for values outside the canonical JSON profile."""

    def __init__(self, detail: str) -> None:
        self.code = "CANONICAL_JSON_INVALID"
        self.detail = detail
        super().__init__(f"{self.code}: {detail}")


def _validate(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"float forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string key forbidden at {path}")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalizationError(
        f"unsupported type {type(value).__name__} at {path}"
    )


def canonical_json(value: Any) -> str:
    """Serialize a value using the frozen canonical JSON v1 profile."""

    _validate(value, "$")
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
