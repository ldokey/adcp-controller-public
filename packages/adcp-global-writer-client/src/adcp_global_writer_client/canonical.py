from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from .errors import GlobalWriterClientError


def _validate_json(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise GlobalWriterClientError("CANONICAL_JSON_INVALID", f"float forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise GlobalWriterClientError("CANONICAL_JSON_INVALID", f"non-string key at {path}")
            _validate_json(item, f"{path}.{key}")
        return
    raise GlobalWriterClientError("CANONICAL_JSON_INVALID", f"unsupported type at {path}")


def canonical_json(value: Any) -> str:
    _validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise GlobalWriterClientError("INVALID_TIMESTAMP", "timezone-aware input required")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def require_sha256(value: str, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise GlobalWriterClientError("INVALID_INPUT", f"{field} must be lowercase SHA-256")
