from __future__ import annotations


class GlobalWriterClientError(RuntimeError):
    """Fail-closed error with a stable machine-readable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


# Compatibility-friendly local name for callers that only need .code/.detail semantics.
StoreError = GlobalWriterClientError
