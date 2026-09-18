from __future__ import annotations

import unittest

from adcp.canonical import (
    CanonicalizationError,
    canonical_bytes,
    canonical_json,
    canonical_sha256,
)


class CanonicalTests(unittest.TestCase):
    def test_canonical_dict_order_stable(self) -> None:
        self.assertEqual(
            canonical_json({"b": 2, "a": {"d": 4, "c": 3}}),
            canonical_json({"a": {"c": 3, "d": 4}, "b": 2}),
        )

    def test_canonical_unicode_utf8_no_bom_no_trailing_newline(self) -> None:
        encoded = canonical_bytes({"한국어": "문맥", "emoji": "✓"})
        self.assertEqual(encoded, canonical_json({"한국어": "문맥", "emoji": "✓"}).encode("utf-8"))
        self.assertFalse(encoded.startswith(b"\xef\xbb\xbf"))
        self.assertFalse(encoded.endswith(b"\n"))
        self.assertIn("한국어".encode("utf-8"), encoded)

    def test_canonical_nested_float_rejected(self) -> None:
        for value in (
            {"outer": [{"value": 1.5}]},
            {"nan": float("nan")},
            {"infinity": float("inf")},
        ):
            with self.assertRaisesRegex(CanonicalizationError, "float forbidden"):
                canonical_json(value)

    def test_canonical_non_string_key_rejected(self) -> None:
        with self.assertRaisesRegex(CanonicalizationError, "non-string key"):
            canonical_json({"outer": [{1: "forbidden"}]})

    def test_canonical_array_order_preserved(self) -> None:
        self.assertEqual('{"items":[3,1,2]}', canonical_json({"items": [3, 1, 2]}))
        self.assertNotEqual(
            canonical_json({"items": [3, 1, 2]}),
            canonical_json({"items": [1, 2, 3]}),
        )

    def test_canonical_hash_stable_and_lowercase(self) -> None:
        left = canonical_sha256({"z": 1, "a": [True, None, "✓"]})
        right = canonical_sha256({"a": [True, None, "✓"], "z": 1})
        self.assertEqual(left, right)
        self.assertRegex(left, r"^[0-9a-f]{64}$")

    def test_canonical_unsupported_nested_type_rejected(self) -> None:
        with self.assertRaisesRegex(CanonicalizationError, "unsupported type tuple"):
            canonical_json({"bad": (1, 2)})


if __name__ == "__main__":
    unittest.main()
