"""请求契约校验（无需数据库）。"""

from __future__ import annotations

import unittest

from src.validators import ValidationError, parse_timestamp, validate

VALID = {
    "idempotency_key": "idem-1",
    "key_id": "demo-key-a",
    "timestamp": "2026-09-05T00:00:00Z",
    "nonce": "nonce-001",
    "resource_scope": "correction/basic",
    "units": 5,
}


class ValidatorTest(unittest.TestCase):
    def test_valid_payload_passes(self):
        out = validate(dict(VALID))
        self.assertEqual(out["units"], 5)

    def test_missing_fields_collected(self):
        with self.assertRaises(ValidationError) as ctx:
            validate({"key_id": "k"})
        joined = " ".join(ctx.exception.errors)
        for field in ("idempotency_key", "timestamp", "nonce",
                      "resource_scope", "units"):
            self.assertIn(field, joined)

    def test_units_must_be_positive_integer(self):
        for bad in (0, -1):
            with self.assertRaises(ValidationError):
                validate({**VALID, "units": bad})
        with self.assertRaises(ValidationError):
            validate({**VALID, "units": 1.5})
        with self.assertRaises(ValidationError):
            validate({**VALID, "units": True})  # bool 不得充作整数

    def test_empty_strings_rejected(self):
        for field in ("idempotency_key", "key_id", "nonce", "resource_scope"):
            with self.assertRaises(ValidationError):
                validate({**VALID, field: ""})

    def test_timestamp_requires_timezone(self):
        with self.assertRaises(ValidationError):
            validate({**VALID, "timestamp": "2026-09-05T00:00:00"})
        # 带偏移量也合法
        out = validate({**VALID, "timestamp": "2026-09-05T08:00:00+08:00"})
        self.assertEqual(
            parse_timestamp(out["timestamp"]).utcoffset().total_seconds(), 8 * 3600
        )

    def test_non_object_body(self):
        with self.assertRaises(ValidationError):
            validate([1, 2, 3])


if __name__ == "__main__":
    unittest.main()
