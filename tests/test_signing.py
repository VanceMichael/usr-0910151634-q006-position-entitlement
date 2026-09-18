import unittest

from src.signing import (
    canonical_message,
    request_hash,
    sign,
    sign_request,
    verify,
    verify_request,
)


class SigningTest(unittest.TestCase):
    def test_tamper_is_rejected(self):
        signature = sign(b"local-demo", b"nonce-1")
        self.assertTrue(verify(b"local-demo", b"nonce-1", signature))
        self.assertFalse(verify(b"local-demo", b"nonce-2", signature))

    def test_request_canonical_signature_covers_every_field(self):
        payload = {
            "idempotency_key": "idem-1",
            "key_id": "demo-key-a",
            "timestamp": "2026-09-05T00:00:00Z",
            "nonce": "nonce-001",
            "resource_scope": "correction/basic",
            "units": 5,
        }
        sig = sign_request("s3cr3t", payload)
        self.assertTrue(verify_request("s3cr3t", payload, sig))

        for field, changed in (
            ("units", 6),
            ("nonce", "nonce-002"),
            ("resource_scope", "correction/premium"),
            ("idempotency_key", "idem-2"),
            ("timestamp", "2026-09-05T00:00:01Z"),
            ("key_id", "demo-key-b"),
        ):
            tampered = dict(payload)
            tampered[field] = changed
            self.assertFalse(
                verify_request("s3cr3t", tampered, sig),
                msg=f"signature must not cover change to {field}",
            )

    def test_wrong_secret_fails(self):
        payload = {
            "idempotency_key": "i", "key_id": "k", "timestamp": "t",
            "nonce": "n", "resource_scope": "s", "units": 1,
        }
        self.assertFalse(verify_request("other", payload, sign_request("s", payload)))

    def test_request_hash_stable_and_distinct(self):
        a = {"idempotency_key": "i", "key_id": "k", "timestamp": "t",
             "nonce": "n", "resource_scope": "s", "units": 1}
        b = dict(a, units=2)
        self.assertEqual(request_hash(a), request_hash(dict(a)))
        self.assertNotEqual(request_hash(a), request_hash(b))

    def test_canonical_message_order_fixed(self):
        payload = {"idempotency_key": "i", "key_id": "k", "timestamp": "t",
                   "nonce": "n", "resource_scope": "s", "units": 1}
        text = canonical_message(payload).decode()
        self.assertEqual(text, "v1\nk\nt\nn\ns\n1\ni")


if __name__ == "__main__":
    unittest.main()
