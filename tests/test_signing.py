import unittest
from src.signing import sign, verify

class SigningTest(unittest.TestCase):
    def test_tamper_is_rejected(self):
        signature = sign(b"local-demo", b"nonce-1")
        self.assertTrue(verify(b"local-demo", b"nonce-1", signature))
        self.assertFalse(verify(b"local-demo", b"nonce-2", signature))

if __name__ == "__main__":
    unittest.main()
