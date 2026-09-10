import hmac
import hashlib

def sign(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def verify(secret: bytes, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, message), signature)
