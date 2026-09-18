"""HMAC-SHA256 请求签名与规范化。

规范化签名串（行分隔，字段顺序固定）::

    v1
    <key_id>
    <timestamp>            # RFC3339，原样
    <nonce>
    <resource_scope>
    <units>
    <idempotency_key>

任何字段被改动都会导致签名失配。
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Mapping

SIGNATURE_VERSION = "v1"
CANONICAL_FIELDS = (
    "key_id",
    "timestamp",
    "nonce",
    "resource_scope",
    "units",
    "idempotency_key",
)


def sign(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify(secret: bytes, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, message), signature)


def canonical_message(payload: Mapping[str, object]) -> bytes:
    lines = [SIGNATURE_VERSION]
    for field in CANONICAL_FIELDS:
        lines.append(str(payload[field]))
    return "\n".join(lines).encode("utf-8")


def request_hash(payload: Mapping[str, object]) -> str:
    """已规范化请求体的 SHA-256，用于幂等键冲突时检测“同键不同请求”。"""
    return hashlib.sha256(canonical_message(payload)).hexdigest()


def sign_request(secret: str | bytes, payload: Mapping[str, object]) -> str:
    secret_b = secret.encode("utf-8") if isinstance(secret, str) else secret
    return sign(secret_b, canonical_message(payload))


def verify_request(
    secret: str | bytes, payload: Mapping[str, object], signature: str
) -> bool:
    secret_b = secret.encode("utf-8") if isinstance(secret, str) else secret
    return hmac.compare_digest(
        sign_request(secret_b, payload), signature.strip().lower()
    )
