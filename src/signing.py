"""请求签名：HMAC-SHA256，规范化字符串绑定方法、路径与报文体。

签名串（以 ``\\n`` 分隔）::

    <METHOD>
    <PATH>
    <key_id>
    <timestamp>
    <nonce>
    <idempotency_key>
    sha256(<canonical JSON body>)

报文体使用键排序、无空白的 UTF-8 JSON；时间戳为 ISO-8601（建议 ``Z`` 结尾）。
"""

import hashlib
import hmac
import json
from typing import Any


def sign(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify(secret: bytes, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, message), signature)


def canonical_body(payload: dict[str, Any]) -> bytes:
    """键排序、无分隔空白的确定性 JSON，作为签名与指纹的唯一序列化形式。"""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def body_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_body(payload)).hexdigest()


def signing_string(
    method: str,
    path: str,
    key_id: str,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    payload: dict[str, Any],
) -> bytes:
    return b"\n".join(
        [
            method.upper().encode("utf-8"),
            path.encode("utf-8"),
            key_id.encode("utf-8"),
            timestamp.encode("utf-8"),
            nonce.encode("utf-8"),
            idempotency_key.encode("utf-8"),
            body_hash(payload).encode("ascii"),
        ]
    )


def sign_request(
    secret: bytes,
    method: str,
    path: str,
    key_id: str,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    payload: dict[str, Any],
) -> str:
    message = signing_string(
        method, path, key_id, timestamp, nonce, idempotency_key, payload
    )
    return sign(secret, message)


def request_fingerprint(
    key_id: str,
    timestamp: str,
    nonce: str,
    payload: dict[str, Any],
) -> str:
    """幂等键复用检测：同一幂等键但请求要素不同即拒绝。"""
    material = json.dumps(
        {
            "key_id": key_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "body_hash": body_hash(payload),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
