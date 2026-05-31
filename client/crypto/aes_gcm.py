import base64
import binascii
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(f"{field_name} is not valid base64") from exc


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError("AES-128-GCM key must be 16 bytes")


def encrypt_vault(plaintext_json: str, key: bytes) -> dict:
    _validate_key(key)
    if not isinstance(plaintext_json, str):
        raise ValueError("plaintext_json must be a string")

    nonce = secrets.token_bytes(NONCE_SIZE)
    encrypted = AESGCM(key).encrypt(nonce, plaintext_json.encode("utf-8"), None)
    ciphertext, tag = encrypted[:-TAG_SIZE], encrypted[-TAG_SIZE:]
    return {
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "tag": _b64encode(tag),
    }


def decrypt_vault(payload: dict, key: bytes) -> str:
    _validate_key(key)
    if not isinstance(payload, dict):
        raise ValueError("encrypted payload must be a dictionary")

    try:
        nonce = _b64decode(payload["nonce"], "nonce")
        ciphertext = _b64decode(payload["ciphertext"], "ciphertext")
        tag = _b64decode(payload["tag"], "tag")
    except KeyError as exc:
        raise ValueError(f"missing encrypted payload field: {exc.args[0]}") from exc

    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be 12 bytes")
    if len(tag) != TAG_SIZE:
        raise ValueError("tag must be 16 bytes")

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    except InvalidTag as exc:
        raise ValueError("decryption failed: invalid key or corrupted payload") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("decrypted vault is not valid UTF-8") from exc
