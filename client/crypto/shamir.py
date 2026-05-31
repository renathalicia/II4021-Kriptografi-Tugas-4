import base64
import binascii
import json
import secrets

from Crypto.Protocol.SecretSharing import Shamir

from client.crypto.aes_gcm import decrypt_vault, encrypt_vault


MASTER_KEY_SIZE = 16
SHARE_X_VALUES = (1, 2, 3)


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError(f"{field_name} is not valid base64") from exc


def generate_master_key() -> bytes:
    return secrets.token_bytes(MASTER_KEY_SIZE)


def validate_share(share: dict) -> tuple[int, bytes]:
    if not isinstance(share, dict):
        raise ValueError("share must be a dictionary")
    if set(share.keys()) != {"x", "y"}:
        raise ValueError("share must contain exactly x and y")

    x = share["x"]
    if not isinstance(x, int) or isinstance(x, bool) or x not in SHARE_X_VALUES:
        raise ValueError("share x must be one of 1, 2, or 3")

    y = _b64decode(share["y"], "share y")
    if len(y) != MASTER_KEY_SIZE:
        raise ValueError("share y must decode to 16 bytes")
    return x, y


def serialize_share(share: dict) -> str:
    validate_share(share)
    return json.dumps(share, sort_keys=True, separators=(",", ":"))


def split_master_key(master_key: bytes) -> list[dict]:
    if not isinstance(master_key, bytes) or len(master_key) != MASTER_KEY_SIZE:
        raise ValueError("master key must be 16 bytes")

    return [{"x": x, "y": _b64encode(y)} for x, y in Shamir.split(2, 3, master_key)]


def reconstruct_master_key(shares: list[dict]) -> bytes:
    if not isinstance(shares, list) or len(shares) != 2:
        raise ValueError("exactly two shares are required")

    parsed = [validate_share(share) for share in shares]
    if parsed[0][0] == parsed[1][0]:
        raise ValueError("duplicate share x values are not allowed")

    try:
        return Shamir.combine(parsed)
    except ValueError as exc:
        raise ValueError("failed to reconstruct master key") from exc


def encrypt_local_share(share: dict, derived_key: bytes) -> dict:
    serialized_share = serialize_share(share)
    return encrypt_vault(serialized_share, derived_key)


def decrypt_local_share(payload: dict, derived_key: bytes) -> dict:
    plaintext = decrypt_vault(payload, derived_key)
    try:
        share = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        raise ValueError("decrypted local share is not valid JSON") from exc
    validate_share(share)
    return share
