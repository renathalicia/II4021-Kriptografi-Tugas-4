import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SALT_SIZE = 16
KEY_SIZE = 16
DEFAULT_ITERATIONS = 200000


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(
    master_password: str,
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
) -> bytes:
    if not isinstance(master_password, str) or not master_password:
        raise ValueError("master_password must be a non-empty string")
    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError("salt must be 16 bytes")
    if not isinstance(iterations, int) or iterations <= 0:
        raise ValueError("iterations must be a positive integer")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode("utf-8"))
