import secrets
import string


PASSWORD_ALPHABET = string.ascii_letters + string.digits + string.punctuation


def generate_password(length: int) -> str:
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise ValueError("length must be a positive integer")
    # secrets dipakai agar pilihan karakter cocok untuk kebutuhan kriptografi.
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))
