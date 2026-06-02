import base64
import json
from datetime import datetime, timezone
from server.db.database import get_connection

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))

def user_exists(username: str) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row is not None


def create_user(username: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, created_at) VALUES (?, ?)",
            (username, _now())
        )
        conn.commit()
        return cur.lastrowid


def create_vault(user_id: int, enc_vault_payload: dict, server_share: dict):
    # decode base64 ke bytes untuk disimpan sebagai BLOB
    nonce_bytes = _b64decode(enc_vault_payload["nonce"])
    ciphertext_bytes = _b64decode(enc_vault_payload["ciphertext"])
    tag_bytes = _b64decode(enc_vault_payload["tag"])
    share_text = json.dumps(server_share, sort_keys=True, separators=(",", ":"))

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO vaults (user_id, encrypted_vault, vault_nonce, vault_tag, server_share, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                ciphertext_bytes,
                nonce_bytes,
                tag_bytes,
                share_text,
                _now(),
            ),
        )
        conn.commit()

def get_vault(username: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT v.encrypted_vault, v.vault_nonce, v.vault_tag, v.server_share
            FROM vaults v
            JOIN users u ON v.user_id = u.id
            WHERE u.username = ?
            """,
            (username,)
        ).fetchone()
    
    if row is None:
        return None
    # encode bytes ke base64 string untuk dikirim ke client
    return {
        "server_share": json.loads(row["server_share"]),
        "enc_vault_payload": {
            "nonce": _b64encode(bytes(row["vault_nonce"])),
            "ciphertext": _b64encode(bytes(row["encrypted_vault"])),
            "tag": _b64encode(bytes(row["vault_tag"])),
        },
    }

def update_vault(username:str, enc_vault_payload: dict) -> bool:
    nonce_bytes = _b64decode(enc_vault_payload["nonce"])
    ciphertext_bytes = _b64decode(enc_vault_payload["ciphertext"])
    tag_bytes = _b64decode(enc_vault_payload["tag"])

    with get_connection() as conn:
        user_row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user_row is None:
            return False
        
        changes = conn.execute(
            """
            UPDATE vaults
            SET encrypted_vault = ?, vault_nonce = ?, vault_tag = ?, updated_at = ?
            WHERE user_id = ?
            """,
            (
                ciphertext_bytes,
                nonce_bytes,
                tag_bytes,
                _now(),
                user_row["id"],
            )
        ).rowcount
        conn.commit()
        return changes > 0
