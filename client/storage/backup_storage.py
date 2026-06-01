import os
import json
import base64

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(_BASE, "data")
BACKUP_FILE = os.path.join(DATA_DIR, "backup_vault.json")


def _buat_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def simpan_backup(enc_vault_payload: dict):
    #Update backup vault lokal. enc_vault_payload adalah dict dari AES-GCM
    _buat_dir()
    data = {
        "enc_vault_payload": enc_vault_payload,  # dict: {nonce, ciphertext, tag}
    }
    with open(BACKUP_FILE, "w") as f:
        json.dump(data, f)

def muat_backup() -> dict | None:
    #Load backup vault
    if not os.path.exists(BACKUP_FILE):
        return None
    with open(BACKUP_FILE) as f:
        raw = json.load(f)
    return {
        "enc_vault_payload": raw["enc_vault_payload"]
    }

def ada_backup() -> bool:
    return os.path.exists(BACKUP_FILE)