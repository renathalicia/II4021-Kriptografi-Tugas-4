import os
import json
import base64

# Folder data dua level di atas file ini = root project / data
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(_BASE, "data")
CONFIG_FILE = os.path.join(DATA_DIR, "client_config.json")


def _buat_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def simpan_config(username: str, enc_local_payload: dict, kdf_salt: bytes, 
                  iterations: int = 200000):
    """Simpan konfigurasi lokal setelah vault dibuat."""
    _buat_dir()
    data = {
        "username": username,
        "enc_local_payload": enc_local_payload,  # dict dari A: {nonce, ciphertext, tag}
        "kdf_salt": base64.b64encode(kdf_salt).decode(),
        "iterations": iterations,
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)

def muat_config() -> dict | None:
    """Baca config lokal."""
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE) as f:
        raw = json.load(f)
    raw["kdf_salt"] = base64.b64decode(raw["kdf_salt"])
    return raw


def sudah_ada() -> bool:
    return os.path.exists(CONFIG_FILE)