import requests
import base64

# [KOORDINASIIN SAMA B] ganti URL dan nama field kalau beda
BASE_URL = "http://localhost:5000"
TIMEOUT = 5


class APIClient:
    def __init__(self, base_url: str = BASE_URL):
        self.url = base_url.rstrip("/")

    def ping(self) -> bool:
        """Cek server hidup atau tidak."""
        try:
            r = requests.get(f"{self.url}/ping", timeout=TIMEOUT)
            return r.status_code == 200
        except Exception:
            return False

    def register(self, username: str, enc_local_payload: dict,
             enc_vault_payload: dict, server_share: dict) -> bool:
    #Kirim data awal vault ke server saat setup
        payload = {
            "username": username,
            "enc_local_payload": enc_local_payload, # dict {nonce, ciphertext, tag}
            "enc_vault_payload": enc_vault_payload, # dict {nonce, ciphertext, tag}
            "server_share": server_share, # dict {x, y}
        }
        try:
            r = requests.post(f"{self.url}/vault/register", json=payload, timeout=TIMEOUT)
            return r.status_code in (200, 201)
        except Exception:
            return False

    def fetch(self, username: str) -> dict | None:
        #Ambil server share + vault dari server (mode normal)
        try:
            r = requests.get(f"{self.url}/vault/fetch/{username}", timeout=TIMEOUT)
            if r.status_code != 200:
                return None
            d = r.json()
            return {
                "server_share": d["server_share"], # dict {x, y}
                "enc_vault_payload": d["enc_vault_payload"], # dict {nonce, ciphertext, tag}
            }
        except Exception:
            return None


    def update(self, username: str, enc_vault_payload: dict) -> bool:
        #Kirim vault yang sudah diencrypt ulang ke server
        payload = {
            "username": username,
            "enc_vault_payload": enc_vault_payload, # dict {nonce, ciphertext, tag}
        }
        try:
            r = requests.put(f"{self.url}/vault/update", json=payload, timeout=TIMEOUT)
            return r.status_code == 200
        except Exception:
            return False
