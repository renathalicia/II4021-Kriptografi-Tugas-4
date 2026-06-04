import os
import json

from client.models.password_entry import PasswordEntry
from client.storage.local_storage import simpan_config, muat_config, sudah_ada
from client.storage.backup_storage import simpan_backup, muat_backup
from client.services.api_client import APIClient

from client.crypto.shamir import (
    generate_master_key,
    split_master_key,
    reconstruct_master_key,
    encrypt_local_share,
    decrypt_local_share,
    serialize_share,
    validate_share,
)
from client.crypto.aes_gcm import encrypt_vault, decrypt_vault
from client.crypto.kdf import derive_key, generate_salt
from client.crypto.password_generator import generate_password

_api = APIClient()


class VaultSession:
    """Representasi vault yang sedang terbuka di memori."""
    
    def __init__(self, master_key: bytes, enc_vault_payload: dict, 
                 username: str, readonly: bool = False):
        self.username = username
        self.readonly = readonly
        self.master_key = master_key
        self.modified = False

        # Dekripsi vault pakai A's function
        try:
            vault_json = decrypt_vault(enc_vault_payload, master_key)
            entries_raw = json.loads(vault_json)
            self.entries = [PasswordEntry.from_dict(e) for e in entries_raw]
        except Exception:
            raise ValueError("Dekripsi vault gagal. Master key tidak valid atau vault rusak.")

    def daftar(self):
        return self.entries

    def _ensure_writable(self):
        if self.readonly:
            raise PermissionError("Mode backup bersifat read-only.")

    def tambah(self, nama_layanan: str, username: str,
               password: str, catatan: str = ""):
        self._ensure_writable()
        e = PasswordEntry(nama_layanan=nama_layanan, username=username,
                          password=password, catatan=catatan)
        self.entries.append(e)
        self.modified = True
        return e

    def edit(self, idx: int, nama_layanan=None, username=None,
             password=None, catatan=None):
        self._ensure_writable()
        if not (0 <= idx < len(self.entries)):
            raise IndexError("Nomor entri tidak valid.")
        e = self.entries[idx]
        if nama_layanan: e.nama_layanan = nama_layanan
        if username:     e.username = username
        if password:     e.password = password
        if catatan is not None: e.catatan = catatan
        self.modified = True

    def hapus(self, idx: int):
        self._ensure_writable()
        if not (0 <= idx < len(self.entries)):
            raise IndexError("Nomor entri tidak valid.")
        removed = self.entries.pop(idx)
        self.modified = True
        return removed

    def simpan(self):
        """Re-enkripsi vault dengan nonce baru, update server dan backup lokal."""
        self._ensure_writable()
        entries_raw = [e.to_dict() for e in self.entries]
        vault_json = json.dumps(entries_raw, ensure_ascii=False)
        
        # Enkripsi ulang pakai A's function — return dict {nonce, ciphertext, tag}
        enc_vault_payload_baru = encrypt_vault(vault_json, self.master_key)

        # Push ke server
        if not _api.update(self.username, enc_vault_payload_baru):
            raise RuntimeError("Gagal update vault ke server.")

        # Update backup lokal juga
        simpan_backup(enc_vault_payload_baru)
        self.modified = False
        print("[+] Vault disimpan dengan nonce baru.")


def init_vault(username: str, master_password: str) -> str:
    """
    Setup vault baru:
    1. Generate master key
    2. Pecah jadi 3 share Shamir (2-of-3)
    3. Enkripsi local share pakai KDF key
    4. Kirim server share ke server
    5. Simpan config lokal + backup
    
    Return: recovery share string (JSON format dari A)
    """
    if sudah_ada():
        raise RuntimeError("Vault sudah ada di perangkat ini.")
    if not _api.ping():
        raise RuntimeError("Server tidak bisa diakses. Pastikan server sudah jalan.")

    # 1. Master key 16 bytes
    master_key = generate_master_key()

    # 2. Pecah jadi 3 share — A return list[dict] dengan {"x": int, "y": "base64..."}
    shares = split_master_key(master_key)
    local_share = shares[0]      # {"x": 1, "y": "base64..."}
    server_share = shares[1]     # {"x": 2, "y": "base64..."}
    recovery_share = shares[2]   # {"x": 3, "y": "base64..."}

    # 3. Turunkan kunci dari master password
    kdf_salt = generate_salt()
    derived_key = derive_key(master_password, kdf_salt, iterations=200000)

    # 4. Enkripsi local share — A's function return dict {nonce, ciphertext, tag}
    enc_local_payload = encrypt_local_share(local_share, derived_key)

    # 5. Buat vault kosong dan enkripsi — A's function
    vault_kosong = json.dumps([])  # string, bukan bytes
    enc_vault_payload = encrypt_vault(vault_kosong, master_key)

    # 6. Kirim ke server
    # if not _api.register(username, enc_local_payload, enc_vault_payload, server_share):
    #     raise RuntimeError("Gagal register ke server.")

    # 6. Kirim ke server (tanpa enc_local_payload, krn hanya disimpan lokal)
    if not _api.register(username, enc_vault_payload, server_share):
        raise RuntimeError("Gagal register ke server.")
    
    # 7. Simpan lokal
    simpan_config(username, enc_local_payload, kdf_salt, iterations=200000)
    simpan_backup(enc_vault_payload)

    # Return recovery share sebagai JSON string (A's function)
    return serialize_share(recovery_share)


def buka_vault_normal(master_password: str) -> VaultSession:
    """Mode normal: rekonstruksi dari local share + server share."""
    config = muat_config()
    if config is None:
        raise RuntimeError("Vault belum ada. Lakukan setup dulu.")

    # Derive kunci dari password + salt yang tersimpan
    derived_key = derive_key(master_password, config["kdf_salt"], 
                             iterations=config.get("iterations", 200000))

    # Dekripsi local share — A's function
    try:
        local_share = decrypt_local_share(config["enc_local_payload"], derived_key)
        # local_share adalah dict: {"x": 1, "y": "base64..."}
    except Exception:
        raise ValueError("Master password salah.")

    # Ambil data dari server
    data = _api.fetch(config["username"])
    if data is None:
        raise RuntimeError("Tidak bisa ambil data dari server.")

    server_share = data["server_share"]  # {"x": 2, "y": "base64..."}
    enc_vault_payload = data["enc_vault_payload"]  # dict {nonce, ciphertext, tag}

    # Rekonstruksi master key — A's function takes exactly 2 dicts
    try:
        master_key = reconstruct_master_key([local_share, server_share])
    except Exception as e:
        raise ValueError(f"Rekonstruksi master key gagal: {e}")

    return VaultSession(master_key, enc_vault_payload, config["username"], readonly=False)


def buka_vault_backup(master_password: str, recovery_str: str) -> VaultSession:
    """Mode backup: rekonstruksi dari local share + recovery share. Tanpa server."""
    config = muat_config()
    if config is None:
        raise RuntimeError("Vault belum ada. Lakukan setup dulu.")

    derived_key = derive_key(master_password, config["kdf_salt"],
                             iterations=config.get("iterations", 200000))

    try:
        local_share = decrypt_local_share(config["enc_local_payload"], derived_key)
    except Exception:
        raise ValueError("Master password salah.")

    try:
        # Parse recovery share dari JSON string
        recovery_share = json.loads(recovery_str)
        # Validate pakai A's function
        validate_share(recovery_share)
    except Exception:
        raise ValueError("Format recovery share tidak valid. Harusnya JSON dengan x dan y.")

    backup = muat_backup()
    if backup is None:
        raise RuntimeError("Backup vault lokal tidak ditemukan.")

    try:
        master_key = reconstruct_master_key([local_share, recovery_share])
    except Exception as e:
        raise ValueError(f"Rekonstruksi master key gagal: {e}")

    return VaultSession(master_key, backup["enc_vault_payload"],
                        config["username"], readonly=True)


def buat_password_acak(panjang: int) -> str:
    """Generate password menggunakan CSPRNG dari modul A."""
    return generate_password(panjang)
