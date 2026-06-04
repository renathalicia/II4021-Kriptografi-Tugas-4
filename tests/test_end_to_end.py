import base64
import json
import os
from unittest.mock import patch

import pytest

_FAKE_Y = base64.b64encode(b"\x00" * 16).decode()


def _fake_encrypt_vault(plaintext: str, key: bytes):
    return {
        "nonce": base64.b64encode(b"\x00" * 12).decode(),
        "ciphertext": base64.b64encode(plaintext.encode()).decode(),
        "tag": base64.b64encode(b"\x00" * 16).decode(),
    }


def _fake_decrypt_vault(payload: dict, key: bytes):
    return json.dumps([])


def _fake_split_master_key(master_key: bytes):
    return [
        {"x": 1, "y": _FAKE_Y},
        {"x": 2, "y": _FAKE_Y},
        {"x": 3, "y": _FAKE_Y},
    ]


def _fake_reconstruct_master_key(shares: list):
    return b"\x00" * 16


def _fake_derive_key(password: str, salt: bytes, iterations: int = 200000):
    return b"\x00" * 16


def _fake_generate_salt():
    return b"salt" * 4


def _fake_generate_password(length: int):
    return "P" * length


def _fake_encrypt_local_share(share: dict, derived_key: bytes):
    return {"nonce": "AAAA", "ciphertext": "AAAA", "tag": "AAAA"}


def _fake_decrypt_local_share(payload: dict, derived_key: bytes):
    return {"x": 1, "y": _FAKE_Y}


def _fake_serialize_share(share: dict):
    return json.dumps(share, sort_keys=True, separators=(",", ":"))


def _fake_validate_share(share: dict):
    return None


_CRYPTO_MOCK = {
    "generate_master_key": lambda: b"\x00" * 16,
    "split_master_key": _fake_split_master_key,
    "reconstruct_master_key": _fake_reconstruct_master_key,
    "encrypt_vault": _fake_encrypt_vault,
    "decrypt_vault": _fake_decrypt_vault,
    "derive_key": _fake_derive_key,
    "generate_salt": _fake_generate_salt,
    "generate_password": _fake_generate_password,
    "encrypt_local_share": _fake_encrypt_local_share,
    "decrypt_local_share": _fake_decrypt_local_share,
    "serialize_share": _fake_serialize_share,
    "validate_share": _fake_validate_share,
}


@pytest.fixture(autouse=True)
def redirect_data(tmp_path, monkeypatch):
    import client.storage.local_storage as ls
    import client.storage.backup_storage as bs

    tmp_data = str(tmp_path / "data")
    monkeypatch.setattr(ls, "DATA_DIR", tmp_data)
    monkeypatch.setattr(ls, "CONFIG_FILE", os.path.join(tmp_data, "client_config.json"))
    monkeypatch.setattr(bs, "DATA_DIR", tmp_data)
    monkeypatch.setattr(bs, "BACKUP_FILE", os.path.join(tmp_data, "backup_vault.json"))


@pytest.fixture
def mock_api_ok():
    with patch("client.services.vault_service._api") as m:
        m.ping.return_value = True
        m.register.return_value = True
        m.update.return_value = True
        m.fetch.return_value = {
            "server_share": {"x": 2, "y": _FAKE_Y},
            "enc_vault_payload": {
                "nonce": base64.b64encode(b"\x00" * 12).decode(),
                "ciphertext": base64.b64encode(json.dumps([]).encode()).decode(),
                "tag": base64.b64encode(b"\x00" * 16).decode(),
            },
        }
        yield m


class TestInitVault:
    def test_setup_berhasil_kembalikan_recovery_share(self, mock_api_ok):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import init_vault
            result = init_vault("usertest", "masterpass")
        parsed = json.loads(result)
        assert isinstance(parsed["x"], int)
        assert len(parsed["y"]) > 0

    def test_setup_gagal_kalau_server_mati(self):
        with patch("client.services.vault_service._api") as m:
            m.ping.return_value = False
            from client.services.vault_service import init_vault
            with pytest.raises(RuntimeError, match="Server tidak bisa diakses"):
                init_vault("user", "pw")

    def test_setup_dua_kali_gagal(self, mock_api_ok):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import init_vault
            init_vault("user1", "pw")
            with pytest.raises(RuntimeError, match="sudah ada"):
                init_vault("user1", "pw")


class TestBukaVaultNormal:
    @pytest.fixture(autouse=True)
    def init_dulu(self, mock_api_ok):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import init_vault
            init_vault("usertest", "benar")

    def test_buka_berhasil(self, mock_api_ok):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import buka_vault_normal, VaultSession
            sesi = buka_vault_normal("benar")
        assert isinstance(sesi, VaultSession)
        assert sesi.readonly is False

    def test_password_salah_ditolak(self, mock_api_ok):
        def decrypt_share_gagal(payload, key):
            raise ValueError("GCM auth tag invalid")
        patches = {**_CRYPTO_MOCK, "decrypt_local_share": decrypt_share_gagal}
        with patch.multiple("client.services.vault_service", **patches):
            from client.services.vault_service import buka_vault_normal
            with pytest.raises(ValueError, match="Master password salah"):
                buka_vault_normal("salah")

    def test_server_mati_gagal(self):
        with patch("client.services.vault_service._api") as m:
            m.ping.return_value = False
            m.fetch.return_value = None
            with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
                from client.services.vault_service import buka_vault_normal
                with pytest.raises(RuntimeError):
                    buka_vault_normal("benar")


class TestCRUDVault:
    @pytest.fixture(autouse=True)
    def buka_sesi(self, mock_api_ok):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import init_vault, buka_vault_normal
            init_vault("user", "pw")
            self.sesi = buka_vault_normal("pw")

    def test_vault_awal_kosong(self):
        assert self.sesi.daftar() == []

    def test_tambah_entri(self):
        e = self.sesi.tambah("GitHub", "dev@test.com", "gh_pass", "akun kerja")
        assert len(self.sesi.daftar()) == 1
        assert e.nama_layanan == "GitHub"
        assert self.sesi.modified is True

    def test_tambah_tanpa_catatan(self):
        self.sesi.tambah("Gmail", "g@g.com", "pw123")
        assert self.sesi.entries[0].catatan == ""

    def test_edit_password(self):
        self.sesi.tambah("Twitter", "tw@g.com", "lama")
        self.sesi.edit(0, password="baru")
        assert self.sesi.entries[0].password == "baru"
        assert self.sesi.modified is True

    def test_hapus_entri(self):
        self.sesi.tambah("A", "a@a.com", "pa")
        self.sesi.tambah("B", "b@b.com", "pb")
        self.sesi.hapus(0)
        assert len(self.sesi.daftar()) == 1
        assert self.sesi.entries[0].nama_layanan == "B"

    def test_hapus_index_invalid_raise(self):
        with pytest.raises(IndexError):
            self.sesi.hapus(99)

    def test_simpan_panggil_api_update(self, mock_api_ok):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            self.sesi.tambah("Test", "t@t.com", "pw")
            self.sesi.simpan()
        mock_api_ok.update.assert_called_once()
        assert self.sesi.modified is False

    def test_generate_password_panjang_benar(self):
        from client.services.vault_service import buat_password_acak
        with patch("client.services.vault_service.generate_password",
                   side_effect=_fake_generate_password):
            hasil = buat_password_acak(20)
        assert len(hasil) == 20
        assert hasil == "P" * 20


class TestModeBackup:
    @pytest.fixture(autouse=True)
    def init_dulu(self, mock_api_ok):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import init_vault
            self.recovery = init_vault("user", "pw")

    def test_buka_backup_readonly(self):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import buka_vault_backup
            sesi = buka_vault_backup("pw", self.recovery)
        assert sesi.readonly is True

    def test_recovery_share_format_salah_ditolak(self):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import buka_vault_backup
            with pytest.raises(ValueError, match="Format"):
                buka_vault_backup("pw", "ini-bukan-format-yang-benar")

    def test_password_salah_di_backup_ditolak(self):
        def decrypt_share_gagal(payload, key):
            raise ValueError("auth gagal")
        patches = {**_CRYPTO_MOCK, "decrypt_local_share": decrypt_share_gagal}
        with patch.multiple("client.services.vault_service", **patches):
            from client.services.vault_service import buka_vault_backup
            with pytest.raises(ValueError, match="Master password salah"):
                buka_vault_backup("salah", self.recovery)


class TestReenkripsivault:
    def test_nonce_baru_setiap_simpan(self, mock_api_ok):
        nonce_list = []

        def fake_encrypt_track(plaintext, key):
            nonce = base64.b64encode(os.urandom(12)).decode()
            nonce_list.append(nonce)
            return {
                "nonce": nonce,
                "ciphertext": base64.b64encode(b"cipher").decode(),
                "tag": base64.b64encode(b"\x00" * 16).decode(),
            }

        patches = {**_CRYPTO_MOCK, "encrypt_vault": fake_encrypt_track}
        with patch.multiple("client.services.vault_service", **patches):
            from client.services.vault_service import init_vault, buka_vault_normal
            init_vault("u", "p")
            sesi = buka_vault_normal("p")
            sesi.tambah("X", "x@x.com", "px")
            sesi.simpan()
            sesi.tambah("Y", "y@y.com", "py")
            sesi.simpan()

        assert len(nonce_list) >= 2
        assert nonce_list[-1] != nonce_list[-2]