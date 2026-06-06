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


class TestMenuSetupQrFirst:
    @pytest.fixture(autouse=True)
    def recovery(self):
        self.recovery = json.dumps({"x": 3, "y": _FAKE_Y}, sort_keys=True, separators=(",", ":"))

    def _run_menu_setup(self, monkeypatch, extra_inputs):
        from client.cli import menu

        inputs = iter(["user"] + list(extra_inputs))
        passwords = iter(["pw", "pw"])
        opened_paths = []

        def fake_open(path):
            opened_paths.append(path)
            assert os.path.exists(path)

        monkeypatch.setattr(menu, "init_vault", lambda username, password: self.recovery)
        monkeypatch.setattr(menu.getpass, "getpass", lambda prompt: next(passwords))
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        monkeypatch.setattr(menu, "_open_image", fake_open)

        menu._menu_setup()
        return menu, opened_paths

    def test_setup_qr_first_default_tidak_mencetak_recovery_key(self, monkeypatch, capsys):
        menu, opened_paths = self._run_menu_setup(monkeypatch, ["", ""])
        output = capsys.readouterr().out

        assert opened_paths
        assert not os.path.exists(opened_paths[0])
        assert self.recovery not in output
        assert os.path.exists(os.path.join(menu.local_storage.DATA_DIR, menu.RECOVERY_SHARE_1_NAME))
        assert os.path.exists(os.path.join(menu.local_storage.DATA_DIR, menu.RECOVERY_SHARE_2_NAME))

    def test_setup_qr_first_bisa_mencetak_recovery_key_fallback(self, monkeypatch, capsys):
        self._run_menu_setup(monkeypatch, ["", "y"])
        output = capsys.readouterr().out

        assert self.recovery in output

    def test_setup_visual_gagal_memaksa_recovery_key_tampil(self, monkeypatch, capsys):
        from client.cli import menu

        inputs = iter(["user"])
        passwords = iter(["pw", "pw"])

        monkeypatch.setattr(menu, "init_vault", lambda username, password: self.recovery)
        monkeypatch.setattr(menu.getpass, "getpass", lambda prompt: next(passwords))
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        monkeypatch.setattr(
            menu,
            "_buat_visual_recovery_qr_first",
            lambda recovery: (_ for _ in ()).throw(RuntimeError("display gagal")),
        )

        menu._menu_setup()
        output = capsys.readouterr().out

        assert "display gagal" in output
        assert self.recovery in output
        assert "Vault berhasil dibuat" in output


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

    def test_backup_session_menolak_operasi_write_langsung(self):
        with patch.multiple("client.services.vault_service", **_CRYPTO_MOCK):
            from client.services.vault_service import buka_vault_backup
            sesi = buka_vault_backup("pw", self.recovery)

        with pytest.raises(PermissionError, match="read-only"):
            sesi.tambah("GitHub", "dev@test.com", "pw")
        with pytest.raises(PermissionError, match="read-only"):
            sesi.edit(0, password="baru")
        with pytest.raises(PermissionError, match="read-only"):
            sesi.hapus(0)
        with pytest.raises(PermissionError, match="read-only"):
            sesi.simpan()

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

    def test_menu_backup_memakai_recovery_key_langsung(self, monkeypatch):
        from client.cli import menu

        calls = {}

        def fake_buka_vault_backup(password, recovery):
            calls["password"] = password
            calls["recovery"] = recovery
            return object()

        inputs = iter([self.recovery])
        monkeypatch.setattr(menu.getpass, "getpass", lambda prompt: "pw")
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        monkeypatch.setattr(menu, "buka_vault_backup", fake_buka_vault_backup)
        monkeypatch.setattr(menu, "_sesi_interaktif", lambda sesi: None)

        menu._menu_backup()

        assert calls == {"password": "pw", "recovery": self.recovery}


class TestXorShareScript:
    @pytest.fixture(autouse=True)
    def recovery(self):
        self.recovery = json.dumps({"x": 3, "y": _FAKE_Y}, sort_keys=True, separators=(",", ":"))

    def test_xorshare_membuka_qr_temp_tanpa_menyimpan_di_data(self, monkeypatch):
        from client.cli import menu
        import xorshare

        menu._buat_visual_recovery(self.recovery)
        opened_paths = []

        def fake_open(path):
            opened_paths.append(path)
            assert os.path.exists(path)

        monkeypatch.setattr(xorshare, "_open_image", fake_open)
        monkeypatch.setattr("builtins.input", lambda prompt="": "")
        monkeypatch.setattr(xorshare.sys, "argv", ["xorshare.py"])

        assert xorshare.main() == 0

        data_dir = os.path.abspath(menu.local_storage.DATA_DIR)
        opened_path = os.path.abspath(opened_paths[0])
        assert os.path.commonpath([data_dir, opened_path]) != data_dir
        assert not os.path.exists(opened_path)

    def test_xorshare_missing_share_exit_nonzero(self, monkeypatch, capsys):
        import xorshare

        monkeypatch.setattr(xorshare.sys, "argv", ["xorshare.py"])

        assert xorshare.main() == 1
        output = capsys.readouterr().out
        assert "tidak ditemukan" in output


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
