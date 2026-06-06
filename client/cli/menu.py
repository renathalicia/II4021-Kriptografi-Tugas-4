import getpass
import json
import os
import subprocess
import sys
import tempfile

from client.crypto.qr_recovery import recovery_share_to_qr
from client.crypto.visual_crypto import split_qr_visual
from client.services.vault_service import (
    init_vault, buka_vault_normal, buka_vault_backup,
    buat_password_acak, VaultSession
)
from client.storage import local_storage
from client.services.api_client import APIClient

_api = APIClient()

RECOVERY_SHARE_1_NAME = "recovery_visual_share_1.png"
RECOVERY_SHARE_2_NAME = "recovery_visual_share_2.png"


def tampilkan_menu_utama():
    while True:
        print("\n=== PASSWORD MANAGER (2-of-3 Shamir) ===")
        print("1. Setup Vault Baru")
        print("2. Buka Vault (Mode Normal)")
        print("3. Buka Vault (Mode Backup - tanpa server)")
        print("4. Keluar")

        pilihan = input("Pilih: ").strip()

        if pilihan == "1":
            _menu_setup()
        elif pilihan == "2":
            _menu_normal()
        elif pilihan == "3":
            _menu_backup()
        elif pilihan == "4":
            print("Sampai jumpa.")
            break
        else:
            print("[!] Pilihan tidak valid.")


def _menu_setup():
    if local_storage.sudah_ada():
        print("[!] Vault sudah ada di perangkat ini.")
        return

    print("\n--- Setup Vault Baru ---")
    username = input("Username: ").strip()
    if not username:
        print("[!] Username tidak boleh kosong.")
        return

    pw = getpass.getpass("Master password: ")
    pw2 = getpass.getpass("Konfirmasi password: ")
    if pw != pw2:
        print("[!] Password tidak cocok.")
        return

    print("[*] Membuat vault...")
    try:
        recovery_str = init_vault(username, pw)
    except Exception as e:
        print(f"[!] Gagal: {e}")
        return

    try:
        share1_path, share2_path = _buat_visual_recovery_qr_first(recovery_str)
    except Exception as e:
        print(f"[!] Gagal membuat visual recovery share: {e}")
        print("[!] Recovery key emergency fallback:")
        _cetak_recovery_key(recovery_str)
    else:
        print("[+] Visual recovery share dibuat:")
        print(f"    1. {share1_path}")
        print(f"    2. {share2_path}")
        print("    Simpan kedua file ini terpisah.")

    print("[+] Vault berhasil dibuat!")


def _menu_normal():
    if not local_storage.sudah_ada():
        print("[!] Vault belum ada. Lakukan setup dulu.")
        return

    if not _api.ping():
        print("[!] Server tidak bisa diakses.")
        coba = input("Coba mode backup? (y/n): ").strip().lower()
        if coba == "y":
            _menu_backup()
        return

    pw = getpass.getpass("Master password: ")
    try:
        sesi = buka_vault_normal(pw)
    except Exception as e:
        print(f"[!] {e}")
        return

    print("[+] Vault terbuka - MODE NORMAL")
    _sesi_interaktif(sesi)


def _menu_backup():
    if not local_storage.sudah_ada():
        print("[!] Vault belum ada. Lakukan setup dulu.")
        return

    pw = getpass.getpass("Master password: ")
    recovery = input("Recovery key: ").strip()

    try:
        sesi = buka_vault_backup(pw, recovery)
    except Exception as e:
        print(f"[!] {e}")
        return

    print("[+] Vault terbuka - MODE BACKUP (read-only)")
    _sesi_interaktif(sesi)


def _recovery_path(filename: str) -> str:
    return os.path.join(local_storage.DATA_DIR, filename)


def _open_image(path: str) -> None:
    if os.name == "nt":
        os.startfile(path)  # type: ignore[attr-defined]
        return

    opener = "open" if sys.platform == "darwin" else "xdg-open"
    subprocess.Popen(
        [opener, path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _cetak_recovery_key(recovery_str: str) -> None:
    print("=" * 55)
    print("RECOVERY KEY - SIMPAN SEKARANG, HANYA TAMPIL SEKALI")
    print("=" * 55)
    print(recovery_str)
    print("=" * 55)


def _tanya_tampilkan_recovery_key(recovery_str: str) -> None:
    pilihan = input("Tampilkan recovery key teks sebagai fallback? (y/N): ").strip().lower()
    if pilihan == "y":
        _cetak_recovery_key(recovery_str)


def _buat_visual_recovery_qr_first(recovery_str: str) -> tuple[str, str]:
    share = json.loads(recovery_str)
    os.makedirs(local_storage.DATA_DIR, exist_ok=True)
    share1_path = _recovery_path(RECOVERY_SHARE_1_NAME)
    share2_path = _recovery_path(RECOVERY_SHARE_2_NAME)

    with tempfile.TemporaryDirectory() as tmp_dir:
        qr_path = os.path.join(tmp_dir, "recovery_qr.png")
        recovery_share_to_qr(share, qr_path)

        print("[*] QR recovery dibuka. Scan QR untuk mendapatkan recovery key.")
        _open_image(qr_path)
        input("Tekan Enter setelah QR selesai discan...")
        _tanya_tampilkan_recovery_key(recovery_str)

        split_qr_visual(qr_path, share1_path, share2_path)

    return share1_path, share2_path


def _buat_visual_recovery(recovery_str: str) -> tuple[str, str]:
    share = json.loads(recovery_str)
    os.makedirs(local_storage.DATA_DIR, exist_ok=True)
    share1_path = _recovery_path(RECOVERY_SHARE_1_NAME)
    share2_path = _recovery_path(RECOVERY_SHARE_2_NAME)

    with tempfile.TemporaryDirectory() as tmp_dir:
        qr_path = os.path.join(tmp_dir, "recovery_qr.png")
        recovery_share_to_qr(share, qr_path)
        split_qr_visual(qr_path, share1_path, share2_path)

    return share1_path, share2_path


# ===== Loop interaktif vault =====

def _sesi_interaktif(sesi: VaultSession):
    mode = "BACKUP (read-only)" if sesi.readonly else "NORMAL"
    print(f"Mode: {mode} | ketik 'help' untuk perintah\n")

    while True:
        try:
            cmd = input("vault> ").strip()
        except (KeyboardInterrupt, EOFError):
            _handle_keluar(sesi)
            break

        if not cmd:
            continue

        parts = cmd.split(None, 1)
        perintah = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if perintah == "help":
            _cetak_bantuan(sesi.readonly)
        elif perintah == "list":
            _cmd_list(sesi)
        elif perintah == "show":
            _cmd_show(sesi, arg)
        elif perintah == "add":
            if sesi.readonly:
                print("  [!] Mode backup: tidak bisa tambah data.")
            else:
                _cmd_add(sesi)
        elif perintah == "edit":
            if sesi.readonly:
                print("  [!] Mode backup: tidak bisa edit.")
            else:
                _cmd_edit(sesi, arg)
        elif perintah == "delete":
            if sesi.readonly:
                print("  [!] Mode backup: tidak bisa hapus.")
            else:
                _cmd_delete(sesi, arg)
        elif perintah == "save":
            if sesi.readonly:
                print("  [!] Mode backup tidak menyimpan perubahan.")
            else:
                try:
                    sesi.simpan()
                except Exception as e:
                    print(f"  [!] {e}")
        elif perintah in ("exit", "quit", "q"):
            _handle_keluar(sesi)
            break
        else:
            print(f"  Perintah '{perintah}' tidak dikenal.")


def _handle_keluar(sesi: VaultSession):
    if not sesi.readonly and sesi.modified:
        jawab = input("Ada perubahan belum disimpan. Simpan? (y/n): ").lower()
        if jawab == "y":
            try:
                sesi.simpan()
            except Exception as e:
                print(f"[!] {e}")
    print("Vault ditutup.")


def _cetak_bantuan(readonly: bool):
    print("""
  list           -> tampilkan semua entri
  show <no>      -> detail entri + password
  add            -> tambah entri baru
  edit <no>      -> edit entri
  delete <no>    -> hapus entri
  save           -> enkripsi ulang dan simpan ke server
  exit           -> tutup vault
    """)
    if readonly:
        print("  [Mode backup aktif: hanya list dan show]\n")


def _cmd_list(sesi: VaultSession):
    entries = sesi.daftar()
    if not entries:
        print("  (vault kosong)")
        return
    print(f"\n  {'No':<4}  {'Layanan':<20}  Username")
    print("  " + "-" * 48)
    for i, e in enumerate(entries):
        print(f"  {i:<4}  {e.nama_layanan:<20}  {e.username}")
    print()


def _cmd_show(sesi: VaultSession, arg: str):
    try:
        idx = int(arg)
        e = sesi.entries[idx]
        print(f"""
  Layanan  : {e.nama_layanan}
  Username : {e.username}
  Password : {e.password}
  Catatan  : {e.catatan or '-'}
        """)
    except (ValueError, IndexError, AttributeError):
        print("  Usage: show <nomor>")


def _cmd_add(sesi: VaultSession):
    print("  --- Tambah Entri ---")
    nama = input("  Nama layanan: ").strip()
    usr = input("  Username/email: ").strip()

    pilihan = input("  Password: (1) Manual  (2) Generate otomatis [1]: ").strip() or "1"
    if pilihan == "2":
        try:
            panjang = int(input("  Panjang [16]: ").strip() or "16")
        except ValueError:
            panjang = 16
        pw = buat_password_acak(panjang)
        print(f"  Password dibangkitkan: {pw}")
    else:
        pw = getpass.getpass("  Password: ")

    catatan = input("  Catatan (opsional): ").strip()
    sesi.tambah(nama, usr, pw, catatan)
    print(f"  [+] '{nama}' ditambahkan. Jangan lupa 'save'.")


def _cmd_edit(sesi: VaultSession, arg: str):
    try:
        idx = int(arg)
        e = sesi.entries[idx]
    except (ValueError, IndexError):
        print("  Usage: edit <nomor>")
        return

    print(f"  --- Edit: {e.nama_layanan} (Enter = tidak diubah) ---")
    nama = input(f"  Nama layanan [{e.nama_layanan}]: ").strip()
    usr = input(f"  Username [{e.username}]: ").strip()

    pw = None
    if input("  Ganti password? (y/n): ").strip().lower() == "y":
        pilihan = input("  (1) Manual  (2) Generate [1]: ").strip() or "1"
        if pilihan == "2":
            try:
                panjang = int(input("  Panjang [16]: ").strip() or "16")
            except ValueError:
                panjang = 16
            pw = buat_password_acak(panjang)
            print(f"  Password baru: {pw}")
        else:
            pw = getpass.getpass("  Password baru: ")

    catatan = input(f"  Catatan [{e.catatan}]: ").strip()
    sesi.edit(idx, nama_layanan=nama or None, username=usr or None,
              password=pw, catatan=catatan or None)
    print("  [+] Diperbarui. Jangan lupa 'save'.")


def _cmd_delete(sesi: VaultSession, arg: str):
    try:
        idx = int(arg)
        e = sesi.entries[idx]
    except (ValueError, IndexError):
        print("  Usage: delete <nomor>")
        return

    if input(f"  Hapus '{e.nama_layanan}'? (y/n): ").strip().lower() == "y":
        sesi.hapus(idx)
        print("  [+] Dihapus. Jangan lupa 'save'.")
