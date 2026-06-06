import os
import subprocess
import sys
import tempfile

from client.crypto.visual_crypto import merge_visual_shares
from client.storage import local_storage

RECOVERY_SHARE_1_NAME = "recovery_visual_share_1.png"
RECOVERY_SHARE_2_NAME = "recovery_visual_share_2.png"


def _share_path(filename: str) -> str:
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


def _require_share_files(share1_path: str, share2_path: str) -> None:
    missing = [path for path in (share1_path, share2_path) if not os.path.exists(path)]
    if missing:
        raise FileNotFoundError("Visual recovery share tidak ditemukan: " + ", ".join(missing))


def buka_qr_recovery_utuh() -> None:
    share1_path = _share_path(RECOVERY_SHARE_1_NAME)
    share2_path = _share_path(RECOVERY_SHARE_2_NAME)
    _require_share_files(share1_path, share2_path)

    with tempfile.TemporaryDirectory() as tmp_dir:
        qr_path = os.path.join(tmp_dir, "recovery_qr.png")
        merge_visual_shares(share1_path, share2_path, qr_path)
        print("[*] QR recovery dibuka. Scan QR untuk mendapatkan recovery key.")
        _open_image(qr_path)
        input("Tekan Enter setelah QR selesai discan...")


def main() -> int:
    if len(sys.argv) > 1:
        print("[!] xorshare.py tidak menerima argumen. Jalankan: python xorshare.py")
        return 2

    try:
        buka_qr_recovery_utuh()
    except Exception as e:
        print(f"[!] Gagal membuka QR recovery: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
