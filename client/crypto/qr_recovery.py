import json

import cv2
import qrcode

from client.crypto.shamir import serialize_share, validate_share


def recovery_share_to_qr(share: dict, output_path: str) -> None:
    # Share divalidasi dulu agar QR hanya berisi format recovery yang sah.
    validate_share(share)
    if not isinstance(output_path, str) or not output_path:
        raise ValueError("output_path must be a non-empty string")

    # Serialisasi dibuat stabil supaya isi QR konsisten lintas proses.
    qr_data = json.dumps(share, sort_keys=True, separators=(",", ":"))
    image = qrcode.make(qr_data)
    image.save(output_path)


def recovery_share_from_qr(qr_path: str) -> str:
    if not isinstance(qr_path, str) or not qr_path:
        raise ValueError("qr_path must be a non-empty string")

    image = cv2.imread(qr_path)
    if image is None:
        raise ValueError("QR recovery image tidak bisa dibaca.")

    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(image)
    if not data:
        raise ValueError("QR recovery tidak terdeteksi atau kosong.")

    try:
        share = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError("Isi QR recovery bukan JSON yang valid.") from exc

    validate_share(share)
    return serialize_share(share)
