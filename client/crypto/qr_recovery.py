import json

import qrcode

from client.crypto.shamir import validate_share


def recovery_share_to_qr(share: dict, output_path: str) -> None:
    # Share divalidasi dulu agar QR hanya berisi format recovery yang sah.
    validate_share(share)
    if not isinstance(output_path, str) or not output_path:
        raise ValueError("output_path must be a non-empty string")

    # Serialisasi dibuat stabil supaya isi QR konsisten lintas proses.
    qr_data = json.dumps(share, sort_keys=True, separators=(",", ":"))
    image = qrcode.make(qr_data)
    image.save(output_path)
