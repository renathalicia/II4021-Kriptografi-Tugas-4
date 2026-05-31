import secrets

from PIL import Image, ImageChops


def _load_binary_image(path: str) -> Image.Image:
    if not isinstance(path, str) or not path:
        raise ValueError("image path must be a non-empty string")
    image = Image.open(path).convert("1")
    return image


def split_qr_visual(qr_path: str, share1_path: str, share2_path: str) -> None:
    qr = _load_binary_image(qr_path)
    width, height = qr.size
    row_bytes = (width + 7) // 8
    random_mask = secrets.token_bytes(row_bytes * height)
    share1 = Image.frombytes("1", qr.size, random_mask)
    share2 = ImageChops.logical_xor(share1, qr)

    share1.save(share1_path)
    share2.save(share2_path)


def merge_visual_shares(share1_path: str, share2_path: str, output_path: str) -> None:
    share1 = _load_binary_image(share1_path)
    share2 = _load_binary_image(share2_path)
    if share1.size != share2.size:
        raise ValueError("visual shares must have the same dimensions")

    merged = ImageChops.logical_xor(share1, share2)
    merged.save(output_path)
