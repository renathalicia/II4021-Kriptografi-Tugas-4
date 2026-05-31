import base64
import json

import pytest
from PIL import Image, ImageChops

from client.crypto.aes_gcm import decrypt_vault, encrypt_vault
from client.crypto.kdf import derive_key, generate_salt
from client.crypto.password_generator import PASSWORD_ALPHABET, generate_password
from client.crypto.qr_recovery import recovery_share_to_qr
from client.crypto.shamir import (
    decrypt_local_share,
    encrypt_local_share,
    generate_master_key,
    reconstruct_master_key,
    split_master_key,
)
from client.crypto.visual_crypto import merge_visual_shares, split_qr_visual


def test_generate_master_key_returns_random_16_byte_values():
    first = generate_master_key()
    second = generate_master_key()

    assert isinstance(first, bytes)
    assert len(first) == 16
    assert len(second) == 16
    assert first != second


@pytest.mark.parametrize("indexes", [(0, 1), (0, 2), (1, 2)])
def test_shamir_reconstructs_master_key_from_any_two_valid_shares(indexes):
    master_key = generate_master_key()
    shares = split_master_key(master_key)

    selected = [shares[indexes[0]], shares[indexes[1]]]

    assert len(shares) == 3
    assert {share["x"] for share in shares} == {1, 2, 3}
    assert reconstruct_master_key(selected) == master_key


def test_shamir_rejects_corrupted_share():
    master_key = generate_master_key()
    shares = split_master_key(master_key)
    corrupted = dict(shares[0])
    corrupted["y"] = base64.b64encode(b"short").decode("ascii")

    with pytest.raises(ValueError):
        reconstruct_master_key([corrupted, shares[1]])


def test_shamir_rejects_invalid_x_and_invalid_base64():
    master_key = generate_master_key()
    shares = split_master_key(master_key)
    invalid_x = dict(shares[0])
    invalid_x["x"] = 4
    invalid_base64 = dict(shares[0])
    invalid_base64["y"] = "not base64"

    with pytest.raises(ValueError):
        reconstruct_master_key([invalid_x, shares[1]])
    with pytest.raises(ValueError):
        reconstruct_master_key([invalid_base64, shares[1]])


def test_shamir_rejects_duplicate_share_x_values():
    master_key = generate_master_key()
    shares = split_master_key(master_key)
    duplicate = dict(shares[0])

    with pytest.raises(ValueError):
        reconstruct_master_key([shares[0], duplicate])


def test_shamir_share_contract_remains_json_base64():
    shares = split_master_key(generate_master_key())

    for share in shares:
        assert set(share) == {"x", "y"}
        assert isinstance(share["x"], int)
        assert isinstance(share["y"], str)
        assert len(base64.b64decode(share["y"], validate=True)) == 16


def test_aes_gcm_encrypts_decrypts_and_uses_new_nonce_each_time():
    key = generate_master_key()
    plaintext = json.dumps({"entries": []})

    first = encrypt_vault(plaintext, key)
    second = encrypt_vault(plaintext, key)

    assert set(first) == {"nonce", "ciphertext", "tag"}
    assert first["nonce"] != second["nonce"]
    assert decrypt_vault(first, key) == plaintext


def test_aes_gcm_rejects_wrong_key_or_corrupted_payload():
    key = generate_master_key()
    other_key = generate_master_key()
    payload = encrypt_vault('{"entries":[]}', key)

    with pytest.raises(ValueError):
        decrypt_vault(payload, other_key)

    corrupted = dict(payload)
    corrupted["ciphertext"] = base64.b64encode(b"tampered").decode("ascii")
    with pytest.raises(ValueError):
        decrypt_vault(corrupted, key)


def test_tampered_16_byte_share_does_not_open_encrypted_vault():
    master_key = generate_master_key()
    vault = encrypt_vault('{"entries":[]}', master_key)
    shares = split_master_key(master_key)
    tampered_share_bytes = bytearray(base64.b64decode(shares[0]["y"], validate=True))
    tampered_share_bytes[0] ^= 0x01
    tampered_share = dict(shares[0])
    tampered_share["y"] = base64.b64encode(bytes(tampered_share_bytes)).decode("ascii")

    reconstructed = reconstruct_master_key([tampered_share, shares[1]])

    assert reconstructed != master_key
    with pytest.raises(ValueError):
        decrypt_vault(vault, reconstructed)


def test_pbkdf2_same_password_and_salt_are_stable_but_new_salt_changes_key():
    salt = generate_salt()
    other_salt = generate_salt()

    key1 = derive_key("correct horse battery staple", salt)
    key2 = derive_key("correct horse battery staple", salt)
    key3 = derive_key("correct horse battery staple", other_salt)

    assert len(key1) == 16
    assert key1 == key2
    assert key1 != key3


def test_local_share_encryption_opens_with_correct_password_only():
    share = split_master_key(generate_master_key())[0]
    salt = generate_salt()
    correct_key = derive_key("master-password", salt)
    wrong_key = derive_key("wrong-password", salt)
    encrypted = encrypt_local_share(share, correct_key)

    assert decrypt_local_share(encrypted, correct_key) == share
    with pytest.raises(ValueError):
        decrypt_local_share(encrypted, wrong_key)


def test_password_generator_returns_requested_length_from_fixed_alphabet():
    password = generate_password(32)

    assert len(password) == 32
    assert set(password).issubset(set(PASSWORD_ALPHABET))


def test_recovery_share_to_qr_creates_png(tmp_path):
    share = split_master_key(generate_master_key())[2]
    qr_path = tmp_path / "recovery.png"

    recovery_share_to_qr(share, str(qr_path))

    assert qr_path.exists()
    with Image.open(qr_path) as image:
        assert image.format == "PNG"
        assert image.size[0] > 0
        assert image.size[1] > 0


def test_visual_crypto_splits_and_merges_qr_back_to_original(tmp_path):
    share = split_master_key(generate_master_key())[2]
    qr_path = tmp_path / "recovery.png"
    share1_path = tmp_path / "visual_share_1.png"
    share2_path = tmp_path / "visual_share_2.png"
    merged_path = tmp_path / "merged.png"
    recovery_share_to_qr(share, str(qr_path))

    split_qr_visual(str(qr_path), str(share1_path), str(share2_path))
    merge_visual_shares(str(share1_path), str(share2_path), str(merged_path))

    assert share1_path.exists()
    assert share2_path.exists()
    assert merged_path.exists()

    with Image.open(qr_path).convert("1") as original:
        with Image.open(merged_path).convert("1") as merged:
            difference = ImageChops.difference(original, merged)
            assert difference.getbbox() is None
