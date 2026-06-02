import base64
import json
import pytest
import server.config as config
from server.app import create_app

# fixtures untuk setup app dan test client
@pytest.fixture
def app(tmp_path, monkeypatch):
    # pakai db sementara agar tes tidak mengganggu data asli
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "test.db"))
    app = create_app()
    app.config["TESTING"] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

# helper data
def _b64(n: int) -> str:
    """Base64 dari n bytes nol - cukup untuk struktur yang valid"""
    return base64.b64encode(b"\x00" * n).decode()

def _sample_vault_payload():
    return {
        "nonce": _b64(12), # nonce AES-GCM 12 bytes
        "ciphertext": _b64(32), # isi ciphertext dummy
        "tag": _b64(16) # tag AES-GCM 16 bytes
    }

def _sample_server_share():
    return {
        "x": 2,
        "y": _b64(16)
    }

def _register(client, username="alicia"):
    return client.post("/vault/register", json={
        "username": username,
        "enc_vault_payload": _sample_vault_payload(),
        "server_share": _sample_server_share()
    })

# test ping
def test_ping(client):
    r = client.get("/ping")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}

# test register
def test_register_sukses(client):
    r = _register(client)
    assert r.status_code == 201
    assert r.get_json() == {"status": "created"}

def test_register_duplikat(client):
    _register(client)
    r = _register(client) # coba daftar lagi dengan username sama
    assert r.status_code == 409

def test_register_tanpa_username(client):
    r = client.post("/vault/register", json={
        "enc_vault_payload": _sample_vault_payload(),
        "server_share": _sample_server_share()
    })
    assert r.status_code == 400

def test_register_vault_payload_tidak_lengkap(client):
    r = client.post("/vault/register", json={
        "username": "bobsam",
        "enc_vault_payload": {"nonce": _b64(12)}, # hanya nonce, tanpa ciphertext dan tag
        "server_share": _sample_server_share()
    })
    assert r.status_code == 400

def test_register_server_share_tidak_lengkap(client):
    r = client.post("/vault/register", json={
        "username": "bobsam",
        "enc_vault_payload": _sample_vault_payload(),
        "server_share": {"x": 2} # hanya x, tanpa y
    })
    assert r.status_code == 400
    
# test fetch
def test_fetch_sukses(client):
    _register(client, "alicia")
    r = client.get("/vault/fetch/alicia")
    assert r.status_code == 200
    data = r.get_json()
    assert "server_share" in data
    assert "enc_vault_payload" in data
    # enc_vault_payload harus punya nonce, ciphertext, tag
    assert {"nonce", "ciphertext", "tag"} <= data["enc_vault_payload"].keys()

def test_fetch_user_tidak_ada(client):
    r = client.get("/vault/fetch/tidakada")
    assert r.status_code == 404

def test_fetch_kembalikan_server_share_benar(client):
    share = _sample_server_share()
    client.post("/vault/register", json={
        "username": "carlen",
        "enc_vault_payload": _sample_vault_payload(),
        "server_share": share
    })
    data = client.get("/vault/fetch/carlen").get_json()
    assert data["server_share"]["x"] == share["x"]
    assert data["server_share"]["y"] == share["y"]

# test update
def test_update_sukses(client):
    _register(client, "dudi")
    vault_baru = _sample_vault_payload()
    vault_baru["nonce"] = _b64(12) # nonce beda simulasi reenkripsi
    r = client.post("/vault/update", json={
        "username": "dudi",
        "enc_vault_payload": vault_baru
    })
    assert r.status_code == 200

def test_update_user_tidak_ada(client):
    r = client.post("/vault/update", json={
        "username": "tidakada",
        "enc_vault_payload": _sample_vault_payload()
    })
    assert r.status_code == 404

def test_update_nonce_berubah(cleint):
    """Setelah update, vault yang di fetch harus punya nonce baru"""
    _register(client, "endah")
    nonce_baru = base64.b64encode(b"\xff" * 12).decode() # nonce berbeda
    vault_baru = {
        "nonce": nonce_baru,
        "ciphertext": _b64(32),
        "tag": _b64(16)
    }
    client.put("/vault/update", json={
        "username": "endah",
        "enc_vault_payload": vault_baru
    })
    data = client.get("/vault/fetch/endah").get_json()
    assert data["enc_vault_payload"]["nonce"] == nonce_baru

# test zero-knowledge
def test_server_tidak_menerima_master_key(client):
    r = client.post("/vault/register", json={
        "username": "hacker",
        "master_key": "seharusnya_ditolak",
        "enc_vault_payload": _sample_vault_payload(),
        "server_share": _sample_server_share(),
    })
    assert r.status_code == 400

def test_server_tidak_menyimpan_local_share(client):
    """
    enc_local_payload dikirim client tapi server tidak menyimpannya. 
    Server share tetap bisa diambil tanpa ada local share di response.
    """
    client.post("/vault/register", json={
        "username": "franco",
        "enc_local_payload": {"nonce": _b64(12), "ciphertext": _b64(32), "tag": _b64(16)}, 
        "enc_vault_payload": _sample_vault_payload(),
        "server_share": _sample_server_share(),
    })
    data = client.get("/vault/fetch/franco").get_json()
    # response gaboleh ada local share
    assert "enc_local_payload" not in data
    assert "local_share" not in data

def test_server_tidak_menyimpan_plaintext_vault(client):
    """
    Vault di database harus berupa BLOB, bukan teks plaintext.
    """
    import sqlite3
    import server.config as config

    _register(client, "gopang")
    conn = sqlite3.connect(config.DATABASE_PATH)
    row = conn.execute("SELECT encrypted_vault FROM vaults").fetchone()
    conn.close()

    # encrypted_vault harus bytes (BLOB), bukan string json atau plaintext
    assert isinstance(row[0], bytes)