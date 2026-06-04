import base64
import binascii

from flask import Blueprint, request, jsonify  # type: ignore[reportMissingImports]
from server.models import user_exists, create_user, create_vault, get_vault, update_vault

vault_bp = Blueprint('vault', __name__)

_VAULT_FIELDS = {"nonce", "ciphertext", "tag"}
_SHARE_FIELDS = {"x", "y"}
_REGISTER_FIELDS = {"username", "enc_vault_payload", "server_share"}
_UPDATE_FIELDS = {"username", "enc_vault_payload"}

# field yang tidak boleh diterima server (zero-knowledge)
_FORBIDDEN_FIELDS = {
    "master_key",
    "local_share",
    "recovery_share",
    "plaintext_vault",
    "vault_plaintext",
    "master_password",
    "password",
    "derived_key",
    "kdf_key",
    "enc_local_payload",
}

def _decode_b64(value: str) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        return None

def _valid_vault_payload(p) -> bool:
    if not isinstance(p, dict) or set(p.keys()) != _VAULT_FIELDS:
        return False

    nonce = _decode_b64(p["nonce"])
    ciphertext = _decode_b64(p["ciphertext"])
    tag = _decode_b64(p["tag"])
    return (
        nonce is not None and len(nonce) == 12
        and ciphertext is not None and len(ciphertext) > 0
        and tag is not None and len(tag) == 16
    )

def _valid_share(s) -> bool:
    if not isinstance(s, dict) or set(s.keys()) != _SHARE_FIELDS:
        return False

    share_y = _decode_b64(s["y"])
    return s["x"] == 2 and share_y is not None and len(share_y) == 16

def _has_forbidden(data: dict) -> bool:
    return bool(_FORBIDDEN_FIELDS & data.keys())

def _valid_request_fields(data: dict, allowed_fields: set[str]) -> bool:
    return not _has_forbidden(data) and set(data.keys()).issubset(allowed_fields)

@vault_bp.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok"}), 200

@vault_bp.route("/vault/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "request body must be JSON"}), 400
    
    # Tolak field sensitif dan field di luar kontrak endpoint.
    if not _valid_request_fields(data, _REGISTER_FIELDS):
        return jsonify({"error": "request contains forbidden or unknown fields"}), 400
    
    username = data.get("username")
    enc_vault_payload = data.get("enc_vault_payload")
    server_share = data.get("server_share")

    if not username or not isinstance(username, str):
        return jsonify({"error": "username is required"}), 400
    if not _valid_vault_payload(enc_vault_payload):
        return jsonify({"error": "enc_vault_payload must contain valid nonce, ciphertext, and tag"}), 400
    if not _valid_share(server_share):
        return jsonify({"error": "server_share must contain valid x and y"}), 400
    
    if user_exists(username):
        return jsonify({"error": "username already registered"}), 409
    
    user_id = create_user(username)
    create_vault(user_id, enc_vault_payload, server_share)
    return jsonify({"status": "created"}), 201
    
@vault_bp.route("/vault/fetch/<username>", methods=["GET"])
def fetch_vault(username: str):
    result = get_vault(username)
    if result is None:
        return jsonify({"error": "vault not found"}), 404
    return jsonify(result), 200

@vault_bp.route("/vault/update", methods=["POST", "PUT"])
def update():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "request body must be JSON"}), 400
    
    if not _valid_request_fields(data, _UPDATE_FIELDS):
        return jsonify({"error": "request contains forbidden or unknown fields"}), 400
    
    username = data.get("username")
    enc_vault_payload = data.get("enc_vault_payload")

    if not username or not isinstance(username, str):
        return jsonify({"error": "username is required"}), 400
    if not _valid_vault_payload(enc_vault_payload):
        return jsonify({"error": "enc_vault_payload must contain valid nonce, ciphertext, and tag"}), 400
    
    if not update_vault(username, enc_vault_payload):
        return jsonify({"error": "vault not found"}), 404
    
    return jsonify({"status": "updated"}), 200
