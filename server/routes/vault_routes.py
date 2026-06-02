from flask import Blueprint, request, jsonify  # type: ignore[reportMissingImports]
from server.models import user_exists, create_user, create_vault, get_vault, update_vault

vault_bp = Blueprint('vault', __name__)

_VAULT_FIELDS = {"nonce", "ciphertext", "tag"}
_SHARE_FIELDS = {"x", "y"}

# field yang tidak boleh diterima server (zero-knowledge)
_FORBIDDEN_FIELDS = {"master_key", "local_share", "recovery_share", "plaintext_vault"}

def _valid_vault_payload(p) -> bool:
    return isinstance(p, dict) and _VAULT_FIELDS.issubset(p)

def _valid_share(s) -> bool:
    return isinstance(s, dict) and _SHARE_FIELDS.issubset(s)

def _has_forbidden(data: dict) -> bool:
    return bool(_FORBIDDEN_FIELDS & data.keys())

@vault_bp.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok"}), 200

@vault_bp.route("/vault/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "request body must be JSON"}), 400
    
    # tolak jika ada field yang tidak boleh dikirim
    if _has_forbidden(data):
        return jsonify({"error": "request contains forbidden fields"}), 400
    
    username = data.get("username")
    enc_vault_payload = data.get("enc_vault_payload")
    server_share = data.get("server_share")

    if not username or not isinstance(username, str):
        return jsonify({"error": "username is required"}), 400
    if not _valid_vault_payload(enc_vault_payload):
        return jsonify({"error": "enc_vault_payload must contain nonce, ciphertext, and tag"}), 400
    if not _valid_share(server_share):
        return jsonify({"error": "server_share must contain x and y"}), 400
    
    if user_exists(username):
        return jsonify({"error": "username already registered"}), 409
    
    # enc_local_payload diterima tapi tidak disimpan (zero-knowledge)
    user_id = create_user(username)
    create_vault(user_id, enc_vault_payload, server_share)
    return jsonify({"status": "created"}), 201
    
@vault_bp.route("/vault/fetch/<username>", methods=["GET"])
def fetch_vault(username: str):
    result = get_vault(username)
    if result is None:
        return jsonify({"error": "vault not found"}), 404
    return jsonify(result), 200

@vault_bp.route("/vault/update", methods=["POST"])
def update():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "request body must be JSON"}), 400
    
    if _has_forbidden(data):
        return jsonify({"error": "request contains forbidden fields"}), 400
    
    username = data.get("username")
    enc_vault_payload = data.get("enc_vault_payload")

    if not username or not isinstance(username, str):
        return jsonify({"error": "username is required"}), 400
    if not _valid_vault_payload(enc_vault_payload):
        return jsonify({"error": "enc_vault_payload must contain nonce, ciphertext, and tag"}), 400
    
    if not update_vault(username, enc_vault_payload):
        return jsonify({"error": "vault not found"}), 404
    
    return jsonify({"status": "updated"}), 200