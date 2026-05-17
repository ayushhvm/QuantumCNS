from config import configure_logging, get_logger, SECRET_KEY
configure_logging()

import json
from flask import Flask, request, jsonify, render_template, session
from flask_socketio import SocketIO, emit

from auth.users  import (
    init_db, register_user, verify_password,
    register_public_keys, get_public_keys, user_exists
)
from auth.tokens import generate_token, validate_token, revoke_token
from crypto.dilithium import DilithiumSigner

logger = get_logger(__name__)

app       = Flask(__name__)
app.secret_key = SECRET_KEY
socketio  = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── In-memory socket registry ─────────────────────────────────────────────────
# Maps username → socket_id. One active connection per user.
_user_sockets: dict[str, str] = {}
_socket_users: dict[str, str] = {}   # Reverse map: socket_id → username

signer = DilithiumSigner()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_username(token: str) -> str | None:
    return validate_token(token)

def _get_sid(username: str) -> str | None:
    return _user_sockets.get(username)

# ── HTTP Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/chat")
def chat():
    return render_template("chat.html")

@app.post("/api/register")
def api_register():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required"}), 400
    if len(username) > 32:
        return jsonify({"ok": False, "error": "Username too long"}), 400

    ok = register_user(username, password)
    if not ok:
        return jsonify({"ok": False, "error": "Username taken"}), 409
    return jsonify({"ok": True})

@app.post("/api/login")
def api_login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not verify_password(username, password):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    token = generate_token(username)
    return jsonify({"ok": True, "token": token, "username": username})

@app.post("/api/logout")
def api_logout():
    token = request.get_json().get("token", "")
    revoke_token(token)
    return jsonify({"ok": True})

@app.get("/api/keys/<username>")
def api_get_keys(username: str):
    """
    Return a user's registered public identity keys.
    Called by clients to fetch a peer's Dilithium public key for signature verification.
    """
    keys = get_public_keys(username)
    if not keys:
        return jsonify({"ok": False, "error": "User not found or keys not registered"}), 404
    return jsonify({"ok": True, **keys})

@app.get("/api/users/online")
def api_users_online():
    """
    Returns a list of currently online usernames.
    """
    return jsonify({"ok": True, "users": list(_user_sockets.keys())})

# ── Socket.IO Events ──────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    logger.info("Socket connected — sid=%s", request.sid)

@socketio.on("disconnect")
def on_disconnect():
    sid      = request.sid
    username = _socket_users.pop(sid, None)
    if username:
        _user_sockets.pop(username, None)
    logger.info("Socket disconnected — sid=%s, username=%s", sid, username)

@socketio.on("register_socket")
def on_register_socket(data):
    """
    Associate an authenticated token with this socket connection.
    Must be the first event after connecting.
    """
    token    = data.get("token", "")
    username = _get_username(token)
    if not username:
        emit("error", {"message": "Invalid or expired token"})
        return

    _user_sockets[username] = request.sid
    _socket_users[request.sid] = username
    logger.info("Socket registered — username=%s, sid=%s", username, request.sid)
    emit("registered", {"username": username})

@socketio.on("register_identity")
def on_register_identity(data):
    """
    Client sends their Dilithium3 and ECDH public keys after login.
    Server stores them for future handshake validation.
    """
    token    = data.get("token", "")
    username = _get_username(token)
    if not username:
        emit("error", {"message": "Unauthorized"})
        return

    try:
        dil_pubkey  = bytes.fromhex(data["dilithium_public_key"])
        ecdh_pubkey = bytes.fromhex(data.get("ecdh_public_key", ""))
    except (ValueError, KeyError) as e:
        emit("error", {"message": f"Invalid key format: {e}"})
        return

    register_public_keys(username, dil_pubkey, ecdh_pubkey)
    emit("identity_registered", {"status": "ok"})

@socketio.on("handshake_init")
def on_handshake_init(data):
    """
    Alice sends her signed ephemeral public keys to Bob.

    Server role:
    1. Authenticate Alice via token.
    2. Fetch Alice's registered Dilithium public key.
    3. Verify her signature over the key bundle.
    4. Forward the bundle to Bob — server does NOT touch key material.

    Payload expected:
        token, target_user, kyber_ephemeral_pubkey (hex),
        ecdhe_ephemeral_pubkey (hex), timestamp (str), signature (hex)
    """
    token    = data.get("token", "")
    sender   = _get_username(token)
    if not sender:
        emit("error", {"message": "Unauthorized"})
        return

    target = data.get("target_user", "")
    logger.info("handshake_init received — from=%s, target=%s", sender, target)

    sender_keys = get_public_keys(sender)
    if not sender_keys:
        emit("error", {"message": "Your identity keys are not registered"})
        return

    # Reconstruct signed payload: kyber_pub || ecdhe_pub || timestamp
    try:
        signed_payload = (
            bytes.fromhex(data["kyber_ephemeral_pubkey"]) +
            bytes.fromhex(data["ecdhe_ephemeral_pubkey"]) +
            data["timestamp"].encode()
        )
        signature      = bytes.fromhex(data["signature"])
        dil_pubkey     = bytes.fromhex(sender_keys["dilithium_public_key"])
    except (ValueError, KeyError) as e:
        emit("error", {"message": f"Malformed handshake payload: {e}"})
        return

    if not signer.verify(dil_pubkey, signed_payload, signature):
        logger.warning(
            "handshake_init: invalid Dilithium signature from %s", sender
        )
        emit("error", {"message": "Invalid handshake signature — possible MITM"})
        return

    target_sid = _get_sid(target)
    if not target_sid:
        logger.warning("handshake_init: target '%s' is offline", target)
        emit("error", {"message": f"{target} is offline"})
        return

    emit("handshake_request", {
        "from":                   sender,
        "kyber_ephemeral_pubkey": data["kyber_ephemeral_pubkey"],
        "ecdhe_ephemeral_pubkey": data["ecdhe_ephemeral_pubkey"],
        "timestamp":              data["timestamp"],
        "signature":              data["signature"],
    }, to=target_sid)

    logger.info("handshake_init forwarded — to=%s (sid=%s)", target, target_sid)

@socketio.on("handshake_response")
def on_handshake_response(data):
    """
    Bob sends his response bundle back to Alice.
    Server validates Bob's signature and forwards.

    Payload expected:
        token, target_user, kyber_ephemeral_pubkey (hex),
        ecdhe_ephemeral_pubkey (hex), kyber_ciphertext (hex),
        timestamp (str), signature (hex)
    """
    token  = data.get("token", "")
    sender = _get_username(token)
    if not sender:
        emit("error", {"message": "Unauthorized"})
        return

    target = data.get("target_user", "")
    logger.info("handshake_response received — from=%s, target=%s", sender, target)

    sender_keys = get_public_keys(sender)
    if not sender_keys:
        emit("error", {"message": "Your identity keys are not registered"})
        return

    try:
        signed_payload = (
            bytes.fromhex(data["kyber_ephemeral_pubkey"]) +
            bytes.fromhex(data["ecdhe_ephemeral_pubkey"]) +
            bytes.fromhex(data["kyber_ciphertext"]) +
            data["timestamp"].encode()
        )
        signature  = bytes.fromhex(data["signature"])
        dil_pubkey = bytes.fromhex(sender_keys["dilithium_public_key"])
    except (ValueError, KeyError) as e:
        emit("error", {"message": f"Malformed response payload: {e}"})
        return

    if not signer.verify(dil_pubkey, signed_payload, signature):
        logger.warning(
            "handshake_response: invalid Dilithium signature from %s", sender
        )
        emit("error", {"message": "Invalid response signature"})
        return

    target_sid = _get_sid(target)
    if not target_sid:
        emit("error", {"message": f"{target} is offline"})
        return

    emit("handshake_complete", {
        "from":                   sender,
        "kyber_ephemeral_pubkey": data["kyber_ephemeral_pubkey"],
        "ecdhe_ephemeral_pubkey": data["ecdhe_ephemeral_pubkey"],
        "kyber_ciphertext":       data["kyber_ciphertext"],
        "timestamp":              data["timestamp"],
        "signature":              data["signature"],
    }, to=target_sid)

    logger.info("handshake_response forwarded — to=%s", target)

@socketio.on("send_message")
def on_send_message(data):
    """
    Server receives an AES-256-GCM encrypted blob and forwards it.
    Server cannot decrypt this. It only sees: sender, recipient,
    nonce, ciphertext, tag, ratchet_step.

    Payload expected:
        token, target_user, nonce (hex), ciphertext (hex),
        tag (hex), ratchet_step (int)
    """
    token  = data.get("token", "")
    sender = _get_username(token)
    if not sender:
        emit("error", {"message": "Unauthorized"})
        return

    target = data.get("target_user", "")
    logger.info(
        "send_message: relaying encrypted blob — from=%s, to=%s", sender, target
    )

    target_sid = _get_sid(target)
    if not target_sid:
        logger.warning("send_message: target '%s' is offline", target)
        emit("error", {"message": f"{target} is offline"})
        return

    emit("receive_message", {
        "from":         sender,
        "nonce":        data.get("nonce", ""),
        "ciphertext":   data.get("ciphertext", ""),
        "tag":          data.get("tag", ""),
        "ratchet_step": data.get("ratchet_step", 0),
    }, to=target_sid)

# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    logger.info("PQChat v2.0 starting on http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
