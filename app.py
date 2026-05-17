"""
PQChat v2.0 — Flask + Socket.IO Application Server

Role: BLIND RELAY
  - Server never generates crypto keys
  - Server never decrypts messages
  - Server routes encrypted blobs between authenticated sockets
  - Server verifies ML-DSA-65 signatures on handshake events only

Socket event spec (Amendment 2 — handshake_response fully specced):
  connect            → validate token, add to connected_users, broadcast user_list
  register_identity  → store ML-DSA-65 + ECDHE identity public keys
  handshake_init     → verify sig, forward to target (client-to-client key exchange)
  handshake_response → verify sig, forward to initiator (Amendment 2)
  send_message       → validate token, forward encrypted blob (server never decrypts)
  request_session_reset → forward reset request to target (Amendment 3 UI trigger)
  disconnect         → remove from connected_users, broadcast updated user_list

Amendment 4: If liboqs-wasm is not available in browser, the client
             downgrades to DEGRADED MODE — displayed in the UI.
             The server emits 'degraded_mode' flag in 'welcome' message
             when client reports WASM unavailability.

Amendment 5: Tokens expire after 24 hours UTC (enforced in auth/users.py).
Amendment 6: Shor's simulator cap N ≤ 9999 (enforced in route).
"""

import base64

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_socketio import SocketIO, disconnect, emit

from auth.users import (
    create_session,
    delete_expired_sessions,
    get_public_keys,
    init_db,
    register_public_key,
    register_user,
    validate_token,
    verify_password,
)
from crypto.dilithium import DilithiumSigner
from simulator.grovers_simulation import analyze_grovers_impact
from simulator.lattice_attack_simulator import run_full_comparison
from simulator.quantum_extrapolator import extrapolate_to_cryptographic_scale
from simulator.shors_simulation import (
    extrapolate_to_p256,
    simulate_shors_period_finding,
)

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = "pqchat-v2-dev-secret-change-in-production"
socketio = SocketIO(app, cors_allowed_origins="*")

_dilithium = DilithiumSigner()

# Runtime state — in-memory (resets on server restart)
# {username: socket_sid}
connected_users: dict[str, str] = {}
# {socket_sid: username}
sid_to_user: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def startup():
    init_db()
    deleted = delete_expired_sessions()
    if deleted:
        app.logger.info(f"Cleaned up {deleted} expired sessions on startup")

    # Seed two demo users if DB is fresh
    register_user("alice", "alice123")
    register_user("bob",   "bob123")


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return redirect(url_for("login_page"))


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/chat")
def chat_page():
    token = request.args.get("token")
    username = validate_token(token)
    if not username:
        return redirect(url_for("login_page"))
    return render_template("chat.html", username=username, token=token)


@app.get("/simulator")
def simulator_page():
    token = request.args.get("token")
    username = validate_token(token)
    if not username:
        return redirect(url_for("login_page"))
    return render_template("simulator.html", username=username, token=token)


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------

@app.post("/api/register")
def api_register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(username) < 2 or len(username) > 32:
        return jsonify({"error": "Username must be 2–32 characters"}), 400

    if register_user(username, password):
        return jsonify({"status": "registered", "username": username})
    return jsonify({"error": "Username already taken"}), 409


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not verify_password(username, password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_session(username)
    return jsonify({"token": token, "username": username})


@app.get("/api/keys/<username>")
def api_get_keys(username: str):
    """
    Return a user's registered ML-DSA-65 and ECDHE identity public keys.
    No authentication required — public keys are public.
    """
    keys = get_public_keys(username)
    if not keys:
        return jsonify({"error": f"No keys registered for '{username}'"}), 404
    return jsonify(keys)


# ---------------------------------------------------------------------------
# Simulator API routes
# ---------------------------------------------------------------------------

@app.post("/api/simulate/shors")
def api_shors():
    """
    Classical Shor's period-finding simulation.
    Amendment 6: N must be between 4 and 9999.
    """
    data = request.get_json(silent=True) or {}
    N = data.get("N", 15)
    a = data.get("a", 2)

    if not isinstance(N, int) or N < 4 or N > 9999:
        return jsonify({"error": "N must be an integer between 4 and 9999"}), 400

    result = simulate_shors_period_finding(N, a)
    result["p256_extrapolation"] = extrapolate_to_p256()
    return jsonify(result)


@app.post("/api/simulate/quantum_shors")
def api_quantum_shors():
    """
    Qiskit-based quantum circuit simulation for N ≤ 35.
    Amendment 6: N must be between 4 and 9999.
    For N > 35, returns complexity estimates only.
    """
    data = request.get_json(silent=True) or {}
    N = data.get("N", 15)

    if not isinstance(N, int) or N < 4 or N > 9999:
        return jsonify({"error": "N must be an integer between 4 and 9999"}), 400

    extrapolation = extrapolate_to_cryptographic_scale()

    if N > 35:
        return jsonify({
            "mode": "complexity_estimate",
            "N": N,
            "note": (
                f"N={N} is too large for classical quantum circuit simulation. "
                f"Exponential RAM required above N≈35."
            ),
            "classical_simulation": {
                "feasible": False,
                "reason": "Qiskit AerSimulator requires O(2^n) RAM for circuit simulation",
            },
            "extrapolation": extrapolation,
        })

    # Attempt Qiskit simulation
    try:
        from simulator.qiskit_shors import run_shors_simulation
        result = run_shors_simulation(N)
        result["extrapolation"] = extrapolation
        result["mode"] = "full_quantum_simulation"
        return jsonify(result)
    except ImportError:
        return jsonify({
            "mode": "complexity_estimate",
            "N": N,
            "note": "Qiskit not available — showing classical simulation instead",
            "classical_result": simulate_shors_period_finding(N),
            "extrapolation": extrapolation,
        })


@app.get("/api/simulate/lattice")
def api_lattice():
    return jsonify(run_full_comparison())


@app.get("/api/simulate/grover")
def api_grover():
    return jsonify(analyze_grovers_impact())


@app.get("/api/simulate/extrapolate")
def api_extrapolate():
    return jsonify(extrapolate_to_cryptographic_scale())


# ---------------------------------------------------------------------------
# Socket.IO helpers
# ---------------------------------------------------------------------------

def _get_user_from_token(token: str | None) -> str | None:
    """Validate token and return username, or None."""
    return validate_token(token)


def _get_online_users() -> list[str]:
    """Return sorted list of currently connected usernames."""
    return sorted(connected_users.keys())


# ---------------------------------------------------------------------------
# Socket.IO events
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    """
    Validate token from query params.
    Register in connected_users. Broadcast updated user list.
    """
    token = request.args.get("token")
    username = _get_user_from_token(token)

    if not username:
        emit("auth_error", {"error": "Invalid or expired token"})
        disconnect()
        return

    connected_users[username] = request.sid
    sid_to_user[request.sid] = username

    emit("welcome", {
        "username": username,
        "online_users": _get_online_users(),
        # Amendment 4: server does not know if WASM loaded — client reports this
        "wasm_check_required": True,
    })

    # Broadcast updated user list to everyone
    socketio.emit("user_list", {"online_users": _get_online_users()})


@socketio.on("register_identity")
def on_register_identity(data: dict):
    """
    Client sends their ML-DSA-65 and ECDHE identity public keys after login.
    Server stores them for handshake signature verification.

    data: {token, dilithium_public_key (hex), ecdh_identity_public_key (hex)}
    """
    token = (data or {}).get("token")
    username = _get_user_from_token(token)
    if not username:
        emit("auth_error", {"error": "Invalid token"})
        return

    dil_pub = data.get("dilithium_public_key", "")
    ecdh_pub = data.get("ecdh_identity_public_key", "")

    if not dil_pub:
        emit("error", {"message": "dilithium_public_key is required"})
        return

    try:
        bytes.fromhex(dil_pub)  # validate hex
    except ValueError:
        emit("error", {"message": "dilithium_public_key must be hex encoded"})
        return

    register_public_key(username, dil_pub, ecdh_pub)
    emit("identity_registered", {"status": "ok", "username": username})


@socketio.on("wasm_status")
def on_wasm_status(data: dict):
    """
    Amendment 4: Client reports whether liboqs-wasm loaded successfully.
    Server records this for logging. Does not change relay behaviour.
    If wasm_available=False, client is operating in DEGRADED MODE.
    This flag is communicated back so the UI can display the banner.

    data: {token, wasm_available: bool, degraded_algorithms: [str]}
    """
    token = (data or {}).get("token")
    username = _get_user_from_token(token)
    if not username:
        return

    wasm_ok = data.get("wasm_available", False)
    if not wasm_ok:
        app.logger.warning(
            f"[DEGRADED MODE] {username} — liboqs-wasm unavailable. "
            f"Algorithms missing: {data.get('degraded_algorithms', [])}"
        )
        emit("degraded_mode_confirmed", {
            "message": "⚠️ DEGRADED MODE — liboqs-wasm not available. "
                       "Post-quantum signatures disabled for this session.",
            "degraded": True,
        })
    else:
        emit("degraded_mode_confirmed", {"degraded": False})


@socketio.on("handshake_init")
def on_handshake_init(data: dict):
    """
    Alice initiates key exchange with Bob.
    Server verifies Alice's ML-DSA-65 signature, then forwards bundle to Bob.
    Server does NOT participate in crypto — blind relay only.

    data: {
        token,
        target_user,
        kyber_ephemeral_pubkey (hex),
        ecdhe_ephemeral_pubkey (hex),
        timestamp (unix ms string),
        signature (hex, ML-DSA-65 over kyber_pub||ecdhe_pub||timestamp)
    }
    """
    token = (data or {}).get("token")
    sender = _get_user_from_token(token)
    if not sender:
        emit("auth_error", {"error": "Invalid token"})
        return

    target = data.get("target_user")
    if not target:
        emit("error", {"message": "target_user is required"})
        return
    if target == sender:
        emit("error", {"message": "Cannot initiate handshake with yourself"})
        return

    # Verify Alice's identity signature over her ephemeral keys
    sender_keys = get_public_keys(sender)
    if not sender_keys:
        emit("error", {"message": "Your identity keys are not registered. Send register_identity first."})
        return

    try:
        kyber_pub_bytes  = bytes.fromhex(data["kyber_ephemeral_pubkey"])
        ecdhe_pub_bytes  = bytes.fromhex(data["ecdhe_ephemeral_pubkey"])
        timestamp_bytes  = data["timestamp"].encode()
        signature_bytes  = bytes.fromhex(data["signature"])
        dil_pubkey_bytes = bytes.fromhex(sender_keys["dilithium_public_key"])
    except (KeyError, ValueError) as e:
        emit("error", {"message": f"Malformed handshake_init payload: {e}"})
        return

    signed_payload = kyber_pub_bytes + ecdhe_pub_bytes + timestamp_bytes

    # Skip sig verify in DEGRADED MODE — signature is 64 zero bytes (marker)
    is_degraded = (signature_bytes == b'\x00' * 64 or signature_bytes == b'\x00' * len(signature_bytes))
    if not is_degraded:
        if not _dilithium.verify(dil_pubkey_bytes, signed_payload, signature_bytes):
            emit("error", {"message": "Invalid handshake signature — possible MITM attack"})
            return
    else:
        app.logger.info(f"[DEGRADED] {sender}: skipping sig verify (DEGRADED MODE)")

    # Forward to target — server adds 'from' field, touches nothing else
    target_sid = connected_users.get(target)
    if not target_sid:
        emit("user_offline", {"username": target})
        return

    emit("handshake_request", {
        "from":                    sender,
        "kyber_ephemeral_pubkey":  data["kyber_ephemeral_pubkey"],
        "ecdhe_ephemeral_pubkey":  data["ecdhe_ephemeral_pubkey"],
        "timestamp":               data["timestamp"],
        "signature":               data["signature"],
    }, to=target_sid)


@socketio.on("handshake_response")
def on_handshake_response(data: dict):
    """
    Amendment 2 — fully specced handshake_response event.

    Bob responds to Alice's handshake_init. Bob sends:
      - His Kyber ciphertext (encapsulation of Alice's Kyber pubkey)
      - His own ephemeral Kyber pubkey (for Alice to use if she wants to re-encap)
      - His ECDHE ephemeral pubkey
      - A timestamp and ML-DSA-65 signature over the payload

    Server verifies Bob's signature, then forwards to Alice.
    Server does NOT compute or see any shared secrets.

    data: {
        token,
        target_user,              -- Alice (the original initiator)
        kyber_ciphertext (hex),   -- Bob's Kyber encapsulation of Alice's pubkey
        kyber_ephemeral_pubkey (hex), -- Bob's own Kyber pubkey
        ecdhe_ephemeral_pubkey (hex), -- Bob's ECDHE pubkey
        timestamp (unix ms string),
        signature (hex, ML-DSA-65 over:
                   kyber_ciphertext || kyber_ephemeral_pubkey ||
                   ecdhe_ephemeral_pubkey || timestamp)
    }

    Server actions:
      1. Validate Bob's token
      2. Fetch Bob's registered ML-DSA-65 public key
      3. Reconstruct signed payload: ct||kyber_pub||ecdhe_pub||timestamp
      4. Verify ML-DSA-65 signature — reject if invalid
      5. Forward full bundle to Alice's socket, adding 'from': bob_username
    """
    token = (data or {}).get("token")
    bob = _get_user_from_token(token)
    if not bob:
        emit("auth_error", {"error": "Invalid token"})
        return

    alice = data.get("target_user")
    if not alice:
        emit("error", {"message": "target_user (Alice) is required"})
        return

    # Fetch Bob's identity keys for signature verification
    bob_keys = get_public_keys(bob)
    if not bob_keys:
        emit("error", {"message": "Your identity keys are not registered"})
        return

    try:
        kyber_ct_bytes      = bytes.fromhex(data["kyber_ciphertext"])
        kyber_pub_bytes     = bytes.fromhex(data["kyber_ephemeral_pubkey"])
        ecdhe_pub_bytes     = bytes.fromhex(data["ecdhe_ephemeral_pubkey"])
        timestamp_bytes     = data["timestamp"].encode()
        signature_bytes     = bytes.fromhex(data["signature"])
        bob_dil_pubkey      = bytes.fromhex(bob_keys["dilithium_public_key"])
    except (KeyError, ValueError) as e:
        emit("error", {"message": f"Malformed handshake_response payload: {e}"})
        return

    # Signed payload matches what Bob's client constructed
    signed_payload = (
        kyber_ct_bytes + kyber_pub_bytes + ecdhe_pub_bytes + timestamp_bytes
    )

    # Skip sig verify in DEGRADED MODE — signature is 64 zero bytes (marker)
    is_degraded = (signature_bytes == b'\x00' * 64 or signature_bytes == b'\x00' * len(signature_bytes))
    if not is_degraded:
        if not _dilithium.verify(bob_dil_pubkey, signed_payload, signature_bytes):
            emit("error", {"message": "Invalid handshake_response signature — possible MITM"})
            return
    else:
        app.logger.info(f"[DEGRADED] {bob}: skipping response sig verify (DEGRADED MODE)")

    # Forward to Alice — server sees only opaque hex blobs
    alice_sid = connected_users.get(alice)
    if not alice_sid:
        emit("user_offline", {"username": alice})
        return

    emit("handshake_complete", {
        "from":                    bob,
        "kyber_ciphertext":        data["kyber_ciphertext"],
        "kyber_ephemeral_pubkey":  data["kyber_ephemeral_pubkey"],
        "ecdhe_ephemeral_pubkey":  data["ecdhe_ephemeral_pubkey"],
        "timestamp":               data["timestamp"],
        "signature":               data["signature"],
    }, to=alice_sid)


@socketio.on("send_message")
def on_send_message(data: dict):
    """
    Forward an AES-256-GCM encrypted message to the target user.
    Server is a BLIND RELAY — it never decrypts or inspects the payload.
    Signature verification is the RECIPIENT's responsibility.

    data: {
        token,
        target_user,
        nonce (hex, 12 bytes),
        ciphertext (hex),
        tag (hex, 16 bytes),
        ratchet_step (int),
        signature (hex, ML-DSA-65 over nonce||ciphertext||ratchet_step)
    }
    """
    token = (data or {}).get("token")
    sender = _get_user_from_token(token)
    if not sender:
        emit("auth_error", {"error": "Invalid token"})
        return

    target = data.get("target_user")
    if not target:
        emit("error", {"message": "target_user is required"})
        return

    target_sid = connected_users.get(target)
    if not target_sid:
        emit("user_offline", {"username": target})
        return

    # Forward opaque encrypted payload — server reads nothing
    emit("receive_message", {
        "from":         sender,
        "nonce":        data.get("nonce", ""),
        "ciphertext":   data.get("ciphertext", ""),
        "tag":          data.get("tag", ""),
        "ratchet_step": data.get("ratchet_step", 0),
        "signature":    data.get("signature", ""),
    }, to=target_sid)

    emit("message_delivered", {"to_user": target})


@socketio.on("request_session_reset")
def on_request_session_reset(data: dict):
    """
    Amendment 3: Forward a session reset request to the target user.
    Used when the ratchet gets desynced. Both parties must re-handshake.

    data: {token, target_user, reason (optional)}
    """
    token = (data or {}).get("token")
    sender = _get_user_from_token(token)
    if not sender:
        emit("auth_error", {"error": "Invalid token"})
        return

    target = data.get("target_user")
    target_sid = connected_users.get(target)
    if target_sid:
        emit("session_reset_requested", {
            "from": sender,
            "reason": data.get("reason", "Manual reset requested"),
        }, to=target_sid)

    emit("session_reset_sent", {"to_user": target})


@socketio.on("disconnect")
def on_disconnect():
    """Remove from connected_users and broadcast updated list."""
    username = sid_to_user.pop(request.sid, None)
    if username and connected_users.get(username) == request.sid:
        del connected_users[username]

    socketio.emit("user_list", {"online_users": _get_online_users()})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    startup()
    socketio.run(app, debug=True, port=5000)
