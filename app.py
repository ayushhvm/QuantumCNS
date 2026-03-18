import base64

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_socketio import SocketIO, disconnect, emit

from auth.users import generate_token, get_session_key, set_session_key, validate_token, verify_user
from crypto.aes_gcm import aes_gcm_decrypt, aes_gcm_encrypt
from crypto.ecdhe import ecdhe_compute_shared, generate_ecdhe_keypair
from crypto.kdf import derive_session_key
from crypto.kyber import generate_kyber_keypair, kyber_encapsulate

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins='*')

SOCKET_MAP = {}
USERNAME_SOCKET = {}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    payload = request.get_json(silent=True) or {}
    username = payload.get('username', '')
    password = payload.get('password', '')

    if not verify_user(username, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(username)
    return jsonify({'token': token, 'username': username})


@app.get('/chat')
def chat():
    token = request.args.get('token')
    username = validate_token(token)
    if not username:
        return redirect(url_for('login'))
    return render_template('chat.html', username=username, token=token)


@app.get('/')
def root_redirect():
    return redirect(url_for('login'))


@socketio.on('connect')
def on_connect():
    token = request.args.get('token')
    username = validate_token(token)
    if not username:
        emit('auth_error', {'error': 'Invalid token'}, to=request.sid)
        disconnect(request.sid)
        return

    SOCKET_MAP[request.sid] = token
    USERNAME_SOCKET[username] = request.sid


@socketio.on('handshake_init')
def on_handshake_init(data):
    token = (data or {}).get('token')
    username = validate_token(token)
    if not username:
        emit('auth_error', {'error': 'Invalid token'}, to=request.sid)
        return

    client_kyber_pub_b64 = data.get('client_kyber_pub_b64')
    client_ecdhe_pub_b64 = data.get('client_ecdhe_pub_b64')
    if not client_kyber_pub_b64 or not client_ecdhe_pub_b64:
        emit('handshake_error', {'error': 'Missing client handshake keys'}, to=request.sid)
        return

    server_kyber_pub, server_kyber_priv = generate_kyber_keypair()
    server_ecdhe_priv, server_ecdhe_pub = generate_ecdhe_keypair()
    _ = (server_kyber_pub, server_kyber_priv)

    ciphertext, kyber_shared = kyber_encapsulate(base64.b64decode(client_kyber_pub_b64))
    ecdhe_shared = ecdhe_compute_shared(server_ecdhe_priv, base64.b64decode(client_ecdhe_pub_b64))

    session_key = derive_session_key(kyber_shared, ecdhe_shared)
    set_session_key(token, session_key)

    emit(
        'handshake_response',
        {
            'server_kyber_ciphertext_b64': base64.b64encode(ciphertext).decode('utf-8'),
            'server_ecdhe_pub_b64': base64.b64encode(server_ecdhe_pub).decode('utf-8'),
            'log_steps': [
                'Kyber512 KEM initiated',
                'ECDHE P-256 exchange completed',
                'HKDF-SHA256 session key derived (256-bit)',
                'AES-256-GCM encryption active',
            ],
        },
        to=request.sid,
    )


@socketio.on('send_message')
def on_send_message(data):
    token = (data or {}).get('token')
    from_user = validate_token(token)
    if not from_user:
        emit('auth_error', {'error': 'Invalid token'}, to=request.sid)
        return

    to_user = data.get('to_user')
    encrypted_payload = data.get('encrypted_payload')
    if not to_user or not encrypted_payload:
        emit('message_error', {'error': 'Missing to_user or encrypted_payload'}, to=request.sid)
        return

    if data.get('token') != SOCKET_MAP.get(request.sid):
        emit('auth_error', {'error': 'Token does not match current socket session'}, to=request.sid)
        return

    target_sid = USERNAME_SOCKET.get(to_user)
    if not target_sid:
        emit('user_offline', {'to_user': to_user}, to=request.sid)
        return

    sender_key = get_session_key(token)
    target_token = SOCKET_MAP.get(target_sid)
    target_key = get_session_key(target_token) if target_token else None
    relay_payload = encrypted_payload

    if sender_key and target_key:
        try:
            plaintext = aes_gcm_decrypt(sender_key, encrypted_payload)
            relay_payload = aes_gcm_encrypt(target_key, plaintext)
        except ValueError:
            emit('message_error', {'error': 'Message authentication failed'}, to=request.sid)
            return

    emit(
        'receive_message',
        {'from_user': from_user, 'encrypted_payload': relay_payload},
        to=target_sid,
    )
    emit('message_delivered', {'to_user': to_user}, to=request.sid)


@socketio.on('disconnect')
def on_disconnect():
    token = SOCKET_MAP.pop(request.sid, None)
    if not token:
        return

    username = validate_token(token)
    if username and USERNAME_SOCKET.get(username) == request.sid:
        del USERNAME_SOCKET[username]


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
