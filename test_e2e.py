import base64
import time

import requests
import socketio

from crypto.aes_gcm import aes_gcm_decrypt, aes_gcm_encrypt
from crypto.ecdhe import ecdhe_compute_shared, generate_ecdhe_keypair
from crypto.kdf import derive_session_key
from crypto.kyber import generate_kyber_keypair, kyber_decapsulate

BASE = 'http://localhost:5000'


def get_token(user, pwd):
    response = requests.post(f'{BASE}/login', json={'username': user, 'password': pwd}, timeout=10)
    response.raise_for_status()
    body = response.json()
    return body['token']


class PQClient:
    def __init__(self, username, token):
        self.username = username
        self.token = token
        self.session_key = None
        self.received = []
        self.sio = socketio.Client()
        self._register_events()

    def _register_events(self):
        @self.sio.event
        def handshake_response(data):
            kyber_ss = kyber_decapsulate(
                self.kyber_priv,
                base64.b64decode(data['server_kyber_ciphertext_b64']),
            )
            ecdhe_ss = ecdhe_compute_shared(
                self.ecdhe_priv,
                base64.b64decode(data['server_ecdhe_pub_b64']),
            )
            self.session_key = derive_session_key(kyber_ss, ecdhe_ss)

        @self.sio.event
        def receive_message(data):
            plaintext = aes_gcm_decrypt(self.session_key, data['encrypted_payload'])
            self.received.append((data['from_user'], plaintext))

    def connect_and_handshake(self):
        self.sio.connect(f'{BASE}?token={self.token}')
        self.kyber_pub, self.kyber_priv = generate_kyber_keypair()
        self.ecdhe_priv, self.ecdhe_pub = generate_ecdhe_keypair()
        self.sio.emit(
            'handshake_init',
            {
                'token': self.token,
                'client_kyber_pub_b64': base64.b64encode(self.kyber_pub).decode(),
                'client_ecdhe_pub_b64': base64.b64encode(self.ecdhe_pub).decode(),
            },
        )

    def send(self, to_user, message):
        time.sleep(0.3)
        payload = aes_gcm_encrypt(self.session_key, message)
        self.sio.emit(
            'send_message',
            {
                'token': self.token,
                'to_user': to_user,
                'encrypted_payload': payload,
            },
        )


if __name__ == '__main__':
    alice = PQClient('alice', get_token('alice', 'alice123'))
    bob = PQClient('bob', get_token('bob', 'bob123'))

    alice.connect_and_handshake()
    bob.connect_and_handshake()
    time.sleep(0.6)

    alice.send('bob', 'Hello Bob! This is end-to-end encrypted.')
    time.sleep(0.6)

    assert ('alice', 'Hello Bob! This is end-to-end encrypted.') in bob.received
    print('PASS: Full E2E encrypted message delivery')

    alice.sio.disconnect()
    bob.sio.disconnect()
