import base64
import os

import socketio

from crypto.ecdhe import generate_ecdhe_keypair
from crypto.kyber import generate_kyber_keypair


TOKEN = os.environ.get('PQ_TOKEN', '')
if not TOKEN:
    raise SystemExit('Set PQ_TOKEN to a valid login token before running test_handshake.py')

sio = socketio.Client()


@sio.event
def handshake_response(data):
    print('Handshake response received:')
    for step in data['log_steps']:
        print(' ', step)
    assert 'server_kyber_ciphertext_b64' in data
    print('PASS: Handshake complete')
    sio.disconnect()


sio.connect(f'http://localhost:5000?token={TOKEN}')
pub_k, priv_k = generate_kyber_keypair()
priv_e, pub_e = generate_ecdhe_keypair()
_ = (priv_k, priv_e)
sio.emit(
    'handshake_init',
    {
        'token': TOKEN,
        'client_kyber_pub_b64': base64.b64encode(pub_k).decode('utf-8'),
        'client_ecdhe_pub_b64': base64.b64encode(pub_e).decode('utf-8'),
    },
)
sio.wait()
