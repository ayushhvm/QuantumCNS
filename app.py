from flask import Flask
from flask_socketio import SocketIO

from crypto import aes_gcm, ecdhe, kdf, kyber

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins='*')


@app.get('/')
def health_check() -> str:
    # Keep explicit references so imports are not optimized away by linters.
    _ = (kyber, ecdhe, kdf, aes_gcm)
    return 'PQ Messenger — OK'


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
