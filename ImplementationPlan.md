# Post-Quantum Secure Messaging Web Application
## Hybrid TLS Handshake (ECDHE + CRYSTALS-Kyber) — Copilot Implementation Plan
> ISE Cryptography & Network Security — Semester Lab Project

| | |
|---|---|
| **Project** | Post-Quantum Secure Messaging App |
| **Approach** | 6 Phases — sequential, test-driven |
| **Stack** | Python (Flask + Flask-SocketIO) · JavaScript · HTML/CSS |
| **Crypto** | CRYSTALS-Kyber (liboqs) · ECDHE · KDF (HKDF-SHA256) · AES-GCM |
| **Start** | Empty folder → fully working application |

---

## How to Use This Document

This plan is written as copilot-ready instructions. Work through the phases in **strict order**. Each phase has a clear deliverable and a set of debug tests to run before proceeding to the next phase. Do not skip ahead — each phase builds directly on the previous one.

| Column | What it means |
|---|---|
| **Goal** | What the phase accomplishes and why it exists |
| **Files to create** | Exact filenames your copilot should produce |
| **What to code** | Line-by-line description of every function/block needed |
| **Debug tests** | Commands to run and expected output before moving on |
| **Checkpoint** | One-sentence pass/fail condition for the phase |

---

## Final Folder Structure (Reference)

Keep this in mind as you build each phase:

```
pq-messenger/
├── app.py                    # Flask + SocketIO entry point
├── requirements.txt          # Python dependencies
├── crypto/
│   ├── __init__.py
│   ├── kyber.py              # CRYSTALS-Kyber wrapper (liboqs)
│   ├── ecdhe.py              # ECDHE key exchange
│   ├── kdf.py                # HKDF key derivation
│   └── aes_gcm.py            # AES-256-GCM encrypt/decrypt
├── auth/
│   ├── __init__.py
│   └── users.py              # In-memory user store + session tokens
├── static/
│   ├── css/style.css
│   └── js/
│       ├── crypto_client.js  # Client-side Kyber KEM (liboqs-wasm)
│       └── chat.js           # SocketIO + AES-GCM chat logic
└── templates/
    ├── login.html
    └── chat.html
```

---

# Phase 1 — Project Skeleton & Dependencies
> Set up the folder structure, virtual environment, and verify all crypto libraries install correctly

## 1.1 Goal

Before writing any logic, establish a working Python environment with every library the project needs. Debugging import errors now saves hours later. This phase ends when you can import every crypto primitive without errors.

## 1.2 Files to Create

| File | Purpose |
|---|---|
| `requirements.txt` | Pin all Python dependencies |
| `app.py` | Empty Flask skeleton — just imports and app init |
| `crypto/__init__.py` | Empty — marks directory as Python package |
| `auth/__init__.py` | Empty — marks directory as Python package |
| `static/css/style.css` | Empty file (populated in Phase 5) |
| `static/js/chat.js` | Empty file (populated in Phase 4) |
| `templates/login.html` | Bare HTML shell (populated in Phase 5) |
| `templates/chat.html` | Bare HTML shell (populated in Phase 5) |

## 1.3 What to Code

### `requirements.txt`

```
flask==3.0.3
flask-socketio==5.3.6
python-socketio==5.11.1
eventlet==0.35.2
cryptography==42.0.8
pycryptodome==3.20.0
liboqs-python==0.10.1
```

### `app.py` — skeleton only

Ask your copilot to write a minimal Flask + SocketIO app that:

- Imports Flask, SocketIO, and all four crypto modules (even though they are empty)
- Creates `app = Flask(__name__)` and `socketio = SocketIO(app, cors_allowed_origins='*')`
- Adds a single `GET /` route that returns the string `'PQ Messenger — OK'`
- Runs with `socketio.run(app, debug=True, port=5000)` under `if __name__ == '__main__'`

> ⚠️ **liboqs-python requires the native liboqs C library.**
> - Ubuntu/Debian: `sudo apt-get install liboqs-dev`
> - macOS: `brew install liboqs`
> - Windows: use WSL2 or build from source (cmake)
>
> Verify with: `python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"`

## 1.4 Debug Tests — Run These Before Phase 2

| Test | Expected output |
|---|---|
| `python -c "import oqs"` | No error — liboqs installed |
| `python -c "from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key"` | No error |
| `python -c "from Crypto.Cipher import AES"` | No error — PyCryptodome installed |
| `python app.py` then `curl http://localhost:5000/` | Returns: `PQ Messenger — OK` |
| `python -c "import oqs; print(oqs.KeyEncapsulation('Kyber512').details)"` | Prints Kyber512 details dict |

> ✅ **CHECKPOINT:** All five tests pass. No `ImportError` anywhere. Proceed to Phase 2.

---

# Phase 2 — Core Cryptography Layer
> Implement all four crypto primitives as standalone, independently testable Python modules

## 2.1 Goal

Each crypto primitive lives in its own file with a clean function interface. Write and test these **completely** before touching the web layer. This makes bugs easy to isolate.

## 2.2 Module: `crypto/kyber.py`

Wraps liboqs `KeyEncapsulation` for Kyber512 (suitable for demo; use Kyber1024 for production).

**Functions to implement:**

- **`generate_kyber_keypair() → (public_key: bytes, private_key: bytes)`**
  Uses `oqs.KeyEncapsulation('Kyber512')`. Calls `generate_keypair()`. Returns `export_public_key()` and `export_secret_key()`.

- **`kyber_encapsulate(public_key: bytes) → (ciphertext: bytes, shared_secret: bytes)`**
  Creates a new KEM object, calls `encap_secret(public_key)`. Returns both outputs.

- **`kyber_decapsulate(private_key: bytes, ciphertext: bytes) → shared_secret: bytes`**
  Creates new KEM, calls `decap_secret(ciphertext)` after loading the secret key. Returns `shared_secret`.

> ℹ️ The liboqs API requires creating a fresh `oqs.KeyEncapsulation` object for each operation. Do not reuse instances across calls.

## 2.3 Module: `crypto/ecdhe.py`

Classical key exchange using ECDH on P-256 (secp256r1).

**Functions to implement:**

- **`generate_ecdhe_keypair() → (private_key_obj, public_key_bytes: bytes)`**
  Use `cryptography` library: `ec.generate_private_key(ec.SECP256R1())`. Serialize public key to DER format using `public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)`.

- **`ecdhe_compute_shared(private_key_obj, peer_public_key_bytes: bytes) → shared_bytes: bytes`**
  Deserialize peer's DER bytes with `load_der_public_key()`. Call `private_key.exchange(ec.ECDH(), peer_public_key)`. Returns raw bytes.

## 2.4 Module: `crypto/kdf.py`

Derives one strong session key from the two independent shared secrets.

**Functions to implement:**

- **`derive_session_key(kyber_secret: bytes, ecdhe_secret: bytes) → session_key: bytes`**
  - Concatenate: `ikm = kyber_secret + ecdhe_secret`
  - Use `HKDF` from `cryptography.hazmat.primitives.kdf.hkdf`
  - Parameters: `algorithm=hashes.SHA256()`, `length=32`, `salt=b'PQ-Messenger-Salt-v1'`, `info=b'session-key'`
  - Returns 32-byte key (suitable for AES-256)

## 2.5 Module: `crypto/aes_gcm.py`

Authenticated encryption for all chat messages.

**Functions to implement:**

- **`aes_gcm_encrypt(key: bytes, plaintext: str) → dict`**
  - Generate 12-byte random nonce: `os.urandom(12)`
  - Use `AES.new(key, AES.MODE_GCM, nonce=nonce)` from `Crypto.Cipher`
  - Call `cipher.encrypt_and_digest(plaintext.encode())`
  - Returns `{'nonce': hex, 'ciphertext': hex, 'tag': hex}`

- **`aes_gcm_decrypt(key: bytes, payload: dict) → str`**
  - Reconstruct cipher with nonce from payload. Call `decrypt_and_verify(ciphertext, tag)`. Returns plaintext string.
  - On authentication failure raise `ValueError('Message authentication failed')`

## 2.6 Debug Tests — Run These Before Phase 3

Create a file `test_crypto.py` at project root:

```python
# test_crypto.py
from crypto.kyber import generate_kyber_keypair, kyber_encapsulate, kyber_decapsulate
from crypto.ecdhe import generate_ecdhe_keypair, ecdhe_compute_shared
from crypto.kdf import derive_session_key
from crypto.aes_gcm import aes_gcm_encrypt, aes_gcm_decrypt

# Test 1: Kyber round-trip
pub, priv = generate_kyber_keypair()
ct, ss_enc = kyber_encapsulate(pub)
ss_dec = kyber_decapsulate(priv, ct)
assert ss_enc == ss_dec, 'Kyber shared secrets must match'
print('PASS: Kyber key exchange')

# Test 2: ECDHE round-trip (Alice and Bob)
alice_priv, alice_pub = generate_ecdhe_keypair()
bob_priv, bob_pub = generate_ecdhe_keypair()
alice_shared = ecdhe_compute_shared(alice_priv, bob_pub)
bob_shared = ecdhe_compute_shared(bob_priv, alice_pub)
assert alice_shared == bob_shared, 'ECDHE shared secrets must match'
print('PASS: ECDHE key exchange')

# Test 3: KDF determinism
key1 = derive_session_key(b'kyber_secret', b'ecdhe_secret')
key2 = derive_session_key(b'kyber_secret', b'ecdhe_secret')
assert key1 == key2 and len(key1) == 32
print('PASS: KDF produces consistent 32-byte key')

# Test 4: AES-GCM round-trip
key = derive_session_key(ss_dec, alice_shared)
payload = aes_gcm_encrypt(key, 'Hello post-quantum world!')
msg = aes_gcm_decrypt(key, payload)
assert msg == 'Hello post-quantum world!'
print('PASS: AES-GCM encrypt/decrypt')

# Test 5: Tamper detection
payload['ciphertext'] = 'ff' * len(bytes.fromhex(payload['ciphertext']))
try:
    aes_gcm_decrypt(key, payload)
except ValueError as e:
    print('PASS: Tamper detected —', e)

print('\nAll crypto tests passed.')
```

Run: `python test_crypto.py`

> ✅ **CHECKPOINT:** All 5 tests print PASS. Proceed to Phase 3.

---

# Phase 3 — Backend: Authentication & Handshake
> Build the Flask server with user login, session management, and the full hybrid handshake over WebSockets

## 3.1 Goal

Wire the crypto layer into a real server. Users authenticate, then the server orchestrates the ECDHE + Kyber handshake over SocketIO events, producing a session key stored server-side. Messages sent by clients will be encrypted payloads the server relays without ever seeing plaintext.

## 3.2 `auth/users.py` — User Store

Implement a simple in-memory user system (no database needed for the lab):

- `USERS` dict: `{ 'alice': 'hashed_password', 'bob': 'hashed_password' }`. Use `hashlib.sha256` to hash passwords. Pre-populate two users on startup.
- `SESSIONS` dict: `{ token: { 'username': str, 'session_key': bytes or None } }`
- **`generate_token(username) → str`**: Creates `secrets.token_hex(32)`, stores in `SESSIONS`, returns token.
- **`validate_token(token) → username or None`**: Looks up token in `SESSIONS`.
- **`set_session_key(token, key: bytes)`**: Stores the derived session key for this token.
- **`get_session_key(token) → bytes or None`**

## 3.3 `app.py` — HTTP Routes

**`POST /login`**
- Accepts JSON body: `{ username, password }`
- Verifies against `USERS` store. On success: calls `generate_token()`, returns `{ token, username }`
- On failure: returns `{ error: 'Invalid credentials' }` with HTTP 401

**`GET /chat`**
- Requires token in query string (`?token=...`). Validates token.
- On success: renders `chat.html` template, passing `username` and `token`
- On failure: redirects to `/login`

**`GET /`** → redirect to `/login`

## 3.4 `app.py` — Hybrid Handshake (SocketIO Events)

This is the centrepiece of the project. Implement these SocketIO event handlers:

**Event: `connect`**
- Validates token from `request.args`. Stores socket ID → token mapping in a `SOCKET_MAP` dict.

**Event: `handshake_init`** — payload: `{ token, client_kyber_pub_b64, client_ecdhe_pub_b64 }`

1. Generate server-side keypairs:
   ```
   server_kyber_pub, server_kyber_priv = generate_kyber_keypair()
   server_ecdhe_priv, server_ecdhe_pub  = generate_ecdhe_keypair()
   ```
2. Kyber encapsulation (server encapsulates to client's public key):
   ```
   ciphertext, kyber_shared = kyber_encapsulate(base64.b64decode(client_kyber_pub_b64))
   ```
3. ECDHE shared secret:
   ```
   ecdhe_shared = ecdhe_compute_shared(server_ecdhe_priv, base64.b64decode(client_ecdhe_pub_b64))
   ```
4. Derive session key:
   ```
   session_key = derive_session_key(kyber_shared, ecdhe_shared)
   ```
5. Store key: `set_session_key(token, session_key)`
6. Emit `handshake_response` back to the same client:
   ```json
   {
     "server_kyber_ciphertext_b64": "...",
     "server_ecdhe_pub_b64": "...",
     "log_steps": [
       "Kyber512 KEM initiated",
       "ECDHE P-256 exchange completed",
       "HKDF-SHA256 session key derived (256-bit)",
       "AES-256-GCM encryption active"
     ]
   }
   ```

**Event: `send_message`** — payload: `{ token, to_user, encrypted_payload: { nonce, ciphertext, tag } }`
- Validates token. Looks up the target user's socket ID from a `USERNAME_SOCKET` dict.
- Emits `receive_message` to target socket: `{ from_user, encrypted_payload }`
- Emits `message_delivered` back to sender

**Event: `disconnect`**
- Cleans up `SOCKET_MAP` and `USERNAME_SOCKET` entries for this socket

## 3.5 Debug Tests — Run These Before Phase 4

```bash
# Terminal 1 — start server
python app.py

# Terminal 2 — test login (should return token)
curl -s -X POST http://localhost:5000/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice123"}'
# Expected: {"token": "<64-char hex string>", "username": "alice"}

# Test bad login
curl -s -X POST http://localhost:5000/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"wrong"}'
# Expected: {"error": "Invalid credentials"} with 401
```

```python
# test_handshake.py — run after server is up
import socketio, base64
from crypto.kyber import generate_kyber_keypair
from crypto.ecdhe import generate_ecdhe_keypair

TOKEN = '<paste token from curl above>'
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
sio.emit('handshake_init', {
    'token': TOKEN,
    'client_kyber_pub_b64': base64.b64encode(pub_k).decode(),
    'client_ecdhe_pub_b64': base64.b64encode(pub_e).decode(),
})
sio.wait()
```

> ✅ **CHECKPOINT:** Login returns a token. Handshake test prints all four log steps and PASS. Proceed to Phase 4.

---

# Phase 4 — Frontend: Client Handshake & Encrypted Chat
> Build the JavaScript client that performs the handshake, derives the session key, and sends/receives AES-GCM encrypted messages

## 4.1 Goal

The browser must independently perform its half of the key exchange so it can encrypt messages locally before sending. This phase uses `liboqs-wasm` for Kyber in the browser and the WebCrypto API for ECDH and AES-GCM.

> ℹ️ `liboqs-wasm` bundles the full Kyber implementation in WebAssembly. Load it from CDN:
> `https://cdn.jsdelivr.net/npm/liboqs-wasm/liboqs.js`
> The WASM module is large (~2MB). Show a loading spinner on the chat page until it is ready.

## 4.2 `static/js/crypto_client.js`

All cryptographic operations in the browser. Structure as an async module.

**State variables:** `clientKyberPub`, `clientKyberPriv`, `clientEcdhePub`, `clientEcdhePriv`, `sessionKey` (CryptoKey object), `kyberDecapObj`

**`async function initClientCrypto()`**
- Generate Kyber512 keypair using liboqs-wasm: `new OQS.KeyEncapsulation('Kyber512')`
- Generate ECDHE keypair: `window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])`
- Export both public keys to ArrayBuffer
- Returns `{ kyberPubB64, ecdhePubB64 }` for sending to server

**`async function processHandshakeResponse(data)`**
- Decapsulate Kyber: use saved `kyberDecapObj.decapSecret(base64ToBuffer(data.server_kyber_ciphertext_b64))` → `kyberSharedSecret`
- Derive ECDH shared secret: import server's ECDHE public key, call `deriveBits` with client's private key → `ecdhSharedSecret`
- Combine: `ikm = concat(kyberSharedSecret, ecdhSharedSecret)`
- Derive 256-bit AES key via HKDF:
  - `hash: 'SHA-256'`
  - `salt: TextEncoder('PQ-Messenger-Salt-v1')`
  - `info: TextEncoder('session-key')`
- Store derived AES-GCM key in module-level `sessionKey` variable

**`async function encryptMessage(plaintext)`**
- Generate 12-byte random IV: `crypto.getRandomValues(new Uint8Array(12))`
- Encrypt: `crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, sessionKey, encoded)`
- AES-GCM in WebCrypto appends the tag to ciphertext. Split: `ciphertext = result.slice(0, -16)`, `tag = result.slice(-16)`
- Return `{ nonce: bufToHex(iv), ciphertext: bufToHex(ct), tag: bufToHex(tag) }`

**`async function decryptMessage(payload)`**
- Reconstruct iv, ciphertext+tag from hex. Concatenate `ct + tag` for WebCrypto.
- Call `crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, sessionKey, ctWithTag)`
- Return decoded string. If decrypt throws, return `'[message authentication failed]'`

## 4.3 `static/js/chat.js` — Main Chat Logic

**On page load:**
- Read `TOKEN` and `USERNAME` from page data attributes (set by server in `chat.html` template)
- Connect: `const socket = io({ query: { token: TOKEN } })`

**On `connect` event:**
- Show `'Performing handshake...'` in a status div
- Call `initClientCrypto()`. Emit `handshake_init` with `{ token, client_kyber_pub_b64, client_ecdhe_pub_b64 }`

**On `handshake_response` event:**
- Call `processHandshakeResponse(data)` to derive `sessionKey`
- Print each step in `data.log_steps` to the terminal-style div on the chat page
- Update status: `'Session secured — AES-256-GCM active ✓'`
- Enable the message input field (disabled until handshake completes)

**On send button click:**
```javascript
const payload = await encryptMessage(inputField.value)
socket.emit('send_message', { token: TOKEN, to_user: chatPartner, encrypted_payload: payload })
// Display own message in chat — you have the key so no need to decrypt
```

**On `receive_message` event:**
```javascript
const plaintext = await decryptMessage(data.encrypted_payload)
// Display: '[data.from_user]: <plaintext>'
```

## 4.4 Debug Tests — Run These Before Phase 5

| Test | How to check |
|---|---|
| Browser console: no errors loading liboqs-wasm | Open DevTools → Console after loading chat page |
| Handshake log visible in terminal panel | Four green log lines appear after connect |
| Status shows 'Session secured' | Status div updates after `handshake_response` |
| Message encrypts before sending | DevTools Network → WS frames show hex payload, not plaintext |
| Received message decrypts correctly | Open two tabs (alice + bob), send message, verify both see plaintext |
| Tampered message shows auth error | In browser console: manually call `decryptMessage` with wrong tag hex |

> ✅ **CHECKPOINT:** Two users can exchange encrypted messages. Network tab shows only ciphertext. Proceed to Phase 5.

---

# Phase 5 — UI: Login Page & Chat Interface
> Build the complete user-facing HTML/CSS for both pages

## 5.1 Goal

Create a clean, readable interface that also serves as a demonstration tool. The chat page must have a visible **crypto terminal panel** showing the handshake steps — this is what evaluators will look at to verify the cryptography is working.

## 5.2 `templates/login.html`

A centered card with:
- App title: `'PQ Messenger'` with subtitle `'Post-Quantum Secure'`
- Username input field (`id='username'`)
- Password input field (`id='password'`, `type='password'`)
- Login button that calls `loginUser()` JavaScript function
- Error message div (hidden by default, shown on 401)

**Login JavaScript (inline in `login.html`):**
- `async function loginUser()`: POSTs to `/login` with `fetch()`, stores returned token in `sessionStorage`
- On success: `window.location.href = '/chat?token=' + data.token`
- On error: show error div with `'Invalid username or password'`

## 5.3 `templates/chat.html`

**Two-column layout:**

- **Left column (~280px):** Contact list. Hardcode `'Alice'` and `'Bob'` as the two users. Clicking a name sets the `chatPartner` variable.
- **Right column (remainder):** Split vertically:
  - Top 60%: Message area — scrollable div with message bubbles (own messages right-aligned, received left-aligned)
  - Bottom: Input row — text input + Send button

**Bottom panel (full width, collapsible): Crypto Terminal**
- Dark background, monospace font
- Connection status line (green dot / red dot)
- Each of the four handshake log steps as they arrive
- Encryption indicator: padlock icon + `'AES-256-GCM'` label

> ℹ️ The crypto terminal panel is the key demonstration element. Make it visually distinct (dark background, green monospace text). Show a blinking cursor animation while handshake is in progress.

## 5.4 `static/css/style.css`

CSS custom properties to define:

```css
:root {
  --primary:      #1E3A5F;
  --accent:       #2E86AB;
  --bg:           #F5F8FC;
  --terminal-bg:  #1A1A2E;
  --terminal-text:#A9DC76;
}
```

Key rules to implement:
- **Login card:** `max-width: 400px`, centered, `box-shadow`, `border-radius: 12px`
- **Chat layout:** CSS Grid with `grid-template-columns: 280px 1fr`, `grid-template-rows: 1fr auto 200px`
- **Message bubbles:** `border-radius: 18px`, `padding: 10px 16px`. Own: `background: var(--accent)`, white text. Received: white background, `border: 1px solid #ddd`
- **Terminal panel:** `font-family: monospace`, `background: var(--terminal-bg)`, `color: var(--terminal-text)`, `overflow-y: auto`
- **Status indicator:** 10px circle, red by default → green after handshake, CSS pulse animation

## 5.5 Debug Tests

| Visual check | Expected |
|---|---|
| Login page loads at `localhost:5000` | Centered card, no console errors |
| Wrong password | Error message appears below button |
| Correct login redirects to `/chat` | Chat page loads with two-column layout |
| Terminal panel on load | Shows `'Connecting...'` with blinking cursor |
| After handshake (~1s) | Terminal shows all 4 green log lines, padlock turns green |
| Message bubbles | Own messages right-aligned blue, received left-aligned white |
| Mobile / narrow window | Layout doesn't break below 768px width |

> ✅ **CHECKPOINT:** Application is fully usable visually. Evaluator can log in, see the handshake terminal, and send messages. Proceed to Phase 6.

---

# Phase 6 — Integration Testing & Final Polish
> End-to-end tests, error handling, and demonstration preparation

## 6.1 Goal

Verify the entire application works as a system, handle edge cases gracefully, and prepare for a live evaluation demo.

## 6.2 End-to-End Test Script: `test_e2e.py`

A headless test using two simultaneous Python SocketIO clients (simulating Alice and Bob):

```python
# test_e2e.py
import socketio, base64, requests, time
from crypto.kyber import generate_kyber_keypair, kyber_decapsulate
from crypto.ecdhe import generate_ecdhe_keypair, ecdhe_compute_shared
from crypto.kdf import derive_session_key
from crypto.aes_gcm import aes_gcm_encrypt, aes_gcm_decrypt

BASE = 'http://localhost:5000'

def get_token(user, pwd):
    r = requests.post(f'{BASE}/login', json={'username': user, 'password': pwd})
    return r.json()['token']

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
                base64.b64decode(data['server_kyber_ciphertext_b64'])
            )
            ecdhe_ss = ecdhe_compute_shared(
                self.ecdhe_priv,
                base64.b64decode(data['server_ecdhe_pub_b64'])
            )
            self.session_key = derive_session_key(kyber_ss, ecdhe_ss)

        @self.sio.event
        def receive_message(data):
            pt = aes_gcm_decrypt(self.session_key, data['encrypted_payload'])
            self.received.append((data['from_user'], pt))

    def connect_and_handshake(self):
        self.sio.connect(f'{BASE}?token={self.token}')
        self.kyber_pub, self.kyber_priv = generate_kyber_keypair()
        self.ecdhe_priv, self.ecdhe_pub = generate_ecdhe_keypair()
        self.sio.emit('handshake_init', {
            'token': self.token,
            'client_kyber_pub_b64': base64.b64encode(self.kyber_pub).decode(),
            'client_ecdhe_pub_b64': base64.b64encode(self.ecdhe_pub).decode(),
        })

    def send(self, to_user, message):
        time.sleep(0.3)  # wait for handshake
        payload = aes_gcm_encrypt(self.session_key, message)
        self.sio.emit('send_message', {
            'token': self.token,
            'to_user': to_user,
            'encrypted_payload': payload
        })

# --- Run the test ---
alice = PQClient('alice', get_token('alice', 'alice123'))
bob   = PQClient('bob',   get_token('bob',   'bob123'))

alice.connect_and_handshake()
bob.connect_and_handshake()
time.sleep(0.5)

alice.send('bob', 'Hello Bob! This is end-to-end encrypted.')
time.sleep(0.5)

assert ('alice', 'Hello Bob! This is end-to-end encrypted.') in bob.received
print('PASS: Full E2E encrypted message delivery')

alice.sio.disconnect()
bob.sio.disconnect()
```

## 6.3 Error Handling Checklist

Ask your copilot to verify each of these is handled:

| Scenario | Expected behaviour |
|---|---|
| User sends message before handshake completes | Button disabled; show `'Securing channel...'` |
| Token missing or invalid on connect | Server emits `'auth_error'`; client shows re-login prompt |
| Target user offline (socket not in `USERNAME_SOCKET`) | Server emits `'user_offline'` back to sender; client shows notice |
| liboqs-wasm not yet loaded when user types | Encrypt button stays disabled until WASM init resolves |
| Network disconnect mid-session | SocketIO auto-reconnect; show `'Reconnecting...'` in terminal |
| Message authentication failure on decrypt | Show `'[tampered message]'` in chat — never crash |

## 6.4 Demo Script for Evaluators

Walk through these exact steps during evaluation:

1. Start server: `python app.py`. Show terminal output confirming startup.
2. Open two browser windows side by side. Log in as `alice` in one, `bob` in the other.
3. Point to the **crypto terminal panel** — walk through each of the four log lines and explain what they mean cryptographically.
4. In Alice's window: open DevTools **Network → WS tab**. Send a message. Show the evaluator the raw WebSocket frame — it contains only hex ciphertext, never plaintext.
5. Show the message arriving and being decrypted automatically in Bob's window.
6. Optional: paste the ciphertext hex into a decoder and show it is unreadable without the session key.

## 6.5 Final Debug Checklist

| Check | Pass condition |
|---|---|
| `python test_crypto.py` | All 5 PASS lines printed |
| `python test_handshake.py` | 4 log steps printed + PASS |
| `python test_e2e.py` | `PASS: Full E2E encrypted message delivery` |
| Browser: no console errors | DevTools console is clean |
| Two users can chat | Both see correct decrypted messages |
| WS frames inspection | Only hex payloads visible, never plaintext |
| Evaluator log panel | 4 crypto log steps visible in terminal UI |

> ✅ **FINAL CHECKPOINT:** All tests pass, application runs cleanly, evaluator demo works. Project complete.

---

# Appendix — Cryptography Concept Reference

Use this section to explain the project to your evaluator.

| Concept | One-line explanation |
|---|---|
| **CRYSTALS-Kyber** | A Key Encapsulation Mechanism (KEM) based on Module-LWE — secure against quantum computers |
| **ECDHE** | Elliptic Curve Diffie-Hellman Ephemeral — classical key exchange; broken by Shor's algorithm on a quantum computer |
| **Hybrid handshake** | Combining both: even if one is broken (classical or quantum), the session remains secure |
| **KDF (HKDF-SHA256)** | Mixes two shared secrets into one uniform 256-bit key with guaranteed entropy |
| **AES-256-GCM** | Symmetric authenticated encryption: provides confidentiality (AES) + integrity (GCM tag) |
| **Post-quantum threat** | A large enough quantum computer can break RSA and ECC using Shor's algorithm. LWE-based schemes (Kyber) are not vulnerable. |
| **NIST PQC** | CRYSTALS-Kyber was standardised by NIST in 2024 as FIPS 203 (ML-KEM) — the first post-quantum KEM standard. |

---

*End of Implementation Plan*