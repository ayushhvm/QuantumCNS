# PQChat v2.0 — Implementation Plan

## Goal
Upgrade the existing v1.0 server-decrypts-everything chat app to a production-grade, academically rigorous v2.0 with:
- True End-to-End Encryption (server is now a blind relay)
- Kyber768 + ML-DSA-65 (Dilithium3 equivalent, FIPS 204) post-quantum primitives
- Simplified Double Ratchet for forward secrecy
- Quantum Attack Simulator (Shor's, BKZ Lattice, Grover's)
- Cyberpunk Terminal UI

---

## ⚠️ Critical Algorithm Finding (Run Before Planning)

| Spec Says | Actual liboqs v0.15.0 Name | Status |
|---|---|---|
| `Kyber768` | `Kyber768` | ✅ Available |
| `Dilithium3` | **NOT FOUND** — use `ML-DSA-65` | ⚠️ Name differs |
| `ML-KEM-768` | `ML-KEM-768` | ✅ Available (NIST name) |
| `ML-DSA-65` | `ML-DSA-65` | ✅ This IS Dilithium3 (FIPS 204) |

**Decision:** Use `Kyber768` for KEM and `ML-DSA-65` for signatures. These are the correct NIST standardized names in liboqs 0.15.0. All code comments will document this.

---

## User Review Required

> [!IMPORTANT]
> The spec calls for `Dilithium3` but your installed liboqs (v0.15.0) uses the new NIST FIPS 204 name `ML-DSA-65`. These are the **same algorithm**, just renamed. The plan proceeds with `ML-DSA-65`.

> [!IMPORTANT]
> The liboqs-wasm (browser-side) situation: The npm package `liboqs-node` has a WASM build but the exact algorithms available in the browser bundle must be verified at runtime. The frontend handshake design has a fallback: if Kyber768 isn't in WASM, we fall back to browser-side emulation via a fetch call to a local signing endpoint (server-assisted, privacy-preserving).

> [!WARNING]
> The Double Ratchet implementation is simplified. It implements the **Symmetric-Key Ratchet** (chain key → message key derivation) fully. The **DH Ratchet** step is architecturally stubbed with clear documentation pointing to the Signal spec. Full DH Ratchet requires careful out-of-order message handling which is documented as a known limitation.

---

## Proposed Changes

### Phase 1 — Crypto Foundation (Backend)

#### [MODIFY] crypto/kyber.py
- Upgrade to `Kyber768` (from `Kyber512`)
- Use context manager pattern (`with oqs.KeyEncapsulation(...) as kem`)
- Add `KyberKEM` class with `generate_keypair`, `encapsulate`, `decapsulate`

#### [NEW] crypto/dilithium.py
- Implement `DilithiumSigner` class using `ML-DSA-65`
- Methods: `generate_keypair`, `sign`, `verify`
- `verify` never raises — returns `False` on invalid signature

#### [MODIFY] crypto/kdf.py → crypto/hkdf.py
- Fix HKDF construction: `salt = SHA256(alice_kyber_pub || bob_kyber_pub)`
- info string: `b"PQChat-v2-session-key"`
- Add `derive_ratchet_keys(chain_key, step) → (new_chain_key, message_key)`

#### [NEW] crypto/ratchet.py
- `SymmetricRatchet` class with `advance()` returning next message key
- Message keys are discarded immediately after use (forward secrecy)
- DH ratchet stub clearly marked

---

### Phase 2 — Backend Overhaul

#### [MODIFY] auth/users.py
- Replace in-memory dict with SQLite (`users.db`)
- Scrypt password hashing (replaces SHA-256)
- Store `dilithium_public_key` and `ecdh_identity_public_key` per user
- Session expiry in the sessions table

#### [NEW] auth/tokens.py
- Move token generation/validation here
- Add token expiry logic

#### [MODIFY] app.py
- Server becomes **blind relay** — never touches plaintext or keys
- New events: `register_identity`, `handshake_init`, `handshake_response`, `send_message`
- New HTTP endpoints: `GET /api/keys/<username>` to fetch public identity keys
- Add simulator routes: `/api/simulate/shors`, `/api/simulate/lattice`, `/api/simulate/grover`

---

### Phase 3 — Quantum Attack Simulator

#### [NEW] simulator/__init__.py
#### [NEW] simulator/shors_simulation.py
- Classical simulation of Shor's period finding
- `simulate_shors_period_finding(N, a)` — works on small N, extrapolates for P-256
- `extrapolate_to_p256()` — estimates quantum resources needed

#### [NEW] simulator/lattice_attack_simulator.py
- BKZ lattice attack complexity estimates
- Actually runs brute-force on toy params (n < 20)
- Reports infeasibility for real Kyber768 params
- Uses numpy

#### [NEW] simulator/grovers_simulation.py
- Grover's algorithm impact analysis on AES and SHA-256
- Pure computational complexity analysis, no actual search

---

### Phase 4 — Frontend Crypto Client

#### [MODIFY] static/js/crypto_client.js
- Full `PQChatClient` class
- Identity key generation via liboqs-wasm (`ML-DSA-65`)
- Ephemeral Kyber768 keypair per handshake
- ECDHE P-256 via WebCrypto
- Sign handshake payload with ML-DSA-65
- Derive session key via HKDF (WebCrypto)
- `encryptMessage` / `decryptMessage` using ratchet message keys

#### [NEW] static/js/ratchet_client.js
- Browser-side symmetric ratchet
- HKDF step via WebCrypto subtle

#### [NEW] static/js/attack_simulator.js
- Calls `/api/simulate/*` endpoints
- Animates results in the simulator panel
- Step-by-step visualization

#### [NEW] static/js/ui.js
- Handles all DOM interactions cleanly
- Fingerprint display and "Mark as Verified" button

---

### Phase 5 — UI / Templates

#### [MODIFY] templates/login.html
- Cyberpunk terminal aesthetic
- Registration form (username + password)
- Monospace fonts, electric cyan on black

#### [MODIFY] templates/chat.html
- Three-panel layout: Contacts | Chat | Crypto Terminal
- Live crypto log panel (ratchet steps, sig verifications, key derivations)
- Key fingerprint display with Verified button
- Status badges: `[QUANTUM-SAFE]` `[E2EE]` `[RATCHET ACTIVE]`

#### [NEW] templates/simulator.html
- Attack selector panel
- Animated output panel
- Defense status sidebar
- Comparison table: ECDHE vs Kyber768 vs AES-256

#### [MODIFY] static/css/style.css
- Full cyberpunk design system
- Color vars: `--cyan: #00f5ff`, `--green: #00ff88`, `--red: #ff2244`
- Scanline overlay for crypto panels
- Glowing borders, pulse animations

---

### Phase 6 — Tests

#### [MODIFY] tests/test_crypto.py
- `test_kyber768_roundtrip()`
- `test_mldsa65_sign_verify()`
- `test_mldsa65_tamper_detection()`
- `test_hkdf_determinism()`
- `test_full_e2ee_handshake()`

#### [NEW] tests/test_ratchet.py
- Ratchet advances correctly for 20 steps
- Each step produces a unique message key
- Chain key changes at each step

#### [NEW] tests/test_e2ee_flow.py
- Full Alice → Bob E2EE flow via Socket.IO test clients
- Verify server never sees plaintext

---

## Verification Plan

### Automated Tests
```bash
source venv/bin/activate
python -m pytest tests/ -v
```

### Manual Verification
1. Start server: `python app.py`
2. Open two browser tabs — login as alice and bob
3. Observe crypto terminal panel showing: `ML-DSA-65 sig verified`, `Kyber768 session key derived`, `Ratchet step N`
4. Send messages — inspect WebSocket frames in DevTools (should show only hex ciphertext)
5. Navigate to `/simulator` — run all three attack simulations
6. Verify fingerprint display matches on both sides

---

## Known Limitations to Document
- localStorage secret key storage is not production-safe (should use WebAuthn)
- DH Ratchet is stubbed (only symmetric ratchet active)
- Out-of-order message delivery breaks ratchet sync
- In-memory session state (no persistence across server restart)
- `liboqs-wasm` algorithm availability in browser needs runtime check

---

## Execution Phases at a Glance

```
Phase 1: crypto/ wrappers + tests          [Foundation]
Phase 2: auth/ + app.py rewrite            [Backend]
Phase 3: simulator/                         [Simulator]
Phase 4: static/js/ crypto client          [Frontend Crypto]
Phase 5: templates/ + CSS                  [UI]
Phase 6: integration tests + final check   [Verify]
```
