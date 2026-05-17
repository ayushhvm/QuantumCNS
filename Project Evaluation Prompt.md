# MASTER ENGINEERING PROMPT
## Post-Quantum Secure Messaging Application — Version 2.0
### For: Local AI Coding Agent
### From: Cryptography Expert & Product Manager
### Classification: Complete Technical Specification

---

## ⚠️ CRITICAL INSTRUCTIONS FOR THE AI CODER

Before writing a single line of code, read this entire document.

**Anti-hallucination rules — non-negotiable:**
1. NEVER invent API method names. If you are unsure of an exact function signature in `liboqs-python`, `cryptography`, or any library — STOP. Write `# VERIFY: [what needs checking]` and report it.
2. NEVER assume library versions are compatible. Check and report exact versions used.
3. After completing EACH module (not each file — each logical module), produce a checkpoint report in this format:
   ```
   ✅ CHECKPOINT REPORT — Module: [Name]
   - What was implemented
   - Libraries used + exact versions
   - Assumptions made (flag each one)
   - What was NOT implemented and why
   - Tests run and results
   - What needs human verification
   ```
4. If you encounter something you are uncertain about, write it explicitly. Do not paper over uncertainty with plausible-looking code.
5. Do not skip error handling. Every cryptographic operation must have explicit failure handling.

---

## PROJECT OVERVIEW

You are rebuilding a Post-Quantum Secure Messaging application from its current v1.0 state into a production-grade, academically rigorous, visually impressive v2.0.

### Current State (v1.0) — What exists:
- Flask + Flask-SocketIO backend
- Client-to-server encryption (NOT end-to-end)
- Hybrid Kyber512 + ECDHE P-256 key exchange
- HKDF-SHA256 key derivation
- AES-256-GCM message encryption
- liboqs-python (backend) + liboqs-wasm (frontend)
- In-memory user store
- Basic Crypto Terminal Panel in frontend

### Target State (v2.0) — What you will build:
A true end-to-end encrypted messenger with post-quantum cryptography, forward secrecy, digital signatures, a quantum attack simulator, and a professional UI.

---

## PART 1 — CRYPTOGRAPHIC ARCHITECTURE OVERHAUL

### 1.1 Fix the Core Security Problem: Implement True E2EE

**Current problem:** Server decrypts every message. This is NOT end-to-end encryption.

**Solution:** Client-to-client key exchange, server is a blind relay.

**Implementation steps — do them in this exact order:**

#### Step A: Long-term Identity Keys (Per User)
Each user gets a permanent identity keypair generated on registration and stored in the browser (localStorage or IndexedDB):

```
Identity Key = Dilithium3 keypair (ML-DSA, FIPS 204)
  - Private key: stays in browser ONLY, never sent to server
  - Public key: registered with server on first login
```

Use `liboqs-wasm` in the browser for Dilithium3. Verify this is available in the liboqs-wasm build before implementing — report what algorithms are exposed.

#### Step B: Ephemeral Session Keys (Per Conversation)
When Alice wants to talk to Bob:

```
Alice generates:
  - Ephemeral Kyber768 keypair (NOT 512 — use 768)
  - Ephemeral ECDHE keypair (P-256 via WebCrypto API)

Alice sends to server (encrypted, signed):
  - Her Kyber768 public key
  - Her ECDHE public key
  - Her Dilithium3 signature over both keys
  - Timestamp (for replay protection)

Server:
  - Validates Dilithium3 signature against Alice's registered public key
  - Forwards the bundle to Bob (does NOT decrypt anything)
  - Server NEVER generates crypto keys itself anymore

Bob receives Alice's bundle:
  - Verifies Alice's Dilithium3 signature
  - Generates his own ephemeral Kyber768 + ECDHE keypairs
  - Performs Kyber768 encapsulation using Alice's public key
  - Performs ECDHE shared secret computation
  - Runs HKDF to derive shared AES-256-GCM session key
  - Sends his public keys + Kyber ciphertext back to Alice (signed)

Alice:
  - Verifies Bob's signature
  - Performs Kyber768 decapsulation
  - Performs ECDHE
  - Runs same HKDF → arrives at identical AES-256-GCM session key
```

**HKDF construction — implement exactly this:**
```python
# ikm = kyber_shared_secret || ecdhe_shared_secret
# salt = SHA256(alice_kyber_pubkey || bob_kyber_pubkey)
# info = b"PQChat-v2-session-key"
# length = 32 bytes
```

Report: Does liboqs-python's Kyber768 KEM return the shared secret as bytes? Confirm the exact method call.

#### Step C: Server Role After E2EE
Server only:
- Stores registered public identity keys (Dilithium3 public keys only)
- Routes encrypted blobs between connected sockets
- Validates that message sender socket matches claimed identity
- Maintains online/offline user registry
- Never touches private keys, shared secrets, or plaintext

---

### 1.2 Implement Double Ratchet for Forward Secrecy

After the initial handshake establishes a root key, implement a simplified Double Ratchet:

**This is complex — implement it carefully and report at each sub-step.**

#### Symmetric Ratchet (simpler, implement this first):
```
root_key = initial HKDF output (32 bytes)

For each message sent:
  new_chain_key, message_key = HKDF(chain_key, b"ratchet-step")
  encrypt message with message_key (AES-256-GCM)
  discard message_key immediately after use
  update chain_key = new_chain_key
```

This gives **forward secrecy**: past message keys cannot be derived from current state.

#### Full Double Ratchet (implement after symmetric ratchet works):
- Add Diffie-Hellman ratchet step every N messages (recommend N=10 for demo)
- Each DH ratchet generates new root key material
- Provides **break-in recovery**: future messages secure even if current state compromised

Use this reference for the exact ratchet construction:
Signal's specification at signal.org/docs/specifications/doubleratchet/

**Do NOT invent your own ratchet construction. Follow the spec exactly or report that you couldn't.**

---

### 1.3 Upgrade Cryptographic Parameters

| Component | Current (v1) | Target (v2) | Library |
|-----------|-------------|-------------|---------|
| PQ KEM | Kyber512 | Kyber768 (ML-KEM-768) | liboqs |
| Classical KEM | ECDHE P-256 | ECDHE P-256 (keep) | WebCrypto / cryptography |
| Signatures | None | Dilithium3 (ML-DSA-65) | liboqs |
| KDF | HKDF-SHA256 | HKDF-SHA256 (keep, fix construction) | cryptography |
| Symmetric | AES-256-GCM | AES-256-GCM (keep) | WebCrypto / cryptography |
| Hash | SHA-256 | SHA-256 (keep) | standard |

**Before implementing:** Verify that liboqs-python exposes `Kyber768` and `Dilithium3` under their exact names. Run:
```python
import oqs
print(oqs.get_enabled_kem_mechanisms())
print(oqs.get_enabled_sig_mechanisms())
```
Report the full output. If algorithm names differ (e.g., `ML-KEM-768` vs `Kyber-768`), use whatever the library actually exposes and document it.

---

### 1.4 Add Key Fingerprint Verification

After handshake, compute and display a safety number:
```python
fingerprint = SHA256(
    alice_dilithium_pubkey + bob_dilithium_pubkey
)[:12]  # 12 bytes = 24 hex chars

# Display as: XXXX XXXX XXXX XXXX XXXX XXXX
# Users compare this out-of-band to detect MITM
```

Show this prominently in the UI. Add a "Mark as Verified" button that persists in localStorage.

---

## PART 2 — QUANTUM ATTACK SIMULATOR MODULE

This is a standalone module that runs alongside the chat. It is PURELY EDUCATIONAL — it simulates attacks, not executes them.

### 2.1 Module Structure

Create: `simulator/quantum_attack_simulator.py`
Create: `static/js/attack_simulator.js`
Create: `templates/simulator.html` or integrate as a panel

### 2.2 Simulation 1: Shor's Algorithm on Small ECDH Keys

```python
# File: simulator/shors_simulation.py

import math
import time
from fractions import Fraction

def simulate_shors_period_finding(N: int, a: int = 2) -> dict:
    """
    Classically simulate the period-finding subroutine of Shor's algorithm.
    
    In a real quantum computer, this step uses the Quantum Fourier Transform (QFT)
    and runs in O(log^3 N) time. Here we brute-force it classically to demonstrate
    the LOGIC, not the speedup.
    
    Args:
        N: The number to factor (simulates RSA/ECDH modulus)
        a: Base for modular exponentiation (must be coprime to N)
    
    Returns:
        dict with period, factors, steps, time_taken
    """
    
    report = {
        "N": N,
        "a": a,
        "steps": [],
        "success": False,
        "factors": None,
        "period": None,
        "time_taken": None,
        "quantum_note": ""
    }
    
    start = time.perf_counter()
    
    # Verify gcd(a, N) == 1
    if math.gcd(a, N) != 1:
        report["steps"].append(f"gcd({a}, {N}) = {math.gcd(a, N)} ≠ 1, pick different a")
        return report
    
    report["steps"].append(f"Step 1: Pick a={a}, verify gcd({a},{N})=1 ✓")
    report["steps"].append(f"Step 2: [QUANTUM] Apply QFT to find period of f(x) = {a}^x mod {N}")
    report["steps"].append(f"Step 2: [CLASSICAL SIM] Brute-forcing period (exponentially slower)...")
    
    # Find period r: smallest r > 0 such that a^r ≡ 1 (mod N)
    r = None
    for x in range(1, N * N):  # cap search
        if pow(a, x, N) == 1:
            r = x
            break
    
    if r is None:
        report["steps"].append("Period not found in search range")
        return report
    
    report["period"] = r
    report["steps"].append(f"Step 3: Period found: r = {r}")
    
    if r % 2 != 0:
        report["steps"].append(f"r={r} is odd — retry with different a")
        return report
    
    # Extract factors
    factor1 = math.gcd(pow(a, r // 2) - 1, N)
    factor2 = math.gcd(pow(a, r // 2) + 1, N)
    
    report["steps"].append(f"Step 4: Compute gcd({a}^(r/2) ± 1, {N})")
    report["steps"].append(f"Step 5: Factors = {factor1} × {factor2}")
    
    if factor1 * factor2 == N and factor1 > 1 and factor2 > 1:
        report["success"] = True
        report["factors"] = (factor1, factor2)
        report["steps"].append(f"✅ FACTORED: {N} = {factor1} × {factor2}")
        report["steps"].append(f"🔑 ECDH private key can now be computed from public key!")
    
    report["time_taken"] = time.perf_counter() - start
    report["quantum_note"] = (
        f"A quantum computer would solve this in O(log³({N})) ≈ "
        f"{int(math.log2(N)**3)} quantum operations using QFT. "
        f"Classical simulation took {report['time_taken']:.4f}s using brute force."
    )
    
    return report


def extrapolate_to_p256() -> dict:
    """
    Extrapolate Shor's attack to P-256 ECDH scale.
    Do NOT attempt to actually run this — compute estimates only.
    """
    p256_bits = 256
    
    return {
        "target": "ECDHE P-256 (your current classical key exchange)",
        "classical_security_bits": 128,
        "shor_quantum_ops": f"O(log³(2^{p256_bits})) ≈ O({p256_bits}³) = O({p256_bits**3:,}) quantum gates",
        "logical_qubits_needed": "~2,000–4,000 error-corrected logical qubits",
        "physical_qubits_needed": "~1,000,000+ physical qubits (due to error correction overhead)",
        "current_best_quantum_hw": "~1,121 superconducting qubits (IBM Condor, 2023) — noisy, not error-corrected",
        "verdict": "VULNERABLE IN PRINCIPLE — not breakable today but will be",
        "protection": "Your Kyber768 hybrid exchange protects against this"
    }
```

### 2.3 Simulation 2: BKZ Lattice Attack on Kyber

```python
# File: simulator/lattice_attack_simulator.py
import numpy as np
import time
import math

def simulate_lwe_instance(n: int, q: int, noise_std: float = 1.0, seed: int = 42):
    """
    Generate an LWE (Learning With Errors) instance matching Kyber parameters.
    LWE is the mathematical hard problem underlying Kyber/ML-KEM.
    
    LWE problem: Given (A, b = A*s + e mod q), find secret s
    where e is a small noise vector.
    """
    rng = np.random.default_rng(seed)
    A = rng.integers(0, q, size=(n, n))
    s = rng.integers(-2, 3, size=n)   # small secret: coefficients in {-2,-1,0,1,2}
    e = rng.integers(-1, 2, size=n)   # small error: coefficients in {-1,0,1}
    b = (A @ s + e) % q
    return A, b, s, e


def simulate_bkz_attack(n: int, q: int, label: str) -> dict:
    """
    Simulate a BKZ (Block Korkine-Zolotarev) lattice reduction attack.
    BKZ is the best known classical AND quantum attack on LWE-based systems.
    
    We do NOT actually run BKZ (it requires specialized libraries like fpylll).
    We compute the ESTIMATED complexity and simulate the failure to find the secret.
    """
    
    # Hermite factor for BKZ-beta attack on LWE
    # Based on: "Estimating quantum speedups for lattice sieves"
    # Classical BKZ core SVP hardness: 2^(0.292 * beta)
    # Required beta to solve LWE with these params (rough estimate):
    beta_classical = int(0.265 * n)   # rough BKZ block size needed
    beta_quantum = int(0.212 * n)     # quantum sieve speedup (sqrt via Grover)
    
    classical_ops = 2 ** (0.292 * beta_classical)
    quantum_ops = 2 ** (0.265 * beta_quantum)   # quantum BKZ has ~0.265 exponent
    
    result = {
        "label": label,
        "parameters": {"n": n, "q": q},
        "attack_type": "BKZ lattice reduction (best known classical+quantum attack on LWE)",
        "classical_complexity": f"2^{0.292 * beta_classical:.1f} ≈ {classical_ops:.2e} operations",
        "quantum_complexity": f"2^{0.265 * beta_quantum:.1f} ≈ {quantum_ops:.2e} operations",
        "universe_age_ops": "~10^26 quantum operations (rough upper bound)",
        "verdict": "",
        "secret_recovered": False
    }
    
    if n < 20:
        # Toy: actually attempt brute force for small n
        A, b, s, e = simulate_lwe_instance(n, q)
        start = time.perf_counter()
        found_s = None
        for _ in range(min(10000, q**min(n, 3))):
            guess = np.random.randint(-2, 3, size=n)
            residual = (b - A @ guess) % q
            if np.all(np.minimum(residual, q - residual) <= 2):
                found_s = guess
                break
        elapsed = time.perf_counter() - start
        
        if found_s is not None:
            result["verdict"] = f"❌ TOY PARAMETERS BROKEN in {elapsed:.3f}s — DO NOT USE IN PRODUCTION"
            result["secret_recovered"] = True
            result["elapsed"] = elapsed
        else:
            result["verdict"] = "⚠️ Not found (toy params, heuristic guesser — increase iterations)"
    else:
        # Real params: just report infeasibility
        result["verdict"] = (
            f"✅ INFEASIBLE — Kyber768 (n={n}, q={q}) requires ~2^"
            f"{0.265 * beta_quantum:.0f} quantum operations. "
            f"No known quantum algorithm can do better."
        )
        result["secret_recovered"] = False
    
    return result


def run_full_comparison():
    """Run attack simulations across toy and real parameters. Return structured report."""
    
    scenarios = [
        {"n": 8,   "q": 17,   "label": "Toy LWE (n=8)  — for demonstration only"},
        {"n": 16,  "q": 97,   "label": "Small LWE (n=16) — still attackable"},
        {"n": 256, "q": 3329, "label": "Kyber512 (n=256, q=3329) — NIST level 1"},
        {"n": 256, "q": 3329, "label": "Kyber768 (n=256×3 modules, q=3329) — NIST level 3"},
        # Note: Kyber768 uses k=3 modules of n=256 — total effective n=768
        # Adjust if your LWE estimator handles modules correctly
    ]
    
    return [simulate_bkz_attack(s["n"], s["q"], s["label"]) for s in scenarios]
```

**VERIFY:** Check that the BKZ complexity estimates align with the LWE hardness estimator at `https://lwe-estimator.readthedocs.io`. Do not rely solely on the formulas above — report any discrepancies.

### 2.4 Simulation 3: Grover's Attack on AES-256

```python
# File: simulator/grovers_simulation.py

def analyze_grovers_impact() -> list:
    """
    Analyze Grover's algorithm impact on symmetric key sizes.
    Grover's provides quadratic speedup on unstructured search.
    For a k-bit key: classical = 2^k ops, quantum = 2^(k/2) ops.
    """
    
    results = []
    
    algorithms = [
        {"name": "AES-128", "key_bits": 128, "used_in_project": False},
        {"name": "AES-256 (your session key)", "key_bits": 256, "used_in_project": True},
        {"name": "SHA-256 (collision)", "key_bits": 128, "used_in_project": True,
         "note": "Birthday attack: classical=2^128, quantum=2^85 (BHT algorithm)"},
        {"name": "HMAC-SHA256", "key_bits": 256, "used_in_project": True},
    ]
    
    for alg in algorithms:
        k = alg["key_bits"]
        classical_security = k
        grover_security = k // 2
        
        # NIST recommends 128-bit post-quantum security minimum
        pq_safe = grover_security >= 128
        
        results.append({
            "algorithm": alg["name"],
            "key_bits": k,
            "classical_security": f"2^{classical_security} operations",
            "quantum_security_grover": f"2^{grover_security} operations",
            "post_quantum_safe": pq_safe,
            "verdict": (
                "✅ Post-quantum secure (≥128-bit quantum security)" 
                if pq_safe 
                else "⚠️ Upgrade key size for post-quantum security"
            ),
            "used_in_project": alg.get("used_in_project", False),
            "note": alg.get("note", "")
        })
    
    return results
```

### 2.5 Flask Routes for Simulator

Add to `app.py`:

```python
from simulator.shors_simulation import simulate_shors_period_finding, extrapolate_to_p256
from simulator.lattice_attack_simulator import run_full_comparison
from simulator.grovers_simulation import analyze_grovers_impact

@app.route('/api/simulate/shors', methods=['POST'])
def api_shors():
    data = request.json
    N = data.get('N', 15)
    if N > 10000:
        return jsonify({"error": "N too large for demo — use N ≤ 10000"}), 400
    result = simulate_shors_period_finding(N)
    extrapolation = extrapolate_to_p256()
    return jsonify({"simulation": result, "p256_extrapolation": extrapolation})

@app.route('/api/simulate/lattice', methods=['GET'])
def api_lattice():
    return jsonify(run_full_comparison())

@app.route('/api/simulate/grover', methods=['GET'])
def api_grover():
    return jsonify(analyze_grovers_impact())
```

---

## PART 3 — BACKEND OVERHAUL

### 3.1 Project Structure (v2.0)

```
pqchat-v2/
├── app.py                        # Main Flask application
├── requirements.txt              # Pinned dependencies
├── config.py                     # Configuration constants
│
├── auth/
│   ├── __init__.py
│   ├── users.py                  # User store (upgrade to SQLite)
│   └── tokens.py                 # Token generation and validation
│
├── crypto/
│   ├── __init__.py
│   ├── kyber.py                  # Kyber768 KEM wrapper
│   ├── dilithium.py              # Dilithium3 signature wrapper
│   ├── ecdhe.py                  # ECDHE P-256 wrapper
│   ├── hkdf.py                   # HKDF construction
│   └── ratchet.py                # Double ratchet implementation
│
├── simulator/
│   ├── __init__.py
│   ├── shors_simulation.py
│   ├── lattice_attack_simulator.py
│   └── grovers_simulation.py
│
├── static/
│   ├── js/
│   │   ├── crypto_client.js      # Core PQ crypto in browser
│   │   ├── ratchet_client.js     # Client-side ratchet
│   │   ├── attack_simulator.js   # Simulator UI logic
│   │   └── ui.js                 # UI interactions
│   ├── css/
│   │   └── style.css             # All styles (see Part 4)
│   └── wasm/
│       └── liboqs.js             # liboqs-wasm bundle
│
├── templates/
│   ├── login.html
│   ├── chat.html                 # Main chat + crypto panel
│   └── simulator.html            # Quantum attack simulator page
│
└── tests/
    ├── test_crypto.py
    ├── test_ratchet.py
    └── test_e2ee_flow.py
```

### 3.2 User Store Upgrade

Replace in-memory dict with SQLite via `sqlite3` (no new dependencies):

```python
# auth/users.py

import sqlite3
import hashlib
import os
import secrets

DB_PATH = "users.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                dilithium_public_key BLOB,       -- registered PQ identity key
                ecdh_identity_public_key BLOB,   -- registered classical identity key
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        conn.commit()

def register_user(username: str, password: str) -> bool:
    salt = secrets.token_hex(32)
    password_hash = hashlib.scrypt(
        password.encode(),
        salt=salt.encode(),
        n=2**14, r=8, p=1,
        dklen=64
    ).hex()
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt)
            )
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username taken

def verify_password(username: str, password: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM users WHERE username = ?",
            (username,)
        ).fetchone()
    
    if not row:
        return False
    
    stored_hash, salt = row
    computed = hashlib.scrypt(
        password.encode(),
        salt=salt.encode(),
        n=2**14, r=8, p=1,
        dklen=64
    ).hex()
    
    return secrets.compare_digest(stored_hash, computed)

def register_public_key(username: str, dilithium_pubkey: bytes, ecdh_pubkey: bytes):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET dilithium_public_key=?, ecdh_identity_public_key=? WHERE username=?",
            (dilithium_pubkey, ecdh_pubkey, username)
        )
        conn.commit()

def get_public_keys(username: str) -> dict | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT dilithium_public_key, ecdh_identity_public_key FROM users WHERE username=?",
            (username,)
        ).fetchone()
    
    if not row or not row[0]:
        return None
    
    return {
        "dilithium_public_key": row[0].hex(),
        "ecdh_identity_public_key": row[1].hex() if row[1] else None
    }
```

### 3.3 Crypto Wrappers

```python
# crypto/kyber.py
# VERIFY: Run the verification block before implementing anything else

import oqs

# VERIFICATION — run this first and report output:
def verify_kyber_availability():
    available = oqs.get_enabled_kem_mechanisms()
    kyber768_names = [name for name in available if '768' in name or 'ML-KEM-768' in name]
    return {
        "all_available_kems": available,
        "kyber768_candidates": kyber768_names,
        "recommended": kyber768_names[0] if kyber768_names else "NOT FOUND — REPORT THIS"
    }

# Set this AFTER running verify_kyber_availability():
KYBER_ALG = "Kyber768"   # adjust to actual name from verification above

class KyberKEM:
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Returns (public_key, secret_key) as bytes."""
        with oqs.KeyEncapsulation(KYBER_ALG) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return public_key, secret_key
    
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret) as bytes."""
        with oqs.KeyEncapsulation(KYBER_ALG) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Returns shared_secret as bytes."""
        with oqs.KeyEncapsulation(KYBER_ALG, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
```

```python
# crypto/dilithium.py
# VERIFY: Check exact algorithm name in liboqs

import oqs

DILITHIUM_ALG = "Dilithium3"   # verify with oqs.get_enabled_sig_mechanisms()

class DilithiumSigner:
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Returns (public_key, secret_key) as bytes."""
        with oqs.Signature(DILITHIUM_ALG) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        return public_key, secret_key
    
    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Returns signature as bytes."""
        with oqs.Signature(DILITHIUM_ALG, secret_key=secret_key) as signer:
            signature = signer.sign(message)
        return signature
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Returns True if valid, False otherwise. Never raises on invalid sig."""
        try:
            with oqs.Signature(DILITHIUM_ALG) as verifier:
                return verifier.verify(message, signature, public_key)
        except Exception:
            return False
```

```python
# crypto/hkdf.py

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hashlib

def derive_session_key(
    kyber_secret: bytes,
    ecdhe_secret: bytes,
    alice_kyber_pubkey: bytes,
    bob_kyber_pubkey: bytes
) -> bytes:
    """
    Derive a 32-byte AES-256 session key from two shared secrets.
    
    Construction:
    - IKM = kyber_secret || ecdhe_secret
    - Salt = SHA256(alice_kyber_pubkey || bob_kyber_pubkey)
    - Info = b"PQChat-v2-session-key"
    - Length = 32 bytes
    """
    ikm = kyber_secret + ecdhe_secret
    salt = hashlib.sha256(alice_kyber_pubkey + bob_kyber_pubkey).digest()
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"PQChat-v2-session-key"
    )
    
    return hkdf.derive(ikm)


def derive_ratchet_keys(chain_key: bytes, step: int) -> tuple[bytes, bytes]:
    """
    Derive next chain key and message key from current chain key.
    Returns (new_chain_key, message_key).
    """
    hkdf_chain = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQChat-v2-chain-key-" + step.to_bytes(4, 'big')
    )
    hkdf_msg = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PQChat-v2-message-key-" + step.to_bytes(4, 'big')
    )
    
    new_chain_key = hkdf_chain.derive(chain_key)
    message_key = hkdf_msg.derive(chain_key)
    
    return new_chain_key, message_key
```

### 3.4 Socket.IO Event Redesign

The server is now a **blind relay**. Rewrite socket events:

```python
# In app.py — Socket.IO events

@socketio.on('register_identity')
def handle_register_identity(data):
    """
    Client registers their Dilithium public key after login.
    Server stores it for future verification.
    """
    username = get_username_from_token(data.get('token'))
    if not username:
        emit('error', {'message': 'Unauthorized'})
        return
    
    dilithium_pubkey = bytes.fromhex(data['dilithium_public_key'])
    ecdh_pubkey = bytes.fromhex(data.get('ecdh_identity_public_key', ''))
    
    register_public_key(username, dilithium_pubkey, ecdh_pubkey)
    emit('identity_registered', {'status': 'ok'})


@socketio.on('handshake_init')
def handle_handshake_init(data):
    """
    Alice sends her ephemeral public keys to Bob.
    Server ONLY validates signature and forwards — does NOT participate in crypto.
    """
    sender = get_username_from_token(data.get('token'))
    if not sender:
        emit('error', {'message': 'Unauthorized'})
        return
    
    target = data.get('target_user')
    
    # Validate Alice's Dilithium signature over her ephemeral keys
    sender_keys = get_public_keys(sender)
    if not sender_keys:
        emit('error', {'message': 'Sender identity not registered'})
        return
    
    dilithium_pubkey = bytes.fromhex(sender_keys['dilithium_public_key'])
    
    # Message to verify = kyber_pubkey || ecdhe_pubkey || timestamp
    signed_payload = bytes.fromhex(data['kyber_ephemeral_pubkey']) + \
                     bytes.fromhex(data['ecdhe_ephemeral_pubkey']) + \
                     data['timestamp'].encode()
    
    signature = bytes.fromhex(data['signature'])
    
    signer = DilithiumSigner()
    if not signer.verify(dilithium_pubkey, signed_payload, signature):
        emit('error', {'message': 'Invalid handshake signature — possible MITM'})
        return
    
    # Forward to target — server never touches the key material
    target_sid = get_socket_id_for_user(target)
    if target_sid:
        emit('handshake_request', {
            'from': sender,
            'kyber_ephemeral_pubkey': data['kyber_ephemeral_pubkey'],
            'ecdhe_ephemeral_pubkey': data['ecdhe_ephemeral_pubkey'],
            'timestamp': data['timestamp'],
            'signature': data['signature']
        }, to=target_sid)
    else:
        emit('error', {'message': f'{target} is offline'})


@socketio.on('send_message')
def handle_send_message(data):
    """
    Server receives an encrypted blob and forwards it.
    Server CANNOT decrypt this — it only knows sender, recipient, and ciphertext.
    """
    sender = get_username_from_token(data.get('token'))
    if not sender:
        emit('error', {'message': 'Unauthorized'})
        return
    
    target = data.get('target_user')
    
    # All server sees:
    encrypted_payload = {
        'from': sender,
        'nonce': data['nonce'],           # AES-GCM nonce
        'ciphertext': data['ciphertext'], # Encrypted message
        'tag': data['tag'],               # AES-GCM auth tag
        'ratchet_step': data.get('ratchet_step', 0),  # For key derivation sync
        'signature': data.get('signature', ''),  # Dilithium sig over nonce+ciphertext
    }
    
    # Optionally verify message signature (prevents spoofing)
    # Server can verify without decrypting
    
    target_sid = get_socket_id_for_user(target)
    if target_sid:
        emit('receive_message', encrypted_payload, to=target_sid)
    else:
        emit('error', {'message': f'{target} is offline'})
```

---

## PART 4 — FRONTEND OVERHAUL

### 4.1 UI Design Specification

Design language: **Cyberpunk Terminal / Secure Operations Center**

- Background: Deep black (`#050508`) with subtle dark blue grain texture
- Primary accent: Electric cyan (`#00f5ff`)
- Secondary accent: Phosphor green (`#00ff88`)
- Danger/attack: Neon red (`#ff2244`)
- Warning: Amber (`#ffaa00`)
- Font (headings): `JetBrains Mono` or `IBM Plex Mono` (monospace, technical)
- Font (body): `Inter` or `Geist`
- All crypto data displayed in monospace
- Glowing borders: `box-shadow: 0 0 8px #00f5ff40`
- Scanline overlay effect on crypto panels

### 4.2 Layout: Three-Panel Chat Interface

```
┌─────────────────────────────────────────────────────────────┐
│  🔐 PQChat v2.0          [QUANTUM-SAFE] [E2EE] [CONNECTED] │
├────────────┬────────────────────────┬────────────────────────┤
│            │                        │  CRYPTO TERMINAL       │
│  CONTACTS  │   CHAT WINDOW          │  ─────────────────     │
│  ────────  │   ──────────           │  Session Key: [hex]    │
│  ● Alice   │   Alice: [msg]         │  Ratchet Step: 7       │
│  ○ Bob     │   Bob:   [msg]         │  Algorithm: Kyber768   │
│            │                        │  Signature: Dilithium3 │
│  [Keys]    │   [type message...]    │  Fingerprint: [short]  │
│            │   [SEND] [🔐 keys]     │  [VERIFIED ✓]          │
│            │                        │  ─────────────────     │
│            │                        │  [LIVE LOG]            │
│            │                        │  > Ratchet advanced    │
│            │                        │  > Sig verified ✓      │
└────────────┴────────────────────────┴────────────────────────┘
```

### 4.3 Frontend Crypto Client (Key Parts)

```javascript
// static/js/crypto_client.js

class PQChatClient {
    constructor() {
        this.oqs = null;           // liboqs-wasm instance
        this.identityKeypair = null; // Dilithium3 long-term keys
        this.sessionKeys = {};     // Per-conversation session state
        this.ratchetState = {};    // Per-conversation ratchet state
        this.log = [];             // Crypto terminal log
    }

    async initialize() {
        // Load liboqs-wasm
        // VERIFY: Exact import method depends on liboqs-wasm build
        // Check the liboqs-wasm README for correct initialization
        this.oqs = await OQS.init();  // VERIFY this method name
        this.logEvent("liboqs-wasm initialized");
        
        // Load or generate identity keys
        await this.loadOrGenerateIdentityKeys();
    }

    async loadOrGenerateIdentityKeys() {
        const stored = localStorage.getItem('pqchat_identity');
        
        if (stored) {
            this.identityKeypair = JSON.parse(stored);
            this.logEvent("Identity keys loaded from storage");
        } else {
            // Generate Dilithium3 keypair
            // VERIFY: Exact API for Dilithium3 in liboqs-wasm
            const sig = new this.oqs.Signature("Dilithium3");  // VERIFY
            const pubkey = sig.generate_keypair();              // VERIFY method name
            const seckey = sig.export_secret_key();            // VERIFY method name
            
            this.identityKeypair = {
                publicKey: bufferToHex(pubkey),
                secretKey: bufferToHex(seckey)
            };
            
            localStorage.setItem('pqchat_identity', JSON.stringify({
                publicKey: this.identityKeypair.publicKey
                // WARNING: Storing secret key in localStorage is NOT production-safe
                // For a real app use WebAuthn / hardware key
                // For this demo it is acceptable — document this limitation
            }));
            
            this.logEvent("New Dilithium3 identity keypair generated");
            this.logEvent(`Public key: ${this.identityKeypair.publicKey.substring(0, 32)}...`);
        }
    }

    async performHandshake(targetUser) {
        this.logEvent(`Initiating PQ handshake with ${targetUser}...`);
        
        // 1. Generate ephemeral Kyber768 keypair
        const kem = new this.oqs.KeyEncapsulation("Kyber768");  // VERIFY
        const kyberPubkey = kem.generate_keypair();              // VERIFY
        const kyberSeckey = kem.export_secret_key();            // VERIFY
        
        // 2. Generate ephemeral ECDHE P-256 keypair via WebCrypto
        const ecdhKeypair = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey", "deriveBits"]
        );
        const ecdhPubkeyRaw = await crypto.subtle.exportKey("raw", ecdhKeypair.publicKey);
        
        // 3. Sign both public keys with Dilithium identity key
        const timestamp = Date.now().toString();
        const payload = hexToBuffer(bufferToHex(kyberPubkey))
            .concat(new Uint8Array(ecdhPubkeyRaw))
            .concat(new TextEncoder().encode(timestamp));
        
        const sig = new this.oqs.Signature("Dilithium3");  // VERIFY
        // VERIFY: How to init signer with existing secret key in liboqs-wasm
        const signature = sig.sign(payload, hexToBuffer(this.identityKeypair.secretKey));
        
        // Store ephemeral keys for when handshake response arrives
        this.sessionKeys[targetUser] = {
            kyberSeckey: bufferToHex(kyberSeckey),
            ecdhPrivateKey: ecdhKeypair.privateKey,
            status: 'pending'
        };
        
        this.logEvent(`Kyber768 pubkey: ${bufferToHex(kyberPubkey).substring(0, 32)}...`);
        this.logEvent(`ECDHE P-256 pubkey generated`);
        this.logEvent(`Dilithium3 signature: ${bufferToHex(signature).substring(0, 32)}...`);
        
        // 4. Send to server (which forwards to target)
        socket.emit('handshake_init', {
            token: authToken,
            target_user: targetUser,
            kyber_ephemeral_pubkey: bufferToHex(kyberPubkey),
            ecdhe_ephemeral_pubkey: bufferToHex(new Uint8Array(ecdhPubkeyRaw)),
            timestamp: timestamp,
            signature: bufferToHex(signature)
        });
    }

    async receiveHandshake(data) {
        this.logEvent(`Received handshake from ${data.from}`);
        
        // 1. Fetch sender's registered Dilithium public key from server
        const senderKeys = await fetchPublicKeys(data.from);
        
        // 2. Verify signature
        const payload = hexToBuffer(data.kyber_ephemeral_pubkey)
            .concat(hexToBuffer(data.ecdhe_ephemeral_pubkey))
            .concat(new TextEncoder().encode(data.timestamp));
        
        const verifier = new this.oqs.Signature("Dilithium3");  // VERIFY
        const valid = verifier.verify(payload, hexToBuffer(data.signature), hexToBuffer(senderKeys.dilithium_public_key));
        
        if (!valid) {
            this.logEvent(`❌ INVALID SIGNATURE from ${data.from} — possible MITM attack!`);
            showSecurityAlert(`Handshake from ${data.from} has an invalid signature!`);
            return;
        }
        
        this.logEvent(`✅ Dilithium3 signature verified for ${data.from}`);
        
        // 3. Kyber768 encapsulation
        const kem = new this.oqs.KeyEncapsulation("Kyber768");  // VERIFY
        const [ciphertext, kyberSecret] = kem.encap_secret(hexToBuffer(data.kyber_ephemeral_pubkey));  // VERIFY
        
        // 4. ECDHE P-256
        const theirECDHPubkey = await crypto.subtle.importKey(
            "raw",
            hexToBuffer(data.ecdhe_ephemeral_pubkey),
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );
        const myECDH = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveBits"]
        );
        const ecdhSecret = await crypto.subtle.deriveBits(
            { name: "ECDH", public: theirECDHPubkey },
            myECDH.privateKey,
            256
        );
        
        // 5. HKDF to derive session key
        const sessionKey = await deriveSessionKey(
            kyberSecret,
            new Uint8Array(ecdhSecret),
            hexToBuffer(data.kyber_ephemeral_pubkey),
            // Bob's kyber pubkey — need to generate and include
        );
        
        this.logEvent(`🔑 Session key derived: ${bufferToHex(sessionKey).substring(0, 16)}...`);
        
        // Store session state + init ratchet
        this.sessionKeys[data.from] = {
            sessionKey: sessionKey,
            status: 'established'
        };
        this.initRatchet(data.from, sessionKey);
        
        // Send response back
        // (Include Bob's ephemeral pubkeys + kyber ciphertext + signature)
        await this.sendHandshakeResponse(data.from, ciphertext, myECDH.publicKey);
    }

    async encryptMessage(targetUser, plaintext) {
        const ratchet = this.ratchetState[targetUser];
        if (!ratchet) throw new Error("No ratchet state for " + targetUser);
        
        // Advance ratchet — get message key
        const [newChainKey, messageKey] = await advanceRatchet(ratchet.chainKey, ratchet.step);
        ratchet.chainKey = newChainKey;
        ratchet.step++;
        
        // Import message key for AES-GCM
        const cryptoKey = await crypto.subtle.importKey(
            "raw", messageKey, { name: "AES-GCM" }, false, ["encrypt"]
        );
        
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);
        
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce },
            cryptoKey,
            encoded
        );
        
        this.logEvent(`Message encrypted (ratchet step ${ratchet.step})`);
        
        return {
            nonce: bufferToHex(nonce),
            ciphertext: bufferToHex(new Uint8Array(ciphertext)),
            ratchet_step: ratchet.step
        };
    }
}
```

---

## PART 5 — QUANTUM ATTACK SIMULATOR UI

### 5.1 Simulator Page Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  ⚛  QUANTUM ATTACK SIMULATOR — Educational Mode               │
│  This simulates quantum cryptanalysis. No real attacks occur.  │
├───────────────────────┬─────────────────────────────────────────┤
│  SELECT ATTACK TYPE   │  SIMULATION OUTPUT                      │
│  ─────────────────    │  ────────────────────────────────────── │
│  ○ Shor's on ECDHE    │                                         │
│  ○ BKZ on Kyber768    │  [Attack steps animate here]            │
│  ○ Grover's on AES    │  [Progress bar]                         │
│  ○ Full comparison    │  [Result: BROKEN / SECURE]              │
│                       │                                         │
│  N = [    15    ]     │  [Verdict panel]                        │
│  [RUN SIMULATION]     │  [Extrapolation to real key sizes]      │
│                       │                                         │
│  ─────────────────    │  COMPARISON TABLE                       │
│  YOUR PROJECT'S       │  ┌──────────┬──────────┬──────────┐     │
│  DEFENSE STATUS:      │  │Algorithm │Classical │Quantum   │     │
│                       │  │ECDHE P256│ 2^128   │ BROKEN ✗ │     │
│  ECDHE: ⚠️ VULNERABLE  │  │Kyber768  │ 2^178   │ 2^128 ✓  │     │
│  Kyber: ✅ SECURE      │  │AES-256   │ 2^256   │ 2^128 ✓  │     │
│  Hybrid: ✅ PROTECTED  │  └──────────┴──────────┴──────────┘     │
└───────────────────────┴─────────────────────────────────────────┘
```

### 5.2 Animation: Shor's Attack Visualization

When Shor's simulation runs against ECDHE, animate:
1. Show the target: "ECDHE P-256 Public Key: [hex]"
2. Step-by-step period-finding with progress
3. Show "PRIVATE KEY FOUND" in red for toy params
4. Then show the same attack against Kyber → "NO PERIODIC STRUCTURE — ATTACK FAILS"
5. Show the hybrid protection: "Even though ECDHE is broken, Kyber secret remains unknown — session KEY REMAINS SECURE ✓"

---

## PART 6 — REQUIREMENTS & DEPENDENCIES

### requirements.txt (pin all versions)

```
flask==3.0.3
flask-socketio==5.3.6
python-socketio==5.11.3
python-engineio==4.9.1
cryptography==42.0.8
liboqs-python==0.10.1        # VERIFY this version is available
eventlet==0.36.1
```

VERIFY: Check current liboqs-python version on PyPI before pinning.
Run: `pip index versions liboqs-python` and report.

### Frontend Dependencies (CDN):

```html
<!-- liboqs-wasm — VERIFY exact CDN URL or local bundle -->
<script src="/static/wasm/liboqs.js"></script>

<!-- Socket.IO -->
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>

<!-- JetBrains Mono font -->
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
```

VERIFY: liboqs-wasm may not be available on a CDN — it may need to be bundled locally. Check the liboqs-wasm npm package and report how to correctly bundle it.

---

## PART 7 — TESTING REQUIREMENTS

Write these tests in `tests/`. Do NOT skip testing.

```python
# tests/test_crypto.py

import pytest
from crypto.kyber import KyberKEM
from crypto.dilithium import DilithiumSigner
from crypto.hkdf import derive_session_key

def test_kyber768_roundtrip():
    """Encapsulate and decapsulate — shared secrets must match."""
    kem = KyberKEM()
    pubkey, seckey = kem.generate_keypair()
    ciphertext, shared_secret_enc = kem.encapsulate(pubkey)
    shared_secret_dec = kem.decapsulate(seckey, ciphertext)
    assert shared_secret_enc == shared_secret_dec, "Kyber shared secrets don't match"

def test_dilithium3_sign_verify():
    """Sign and verify a message — must succeed."""
    signer = DilithiumSigner()
    pubkey, seckey = signer.generate_keypair()
    message = b"test handshake payload"
    signature = signer.sign(seckey, message)
    assert signer.verify(pubkey, message, signature), "Valid signature rejected"

def test_dilithium3_tamper_detection():
    """Tampered message must fail verification."""
    signer = DilithiumSigner()
    pubkey, seckey = signer.generate_keypair()
    message = b"original message"
    signature = signer.sign(seckey, message)
    tampered = b"tampered message"
    assert not signer.verify(pubkey, tampered, signature), "Tampered message accepted"

def test_hkdf_determinism():
    """Same inputs must produce same key."""
    key1 = derive_session_key(b"a"*32, b"b"*32, b"c"*100, b"d"*100)
    key2 = derive_session_key(b"a"*32, b"b"*32, b"c"*100, b"d"*100)
    assert key1 == key2

def test_hkdf_different_inputs():
    """Different inputs must produce different keys."""
    key1 = derive_session_key(b"a"*32, b"b"*32, b"c"*100, b"d"*100)
    key2 = derive_session_key(b"x"*32, b"b"*32, b"c"*100, b"d"*100)
    assert key1 != key2

def test_full_e2ee_handshake():
    """Simulate a full Alice-Bob handshake and verify shared key matches."""
    # This is the most important integration test
    # Alice side
    alice_kem = KyberKEM()
    alice_kyber_pub, alice_kyber_sec = alice_kem.generate_keypair()
    
    # Bob encapsulates
    bob_kem = KyberKEM()
    ciphertext, bob_shared_secret = bob_kem.encapsulate(alice_kyber_pub)
    
    # Alice decapsulates
    alice_shared_secret = alice_kem.decapsulate(alice_kyber_sec, ciphertext)
    
    assert alice_shared_secret == bob_shared_secret, "E2EE handshake failed — secrets don't match"
```

---

## PART 8 — IMPLEMENTATION ORDER

Follow this exact order. Do not jump ahead. Report checkpoint after each:

```
Phase 1 — Foundation (do first, everything depends on this)
  [ ] 1.1 Verify liboqs availability (run verification block, report output)
  [ ] 1.2 Implement crypto/ wrappers (kyber.py, dilithium.py, hkdf.py)
  [ ] 1.3 Run and pass all tests in test_crypto.py
  [ ] CHECKPOINT REPORT 1

Phase 2 — Backend
  [ ] 2.1 Upgrade auth/users.py to SQLite
  [ ] 2.2 Rewrite Socket.IO events for blind relay
  [ ] 2.3 Add /api/keys endpoint for public key lookup
  [ ] CHECKPOINT REPORT 2

Phase 3 — Simulator
  [ ] 3.1 Implement shors_simulation.py
  [ ] 3.2 Implement lattice_attack_simulator.py
  [ ] 3.3 Implement grovers_simulation.py
  [ ] 3.4 Add Flask routes for simulator
  [ ] CHECKPOINT REPORT 3

Phase 4 — Frontend Crypto
  [ ] 4.1 Verify liboqs-wasm algorithms available
  [ ] 4.2 Implement identity key generation
  [ ] 4.3 Implement handshake (PQChatClient class)
  [ ] 4.4 Implement ratchet
  [ ] 4.5 Implement encrypt/decrypt
  [ ] CHECKPOINT REPORT 4

Phase 5 — UI
  [ ] 5.1 Implement three-panel chat layout
  [ ] 5.2 Implement Crypto Terminal Panel with live logging
  [ ] 5.3 Implement fingerprint display + verification button
  [ ] 5.4 Implement Quantum Attack Simulator page
  [ ] CHECKPOINT REPORT 5

Phase 6 — Integration & Testing
  [ ] 6.1 End-to-end test: Alice sends message, Bob decrypts
  [ ] 6.2 Test ratchet: 20 messages, verify each decrypts
  [ ] 6.3 Test signature rejection on tampered handshake
  [ ] 6.4 Test simulator endpoints
  [ ] FINAL REPORT
```

---

## PART 9 — KNOWN RISKS TO WATCH FOR

Report immediately if you encounter any of these:

1. **liboqs-wasm algorithm availability** — not all liboqs algorithms are compiled into the WASM build. Dilithium3 and Kyber768 may need to be verified.

2. **liboqs-python secret key re-import** — the pattern `oqs.KeyEncapsulation(alg, secret_key=sk)` for decapsulation may differ between versions. Verify exact API.

3. **WebCrypto ECDHE + liboqs-wasm key ordering** — the HKDF must use the same key ordering on both Alice and Bob sides. A bug here produces different session keys silently.

4. **Double ratchet message ordering** — out-of-order messages break naive ratchet implementations. For v2.0 demo, document this limitation rather than papering over it.

5. **localStorage secret key storage** — storing Dilithium secret key in localStorage is insecure in production. Document this clearly in code comments and README.

6. **CORS and CSP headers** — Flask-SocketIO + WASM loading may require specific Content-Security-Policy headers. Report if WASM fails to load.

---

## PART 10 — FINAL DELIVERABLES

When complete, provide:

1. **Full source code** — all files in the structure above
2. **README.md** with:
   - Setup instructions (exact pip commands)
   - Architecture diagram (ASCII is fine)
   - What changed from v1.0 to v2.0
   - Known limitations (be honest)
   - Academic references for each algorithm
3. **SECURITY_NOTES.md** — honest document listing:
   - What is production-safe
   - What is demo-only and why
   - What attacks this does NOT protect against
4. **Test results** — output of `pytest tests/ -v`
5. **Checkpoint reports** — all 5 checkpoint reports

---

## REFERENCES (Use these — do not invent citations)

- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- Signal Double Ratchet Spec: https://signal.org/docs/specifications/doubleratchet/
- liboqs Python docs: https://github.com/open-quantum-safe/liboqs-python
- liboqs-wasm: https://github.com/open-quantum-safe/liboqs-node (check if wasm build exists)
- LWE Hardness Estimator: https://lwe-estimator.readthedocs.io
- Kyber/ML-KEM spec: https://pq-crystals.org/kyber/

---

*End of prompt. Total scope: ~2,500 lines of new code across 15+ files. Estimated implementation time: 8–12 focused hours. Do not rush Phase 1 — if the crypto wrappers are wrong, everything built on top is wrong.*
