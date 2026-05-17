"""
Phase 1 crypto tests — all must pass before Phase 2 begins.

Tests:
  1. Kyber768 round-trip (encap/decap shared secrets match)
  2. ML-DSA-65 sign + verify (valid signature accepted)
  3. ML-DSA-65 tamper detection (tampered message rejected)
  4. HKDF determinism (same inputs → same key)
  5. HKDF different inputs → different keys
  6. HKDF lexicographic salt symmetry (Amendment 1 — call order must not matter)
  7. Full E2EE handshake simulation (Alice+Bob derive matching session key)
  8. Ratchet: 20 steps produce unique message keys
  9. Ratchet reset (Amendment 3 — reset from new root key works)
 10. Fingerprint: both parties compute the same value
"""

import pytest
from crypto.kyber import KyberKEM
from crypto.dilithium import DilithiumSigner
from crypto.hkdf import derive_session_key, derive_ratchet_keys, compute_fingerprint
from crypto.ratchet import SymmetricRatchet


# ---------------------------------------------------------------------------
# 1. Kyber768 round-trip
# ---------------------------------------------------------------------------

def test_kyber768_roundtrip():
    """Encapsulate and decapsulate — shared secrets must match."""
    kem = KyberKEM()
    pub, sec = kem.generate_keypair()

    assert len(pub) == 1184, f"Expected pub 1184B, got {len(pub)}"
    assert len(sec) == 2400, f"Expected sec 2400B, got {len(sec)}"

    ct, ss_enc = kem.encapsulate(pub)
    assert len(ct) == 1088, f"Expected ct 1088B, got {len(ct)}"
    assert len(ss_enc) == 32, f"Expected ss 32B, got {len(ss_enc)}"

    ss_dec = kem.decapsulate(sec, ct)
    assert ss_enc == ss_dec, "Kyber768 shared secrets don't match"


# ---------------------------------------------------------------------------
# 2. ML-DSA-65 sign + verify
# ---------------------------------------------------------------------------

def test_mldsa65_sign_verify():
    """Sign and verify a message — must succeed."""
    signer = DilithiumSigner()
    pub, sec = signer.generate_keypair()

    assert len(pub) == 1952, f"Expected pub 1952B, got {len(pub)}"
    assert len(sec) == 4032, f"Expected sec 4032B, got {len(sec)}"

    message = b"alice kyber_pub || ecdhe_pub || 1713675712"
    sig = signer.sign(sec, message)

    assert len(sig) > 0
    assert signer.verify(pub, message, sig), "Valid ML-DSA-65 signature was rejected"


# ---------------------------------------------------------------------------
# 3. ML-DSA-65 tamper detection
# ---------------------------------------------------------------------------

def test_mldsa65_tamper_detection():
    """A tampered message must fail verification — never raises."""
    signer = DilithiumSigner()
    pub, sec = signer.generate_keypair()
    message = b"original handshake payload"
    sig = signer.sign(sec, message)

    assert not signer.verify(pub, b"tampered payload", sig), \
        "Tampered message incorrectly accepted"


def test_mldsa65_wrong_key_rejected():
    """Signature from key A must not verify against key B's public key."""
    signer = DilithiumSigner()
    pub_a, sec_a = signer.generate_keypair()
    pub_b, _ = signer.generate_keypair()
    message = b"some message"
    sig = signer.sign(sec_a, message)
    assert not signer.verify(pub_b, message, sig), \
        "Wrong public key incorrectly accepted"


# ---------------------------------------------------------------------------
# 4 & 5. HKDF determinism + different inputs
# ---------------------------------------------------------------------------

def test_hkdf_determinism():
    """Same inputs must produce same session key."""
    ks = b"k" * 32
    es = b"e" * 32
    pa = b"a" * 1184
    pb = b"b" * 1184
    k1 = derive_session_key(ks, es, pa, pb)
    k2 = derive_session_key(ks, es, pa, pb)
    assert k1 == k2, "HKDF is not deterministic"
    assert len(k1) == 32


def test_hkdf_different_inputs_differ():
    """Different Kyber secrets must produce different session keys."""
    es = b"e" * 32
    pa = b"a" * 1184
    pb = b"b" * 1184
    k1 = derive_session_key(b"k1" * 16, es, pa, pb)
    k2 = derive_session_key(b"k2" * 16, es, pa, pb)
    assert k1 != k2, "Different kyber secrets produced same key"


# ---------------------------------------------------------------------------
# 6. HKDF lexicographic salt symmetry (Amendment 1)
# ---------------------------------------------------------------------------

def test_hkdf_lexicographic_salt_symmetry():
    """
    Amendment (1): Call order of pubkeys must NOT affect the derived session key.
    Alice calls derive_session_key(ks, es, alice_pub, bob_pub).
    Bob calls   derive_session_key(ks, es, bob_pub,   alice_pub).
    Both must get the same key.
    """
    ks = b"shared_kyber_secret_32b_padding!"  # 32 bytes
    es = b"shared_ecdhe_secret_32b_padding!"  # 32 bytes
    alice_pub = b"\xaa" * 1184
    bob_pub   = b"\xbb" * 1184

    key_alice_order = derive_session_key(ks, es, alice_pub, bob_pub)
    key_bob_order   = derive_session_key(ks, es, bob_pub,   alice_pub)

    assert key_alice_order == key_bob_order, \
        "HKDF salt is NOT symmetric — lexicographic ordering broken"


# ---------------------------------------------------------------------------
# 7. Full E2EE handshake simulation
# ---------------------------------------------------------------------------

def test_full_e2ee_handshake():
    """
    Simulate Alice+Bob key exchange:
      - Alice generates Kyber768 keypair
      - Bob encapsulates to Alice's pubkey → gets kyber_secret_bob
      - Alice decapsulates → gets kyber_secret_alice
      - Both run HKDF with same inputs → same session key
    """
    kem = KyberKEM()

    # Alice generates keypair
    alice_kyber_pub, alice_kyber_sec = kem.generate_keypair()

    # Bob encapsulates to Alice (simulates handshake_request → handshake_response)
    bob_kyber_pub, _ = kem.generate_keypair()           # Bob's ephemeral pub (for salt)
    ct, kyber_secret_bob = kem.encapsulate(alice_kyber_pub)

    # Alice decapsulates
    kyber_secret_alice = kem.decapsulate(alice_kyber_sec, ct)

    assert kyber_secret_alice == kyber_secret_bob, \
        "E2EE handshake: Kyber728 shared secrets don't match"

    # Simulate ECDHE shared secret (same on both sides in real impl)
    ecdhe_secret = b"simulated_ecdhe_shared_secret_XY"  # 32 bytes

    # Both derive session key — Amendment (1): order must not matter
    session_key_alice = derive_session_key(
        kyber_secret_alice, ecdhe_secret, alice_kyber_pub, bob_kyber_pub
    )
    session_key_bob = derive_session_key(
        kyber_secret_bob, ecdhe_secret, bob_kyber_pub, alice_kyber_pub
    )

    assert session_key_alice == session_key_bob, \
        "E2EE handshake: session keys don't match (check lexicographic ordering)"
    assert len(session_key_alice) == 32


# ---------------------------------------------------------------------------
# 8. Ratchet: 20 steps produce unique message keys
# ---------------------------------------------------------------------------

def test_ratchet_20_unique_message_keys():
    """Each ratchet advance must produce a unique message key."""
    root_key = b"test_root_key_for_ratchet_init!!"  # 32 bytes
    ratchet = SymmetricRatchet(root_key)
    keys = [ratchet.advance() for _ in range(20)]

    assert len(set(keys)) == 20, "Ratchet produced duplicate message keys"
    assert all(len(k) == 32 for k in keys), "Not all message keys are 32 bytes"
    assert ratchet.step == 20


def test_ratchet_chain_key_changes():
    """Each advance must update the chain key."""
    root_key = b"root_key_32_bytes_padding_padXYZ"
    ratchet = SymmetricRatchet(root_key)
    initial_chain = ratchet.chain_key
    ratchet.advance()
    assert ratchet.chain_key != initial_chain, "Chain key did not advance"


# ---------------------------------------------------------------------------
# 9. Ratchet reset (Amendment 3)
# ---------------------------------------------------------------------------

def test_ratchet_reset():
    """
    Amendment (3): reset() clears state to a new root key.
    After reset, step counter resets to 0 and ratchet works from new root.
    """
    root_key = b"original_root_32bytes_padding00!"
    ratchet = SymmetricRatchet(root_key)
    for _ in range(5):
        ratchet.advance()
    assert ratchet.step == 5

    new_root = b"new_root_after_session_reset_XX!"
    ratchet.reset(new_root)
    assert ratchet.step == 0, "Step counter not reset"
    assert ratchet.chain_key == new_root, "Chain key not updated to new root"

    # Should still produce valid keys after reset
    msg_key = ratchet.advance()
    assert len(msg_key) == 32
    assert ratchet.step == 1


# ---------------------------------------------------------------------------
# 10. Fingerprint symmetry
# ---------------------------------------------------------------------------

def test_fingerprint_symmetry():
    """Both parties must compute the same fingerprint regardless of argument order."""
    pub_alice = b"\xaa" * 1952
    pub_bob   = b"\xbb" * 1952
    fp_alice = compute_fingerprint(pub_alice, pub_bob)
    fp_bob   = compute_fingerprint(pub_bob,   pub_alice)
    assert fp_alice == fp_bob, "Fingerprint differs by call order"
    # Format: 6 groups of 4 hex chars
    parts = fp_alice.split(" ")
    assert len(parts) == 6, f"Expected 6 groups, got: {fp_alice}"
    assert all(len(p) == 4 for p in parts)
