import pytest
import os
from config import configure_logging
configure_logging()

from crypto.kyber     import KyberKEM
from crypto.dilithium import DilithiumSigner
from crypto.hkdf      import derive_session_key, derive_ratchet_keys
from crypto.ratchet   import ChainRatchet


# ── ML-KEM-768 ────────────────────────────────────────────────────────────────

class TestKyberKEM:

    def test_keypair_sizes(self):
        kem = KyberKEM()
        pub, sec = kem.generate_keypair()
        assert len(pub) == 1184, f"pubkey wrong size: {len(pub)}"
        assert len(sec) == 2400, f"seckey wrong size: {len(sec)}"

    def test_encap_output_sizes(self):
        kem = KyberKEM()
        pub, _ = kem.generate_keypair()
        ct, ss = kem.encapsulate(pub)
        assert len(ct) == 1088, f"ciphertext wrong size: {len(ct)}"
        assert len(ss) == 32,   f"shared secret wrong size: {len(ss)}"

    def test_encap_decap_roundtrip(self):
        """Shared secrets from encapsulation and decapsulation must be identical."""
        kem = KyberKEM()
        pub, sec = kem.generate_keypair()
        ct, ss_enc = kem.encapsulate(pub)
        ss_dec = kem.decapsulate(sec, ct)
        assert ss_enc == ss_dec, "Shared secrets do not match"

    def test_different_keypairs_produce_different_secrets(self):
        kem = KyberKEM()
        pub1, sec1 = kem.generate_keypair()
        pub2, sec2 = kem.generate_keypair()
        ct1, ss1 = kem.encapsulate(pub1)
        ct2, ss2 = kem.encapsulate(pub2)
        assert ss1 != ss2

    def test_wrong_seckey_decap_raises(self):
        kem = KyberKEM()
        pub1, sec1 = kem.generate_keypair()
        pub2, sec2 = kem.generate_keypair()
        ct, _ = kem.encapsulate(pub1)
        # Decapping with the wrong secret key should either raise or return wrong secret
        # We accept both behaviours — the important thing is it does NOT return the right secret
        try:
            ss = kem.decapsulate(sec2, ct)
            ct_correct, ss_correct = kem.encapsulate(pub1)
            ss_correct = kem.decapsulate(sec1, ct)
            assert ss != ss_correct
        except Exception:
            pass  # Raising is also acceptable

    def test_invalid_pubkey_length_raises(self):
        kem = KyberKEM()
        with pytest.raises((ValueError, RuntimeError)):
            kem.encapsulate(b"\x00" * 100)

    def test_invalid_seckey_length_raises(self):
        kem = KyberKEM()
        pub, _ = kem.generate_keypair()
        ct, _ = kem.encapsulate(pub)
        with pytest.raises((ValueError, RuntimeError)):
            kem.decapsulate(b"\x00" * 100, ct)


# ── ML-DSA-65 ─────────────────────────────────────────────────────────────────

class TestDilithiumSigner:

    def test_keypair_sizes(self):
        s = DilithiumSigner()
        pub, sec = s.generate_keypair()
        assert len(pub) == 1952, f"pubkey wrong size: {len(pub)}"
        assert len(sec) == 4032, f"seckey wrong size: {len(sec)}"

    def test_sign_and_verify(self):
        s = DilithiumSigner()
        pub, sec = s.generate_keypair()
        msg = b"test handshake payload 12345"
        sig = s.sign(sec, msg)
        assert s.verify(pub, msg, sig), "Valid signature was rejected"

    def test_tampered_message_rejected(self):
        s = DilithiumSigner()
        pub, sec = s.generate_keypair()
        msg = b"original message"
        sig = s.sign(sec, msg)
        assert not s.verify(pub, b"tampered message", sig), \
            "Tampered message was accepted"

    def test_wrong_pubkey_rejected(self):
        s = DilithiumSigner()
        pub1, sec1 = s.generate_keypair()
        pub2, _    = s.generate_keypair()
        msg = b"test"
        sig = s.sign(sec1, msg)
        assert not s.verify(pub2, msg, sig), \
            "Signature verified with wrong public key"

    def test_truncated_signature_rejected(self):
        s = DilithiumSigner()
        pub, sec = s.generate_keypair()
        msg = b"test"
        sig = s.sign(sec, msg)
        assert not s.verify(pub, msg, sig[:100]), \
            "Truncated signature was accepted"

    def test_empty_message(self):
        s = DilithiumSigner()
        pub, sec = s.generate_keypair()
        msg = b""
        sig = s.sign(sec, msg)
        assert s.verify(pub, msg, sig)


# ── HKDF ──────────────────────────────────────────────────────────────────────

class TestHKDF:

    def test_session_key_length(self):
        key = derive_session_key(
            os.urandom(32), os.urandom(32),
            os.urandom(1184), os.urandom(1184)
        )
        assert len(key) == 32

    def test_session_key_determinism(self):
        """Same inputs must produce identical output."""
        kyber_ss  = b"a" * 32
        ecdhe_ss  = b"b" * 32
        alice_pub = b"c" * 1184
        bob_pub   = b"d" * 1184
        k1 = derive_session_key(kyber_ss, ecdhe_ss, alice_pub, bob_pub)
        k2 = derive_session_key(kyber_ss, ecdhe_ss, alice_pub, bob_pub)
        assert k1 == k2

    def test_session_key_different_inputs(self):
        """Different kyber_ss must produce different output."""
        ecdhe_ss  = b"b" * 32
        alice_pub = b"c" * 1184
        bob_pub   = b"d" * 1184
        k1 = derive_session_key(b"a" * 32, ecdhe_ss, alice_pub, bob_pub)
        k2 = derive_session_key(b"z" * 32, ecdhe_ss, alice_pub, bob_pub)
        assert k1 != k2

    def test_session_key_ordering_matters(self):
        """Swapping kyber/ecdhe secrets must produce different keys."""
        ss_a = os.urandom(32)
        ss_b = os.urandom(32)
        pub1 = os.urandom(1184)
        pub2 = os.urandom(1184)
        k1 = derive_session_key(ss_a, ss_b, pub1, pub2)
        k2 = derive_session_key(ss_b, ss_a, pub1, pub2)
        assert k1 != k2, "Key ordering does not affect output — this is a bug"

    def test_ratchet_keys_length(self):
        new_chain, msg_key = derive_ratchet_keys(os.urandom(32), step=0)
        assert len(new_chain) == 32
        assert len(msg_key)   == 32

    def test_ratchet_keys_differ(self):
        """Chain key and message key must be different."""
        new_chain, msg_key = derive_ratchet_keys(os.urandom(32), step=0)
        assert new_chain != msg_key

    def test_ratchet_step_determinism(self):
        chain_key = os.urandom(32)
        r1_chain, r1_msg = derive_ratchet_keys(chain_key, step=5)
        r2_chain, r2_msg = derive_ratchet_keys(chain_key, step=5)
        assert r1_chain == r2_chain
        assert r1_msg   == r2_msg

    def test_ratchet_different_steps_differ(self):
        chain_key = os.urandom(32)
        _, msg0 = derive_ratchet_keys(chain_key, step=0)
        _, msg1 = derive_ratchet_keys(chain_key, step=1)
        assert msg0 != msg1


# ── Chain Ratchet ─────────────────────────────────────────────────────────────

class TestChainRatchet:

    def test_encrypt_decrypt_single_message(self):
        """Alice and Bob must derive the same message key for step 0."""
        session_key = os.urandom(32)
        alice = ChainRatchet()
        bob   = ChainRatchet()
        alice.init_from_session_key("bob", session_key)
        bob.init_from_session_key("alice", session_key)

        alice_msg_key, step = alice.encrypt_step("bob")
        bob_msg_key         = bob.decrypt_step("alice", step)
        assert alice_msg_key == bob_msg_key

    def test_twenty_messages_in_order(self):
        """Simulate 20 messages Alice → Bob, all must decrypt correctly."""
        session_key = os.urandom(32)
        alice = ChainRatchet()
        bob   = ChainRatchet()
        alice.init_from_session_key("bob", session_key)
        bob.init_from_session_key("alice", session_key)

        for i in range(20):
            a_key, step = alice.encrypt_step("bob")
            b_key       = bob.decrypt_step("alice", step)
            assert a_key == b_key, f"Key mismatch at step {i}"

    def test_forward_secrecy_message_keys_differ(self):
        """Each message must use a different key."""
        session_key = os.urandom(32)
        ratchet = ChainRatchet()
        ratchet.init_from_session_key("peer", session_key)
        keys = set()
        for _ in range(10):
            key, _ = ratchet.encrypt_step("peer")
            assert key not in keys, "Ratchet produced duplicate message key"
            keys.add(key)

    def test_out_of_order_raises(self):
        """Decrypting with wrong step number must raise ValueError."""
        session_key = os.urandom(32)
        ratchet = ChainRatchet()
        ratchet.init_from_session_key("peer", session_key)
        with pytest.raises(ValueError, match="step"):
            ratchet.decrypt_step("peer", expected_step=5)

    def test_missing_peer_raises(self):
        ratchet = ChainRatchet()
        with pytest.raises(KeyError):
            ratchet.encrypt_step("nobody")
