"""Phase 2 cryptography tests."""

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
