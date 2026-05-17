# PQChat v2.0 - Security Notes

## What is production-grade in this implementation
- **ML-KEM-768 key exchange**: Implements the NIST FIPS 203 draft standard (NIST security level 3).
- **ML-DSA-65 signatures**: Implements the NIST FIPS 204 draft standard (NIST security level 3).
- **AES-256-GCM authenticated encryption**: Provides standard confidentiality and integrity for message payloads.
- **HKDF-SHA256 key derivation**: Strictly compliant key expansion using Kyber + ECDHE inputs and a unique salt.
- **Hybrid KEM (quantum + classical)**: Mitigates risks against both store-and-harvest quantum attacks and potential classical flaws by combining ECDHE (P-256) and ML-KEM-768.
- **Per-message key churn via symmetric ratchet**: Forward secrecy is strictly maintained at the message level via HKDF symmetric ratcheting.
- **scrypt password hashing**: Password-based authentication uses memory-hard parameters (`n=16384, r=8, p=1`).

## What is demo-only and why
- **Private keys stored in IndexedDB**: A production app should leverage the WebAuthn standard or secure hardware enclaves (HSMs) rather than the local browser storage, as IndexedDB is vulnerable to XSS and physical device access.
- **No out-of-order message handling**: The symmetric ratchet requires strictly in-order message delivery to function. If a message drops or is delayed, the session state corrupts. Real implementations use more complex skipped-message structures.
- **In-memory socket registry**: State maps user sockets to usernames. This state is wiped if the Flask server reboots, requiring users to log out and reconnect manually.
- **No message persistence**: Messages are ephemeral and live only in the DOM of the active chat. There is no SQLite or IndexedDB storage layer for chat histories.
- **No certificate pinning**: The `/api/keys` endpoint delivers public identity keys directly to the client over standard TLS, relying purely on the transport layer for security without a trust-on-first-use (TOFU) or pinning mechanism.

## What this does NOT protect against
- **A compromised server operator modifying the served JavaScript**: The server can simply modify `crypto_client.js` to exfiltrate private key bytes.
- **A malicious user on the same machine accessing IndexedDB**: Anyone with file system access or dev tools on the unlocked host machine can retrieve `pqchat-identity`.
- **Break-in recovery (Post-Compromise Security)**: This app does not implement an asymmetric Diffie-Hellman ratchet step (like Signal's Double Ratchet). If the session chain key is compromised, subsequent messages are compromised until a new handshake is manually established.
- **Server-side traffic analysis**: The server sees who is talking to whom, connection timings, and message byte sizes. (Metadata is not encrypted).
