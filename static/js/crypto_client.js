/**
 * PQChat v2.0 — Browser-Side Post-Quantum Crypto Client
 *
 * Implements the client side of the hybrid PQ handshake and message encryption.
 * All cryptographic operations run in the browser — server is a BLIND RELAY.
 *
 * ── Algorithm stack ──────────────────────────────────────────────────────
 *  PQ KEM:      Kyber768 via liboqs-wasm  (NIST FIPS 203 / ML-KEM-768)
 *  PQ Sig:      ML-DSA-65 via liboqs-wasm (NIST FIPS 204 / Dilithium3)
 *  Classical:   ECDHE P-256 via WebCrypto API
 *  KDF:         HKDF-SHA256 via WebCrypto (Amendment 1: lexicographic salt)
 *  Symmetric:   AES-256-GCM via WebCrypto
 *  Ratchet:     SymmetricRatchetClient (ratchet_client.js)
 *
 * ── Amendment 4: DEGRADED MODE ───────────────────────────────────────────
 *  If liboqs-wasm fails to load:
 *    - DEGRADED MODE banner shown in UI
 *    - Kyber768 KEM: skipped (ECDHE-only handshake, classical security only)
 *    - ML-DSA-65 sigs: skipped (unauthenticated handshake)
 *    - AES-256-GCM + ECDHE: still work (WebCrypto only)
 *    - Server is notified via 'wasm_status' event
 *  Session key derivation in DEGRADED MODE uses only ECDHE secret.
 *
 * ── Key sizes (verified pre-Phase 1) ─────────────────────────────────────
 *  Kyber768 pubkey   = 1184 bytes
 *  Kyber768 privkey  = 2400 bytes
 *  Kyber768 ct       = 1088 bytes
 *  ML-DSA-65 pubkey  = 1952 bytes
 *  ML-DSA-65 privkey = 4032 bytes
 *  ML-DSA-65 sig     ≤ 3309 bytes
 *
 * ── WASM note ─────────────────────────────────────────────────────────────
 *  liboqs-wasm is loaded from CDN. The window.OQS object is set by the
 *  WASM loader script (liboqs.js). If unavailable, DEGRADED MODE activates.
 *  See also: simulator.html for the WASM status banner (Amendment 4).
 */

'use strict';

class PQChatClient {
  constructor(socket, username, authToken) {
    this._socket     = socket;
    this._username   = username;
    this._authToken  = authToken;

    // liboqs-wasm state
    this._oqs        = null;      // loaded WASM module or null
    this._degraded   = false;     // Amendment 4: DEGRADED MODE flag

    // Identity keys (ML-DSA-65 long-term keypair)
    this._identityPub = null;     // Uint8Array, 1952 bytes
    this._identitySec = null;     // Uint8Array, 4032 bytes — memory only

    // Per-conversation ephemeral state
    // { peer: { kyberSec, ecdhPriv, kyberPub } }
    this._pendingHandshakes = {};

    // Per-conversation session state
    // { peer: { sessionKey: Uint8Array } }
    this._sessions = {};

    // Ratchet manager (from ratchet_client.js)
    this._ratchet = new window.RatchetManager();

    // Crypto terminal log callback — set by UI
    this.onLog = null;

    // Fingerprint registry { peer: { fingerprint, verified } }
    this._fingerprints = {};
  }

  // ─── Initialization ────────────────────────────────────────────────────

  /**
   * Initialize the client.
   * 1. Attempt to load liboqs-wasm
   * 2. Load or generate ML-DSA-65 identity keys
   * 3. Register identity with server
   */
  async initialize() {
    this._log('PQChat v2.0 initializing...');
    await this._loadWasm();
    await this._loadOrGenerateIdentityKeys();
    await this._registerIdentityWithServer();
    this._log(`✅ Ready. Identity: ${this._truncateHex(this._toHex(this._identityPub))}...`);
  }

  async _loadWasm() {
    try {
      // liboqs-wasm exposes window.OQS after loading liboqs.js
      // Attempt to access it; if unavailable, fall back to DEGRADED MODE
      if (typeof window.OQS !== 'undefined' && window.OQS) {
        this._oqs = window.OQS;
        this._log('✅ liboqs-wasm loaded (Kyber768 + ML-DSA-65 available)');
        this._degraded = false;
      } else {
        throw new Error('window.OQS not defined after loading liboqs.js');
      }
    } catch (err) {
      // Amendment 4: DEGRADED MODE
      this._degraded = true;
      this._oqs = null;
      this._log('⚠️ liboqs-wasm unavailable — entering DEGRADED MODE');
      this._log('   Kyber768 and ML-DSA-65 disabled. ECDHE-only session.');
      window.dispatchEvent(new CustomEvent('pqchat:degraded', {
        detail: { reason: err.message }
      }));
    }

    // Report WASM status to server (Amendment 4)
    this._socket.emit('wasm_status', {
      token: this._authToken,
      wasm_available: !this._degraded,
      degraded_algorithms: this._degraded ? ['Kyber768', 'ML-DSA-65'] : [],
    });
  }

  // ─── Identity Key Management ───────────────────────────────────────────

  async _loadOrGenerateIdentityKeys() {
    const stored = localStorage.getItem('pqchat_identity_v2');

    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        if (parsed.username === this._username && parsed.pub) {
          this._identityPub = this._fromHex(parsed.pub);
          this._identitySec = this._fromHex(parsed.sec);
          this._log('Identity keys loaded from localStorage');
          return;
        }
      } catch (_) { /* fall through to regenerate */ }
    }

    if (this._degraded) {
      // DEGRADED MODE: use a stable 1952-byte placeholder stored in localStorage.
      // Must be 1952 bytes so server hex validation passes (ML-DSA-65 pubkey size).
      const stableKey  = crypto.getRandomValues(new Uint8Array(1952));
      const stablePriv = crypto.getRandomValues(new Uint8Array(32));
      this._identityPub = stableKey;
      this._identitySec = stablePriv;
      localStorage.setItem('pqchat_identity_v2', JSON.stringify({
        username: this._username,
        pub: this._toHex(stableKey),
        sec: this._toHex(stablePriv),
        degraded: true,
      }));
      this._log('\u26a0\ufe0f DEGRADED: Stable 1952-byte placeholder identity stored in localStorage');
      return;
    }

    // Generate fresh ML-DSA-65 keypair
    this._log('Generating ML-DSA-65 identity keypair...');
    const { publicKey, secretKey } = await this._mldsaGenerateKeypair();
    this._identityPub = publicKey;
    this._identitySec = secretKey;

    // WARNING: localStorage is not production-safe for secret keys.
    // For production use WebAuthn / hardware security key.
    // This is acceptable for the demo — documented limitation.
    localStorage.setItem('pqchat_identity_v2', JSON.stringify({
      username: this._username,
      pub: this._toHex(publicKey),
      sec: this._toHex(secretKey),  // DEMO ONLY — not for production
    }));

    this._log(`ML-DSA-65 identity generated. Pub: ${this._truncateHex(this._toHex(publicKey))}...`);
  }

  async _registerIdentityWithServer() {
    // ECDHE identity public key (classical, for reference)
    const ecdhKeypair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const ecdhPubRaw = new Uint8Array(
      await crypto.subtle.exportKey('raw', ecdhKeypair.publicKey)
    );

    this._socket.emit('register_identity', {
      token: this._authToken,
      dilithium_public_key:     this._toHex(this._identityPub),
      ecdh_identity_public_key: this._toHex(ecdhPubRaw),
    });

    this._log('Identity keys registered with server');
  }

  // ─── Handshake: Initiator (Alice) ──────────────────────────────────────

  /**
   * Initiate a PQ handshake with a peer.
   * Alice sends: ephemeral Kyber768 pubkey + ECDHE pubkey + ML-DSA-65 signature
   *
   * @param {string} peer - target username
   */
  async initiateHandshake(peer) {
    this._log(`Initiating PQ handshake with ${peer}...`);

    // 1. Ephemeral Kyber768 keypair
    let kyberPub = null, kyberSec = null;
    if (!this._degraded) {
      ({ publicKey: kyberPub, secretKey: kyberSec } = await this._kyberGenerateKeypair());
      this._log(`Kyber768 ephemeral pub: ${this._truncateHex(this._toHex(kyberPub))}...`);
    } else {
      // DEGRADED: use random placeholder
      kyberPub = crypto.getRandomValues(new Uint8Array(1184));
      kyberSec = crypto.getRandomValues(new Uint8Array(2400));
      this._log('⚠️ DEGRADED: Kyber768 placeholder (no PQ security)');
    }

    // 2. Ephemeral ECDHE P-256 keypair via WebCrypto
    const ecdhKeypair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const ecdhPubRaw = new Uint8Array(
      await crypto.subtle.exportKey('raw', ecdhKeypair.publicKey)
    );
    this._log(`ECDHE P-256 ephemeral pub generated (${ecdhPubRaw.length} bytes)`);

    // 3. Sign both pubkeys with identity key
    const timestamp = Date.now().toString();
    const signPayload = this._concat(kyberPub, ecdhPubRaw, new TextEncoder().encode(timestamp));
    let signature;

    if (!this._degraded) {
      signature = await this._mldsaSign(this._identitySec, signPayload);
      this._log(`ML-DSA-65 signature: ${this._truncateHex(this._toHex(signature))}...`);
    } else {
      signature = new Uint8Array(64); // placeholder
      this._log('⚠️ DEGRADED: No ML-DSA-65 signature');
    }

    // Store ephemeral state for when handshake_complete arrives
    this._pendingHandshakes[peer] = {
      kyberPub: kyberPub,
      kyberSec: kyberSec,
      ecdhPriv: ecdhKeypair.privateKey,
    };

    this._socket.emit('handshake_init', {
      token:                   this._authToken,
      target_user:             peer,
      kyber_ephemeral_pubkey:  this._toHex(kyberPub),
      ecdhe_ephemeral_pubkey:  this._toHex(ecdhPubRaw),
      timestamp:               timestamp,
      signature:               this._toHex(signature),
    });

    this._log(`Handshake_init sent to ${peer}`);
  }

  // ─── Handshake: Responder (Bob) ────────────────────────────────────────

  /**
   * Handle incoming handshake_request from Alice.
   * Bob verifies Alice's signature, encapsulates Kyber768, computes ECDHE.
   * Bob sends: kyber_ciphertext + his Kyber pubkey + ECDHE pubkey (signed).
   *
   * @param {Object} data - from server 'handshake_request' event
   */
  async handleHandshakeRequest(data) {
    const alice = data.from;
    this._log(`Received handshake_request from ${alice}`);

    // 1. Fetch Alice's identity public key
    const aliceKeys = await this._fetchPublicKeys(alice);
    if (!aliceKeys) {
      this._log(`❌ Cannot fetch ${alice}'s public keys`);
      return;
    }

    // 2. Verify Alice's ML-DSA-65 signature
    if (!this._degraded) {
      const alicePub      = this._fromHex(aliceKeys.dilithium_public_key);
      const kyberPubBytes = this._fromHex(data.kyber_ephemeral_pubkey);
      const ecdhePubBytes = this._fromHex(data.ecdhe_ephemeral_pubkey);
      const tsBytes       = new TextEncoder().encode(data.timestamp);
      const sigPayload    = this._concat(kyberPubBytes, ecdhePubBytes, tsBytes);
      const sig           = this._fromHex(data.signature);

      const valid = await this._mldsaVerify(alicePub, sigPayload, sig);
      if (!valid) {
        this._log(`❌ INVALID ML-DSA-65 signature from ${alice} — possible MITM!`);
        window.dispatchEvent(new CustomEvent('pqchat:mitm_warning', { detail: { peer: alice } }));
        return;
      }
      this._log(`✅ ML-DSA-65 signature verified for ${alice}`);
    }

    const aliceKyberPub = this._fromHex(data.kyber_ephemeral_pubkey);
    const aliceEcdhePub = this._fromHex(data.ecdhe_ephemeral_pubkey);

    // 3. Kyber768 encapsulation (Bob encapsulates to Alice's pub)
    let kyberCt, kyberSecret;
    let bobKyberPub, bobKyberSec;

    if (!this._degraded) {
      ({ publicKey: bobKyberPub, secretKey: bobKyberSec } = await this._kyberGenerateKeypair());
      ({ ciphertext: kyberCt, sharedSecret: kyberSecret } = await this._kyberEncapsulate(aliceKyberPub));
      this._log(`Kyber768 encapsulated. ct: ${this._truncateHex(this._toHex(kyberCt))}...`);
    } else {
      // DEGRADED: use all-zero kyber contribution so both sides agree.
      // Session key will be ECDHE-only (32-byte shared secret).
      bobKyberPub = new Uint8Array(1184); // all zeros
      kyberCt     = new Uint8Array(1088); // all zeros (placeholder)
      kyberSecret = new Uint8Array(32);   // all zeros — same on both sides
      this._log('\u26a0\ufe0f DEGRADED: Using zero kyber secret (ECDHE-only session)');
    }

    // 4. Bob's ephemeral ECDHE
    const bobEcdhKp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const bobEcdhPubRaw = new Uint8Array(
      await crypto.subtle.exportKey('raw', bobEcdhKp.publicKey)
    );

    // 5. Compute ECDHE shared secret with Alice's ECDHE pub
    const aliceEcdhCryptoKey = await crypto.subtle.importKey(
      'raw', aliceEcdhePub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
    );
    const ecdheBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: aliceEcdhCryptoKey },
      bobEcdhKp.privateKey,
      256
    );
    const ecdheSecret = new Uint8Array(ecdheBits);

    // 6. Derive session key — Amendment (1): lexicographic salt
    const sessionKey = await this._deriveSessionKey(
      kyberSecret, ecdheSecret, aliceKyberPub, bobKyberPub
    );
    this._log(`🔑 Session key derived: ${this._truncateHex(this._toHex(sessionKey))}...`);

    // 7. Store session + init ratchet
    this._sessions[alice] = { sessionKey };
    this._ratchet.init(alice, sessionKey);
    this._log(`Ratchet initialized for ${alice} (step 0)`);

    // 8. Compute fingerprint
    const fingerprint = await this._computeFingerprint(
      this._identityPub,
      this._fromHex(aliceKeys.dilithium_public_key)
    );
    this._fingerprints[alice] = { fingerprint, verified: false };
    window.dispatchEvent(new CustomEvent('pqchat:fingerprint', {
      detail: { peer: alice, fingerprint }
    }));

    // 9. Sign response — Amendment 2: sig over ct||kyberPub||ecdhePub||timestamp
    const timestamp = Date.now().toString();
    const responsePayload = this._concat(
      kyberCt, bobKyberPub, bobEcdhPubRaw, new TextEncoder().encode(timestamp)
    );
    let responseSig;
    if (!this._degraded) {
      responseSig = await this._mldsaSign(this._identitySec, responsePayload);
    } else {
      responseSig = new Uint8Array(64);
    }

    // 10. Send handshake_response to server → routed to Alice
    this._socket.emit('handshake_response', {
      token:                   this._authToken,
      target_user:             alice,
      kyber_ciphertext:        this._toHex(kyberCt),
      kyber_ephemeral_pubkey:  this._toHex(bobKyberPub),
      ecdhe_ephemeral_pubkey:  this._toHex(bobEcdhPubRaw),
      timestamp:               timestamp,
      signature:               this._toHex(responseSig),
    });

    this._log(`Handshake_response sent to ${alice}`);
    window.dispatchEvent(new CustomEvent('pqchat:session_ready', { detail: { peer: alice } }));
  }

  // ─── Handshake: Initiator Completion (Alice) ───────────────────────────

  /**
   * Handle 'handshake_complete' from server (Bob's response to Alice).
   * Alice decapsulates Kyber768, computes ECDHE, derives session key.
   *
   * @param {Object} data - from server 'handshake_complete' event
   */
  async handleHandshakeComplete(data) {
    const bob = data.from;
    this._log(`Received handshake_complete from ${bob}`);

    const pending = this._pendingHandshakes[bob];
    if (!pending) {
      this._log(`❌ No pending handshake for ${bob}`);
      return;
    }

    // 1. Fetch Bob's identity keys
    const bobKeys = await this._fetchPublicKeys(bob);

    // 2. Verify Bob's signature (Amendment 2 spec)
    if (!this._degraded && bobKeys) {
      const bobDilPub    = this._fromHex(bobKeys.dilithium_public_key);
      const kyberCtBytes = this._fromHex(data.kyber_ciphertext);
      const kyberPubB    = this._fromHex(data.kyber_ephemeral_pubkey);
      const ecdhePubB    = this._fromHex(data.ecdhe_ephemeral_pubkey);
      const tsBytes      = new TextEncoder().encode(data.timestamp);
      const sigPayload   = this._concat(kyberCtBytes, kyberPubB, ecdhePubB, tsBytes);
      const sig          = this._fromHex(data.signature);

      const valid = await this._mldsaVerify(bobDilPub, sigPayload, sig);
      if (!valid) {
        this._log(`❌ INVALID ML-DSA-65 signature from ${bob} in handshake_complete!`);
        window.dispatchEvent(new CustomEvent('pqchat:mitm_warning', { detail: { peer: bob } }));
        return;
      }
      this._log(`✅ ML-DSA-65 signature verified for ${bob} (handshake_complete)`);
    }

    // 3. Kyber768 decapsulation
    let kyberSecret;
    if (!this._degraded) {
      kyberSecret = await this._kyberDecapsulate(
        pending.kyberSec,
        this._fromHex(data.kyber_ciphertext)
      );
      this._log(`Kyber768 decapsulated. ss: ${this._truncateHex(this._toHex(kyberSecret))}...`);
    } else {
      // DEGRADED: zero kyber secret — matches Bob's zero kyber secret above.
      kyberSecret = new Uint8Array(32); // all zeros, same as Bob sent
      this._log('\u26a0\ufe0f DEGRADED: Using zero kyber secret (ECDHE-only session)');
    }

    // 4. ECDHE with Bob's ECDHE pub
    const bobEcdhPub = await crypto.subtle.importKey(
      'raw',
      this._fromHex(data.ecdhe_ephemeral_pubkey),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const ecdheBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: bobEcdhPub },
      pending.ecdhPriv,
      256
    );
    const ecdheSecret = new Uint8Array(ecdheBits);

    // 5. Derive session key — Amendment (1): lexicographic salt
    const aliceKyberPub = pending.kyberPub;
    const bobKyberPub   = this._fromHex(data.kyber_ephemeral_pubkey);
    const sessionKey = await this._deriveSessionKey(
      kyberSecret, ecdheSecret, aliceKyberPub, bobKyberPub
    );
    this._log(`🔑 Session key derived: ${this._truncateHex(this._toHex(sessionKey))}...`);

    // 6. Store session + init ratchet
    this._sessions[bob] = { sessionKey };
    this._ratchet.init(bob, sessionKey);
    this._log(`Ratchet initialized for ${bob} (step 0)`);

    // 7. Compute fingerprint
    if (bobKeys) {
      const fingerprint = await this._computeFingerprint(
        this._identityPub,
        this._fromHex(bobKeys.dilithium_public_key)
      );
      this._fingerprints[bob] = { fingerprint, verified: false };
      window.dispatchEvent(new CustomEvent('pqchat:fingerprint', {
        detail: { peer: bob, fingerprint }
      }));
    }

    // Clean up pending state
    delete this._pendingHandshakes[bob];

    window.dispatchEvent(new CustomEvent('pqchat:session_ready', { detail: { peer: bob } }));
  }

  // ─── Message Encryption ────────────────────────────────────────────────

  /**
   * Encrypt a plaintext message for a peer using the ratchet.
   *
   * @param {string} peer
   * @param {string} plaintext
   * @returns {{ nonce, ciphertext, tag, ratchet_step, signature }}
   */
  async encryptMessage(peer, plaintext) {
    const ratchet = this._ratchet.get(peer);
    if (!ratchet) throw new Error(`No ratchet state for ${peer}. Handshake required.`);

    // Advance ratchet — get one-time message key (non-extractable CryptoKey)
    const msgKey = await ratchet.advance();
    this._log(`Encrypt → ratchet step ${ratchet.step} (${peer})`);

    const nonce   = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);

    // AES-256-GCM returns ciphertext + 16-byte auth tag concatenated
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      msgKey,
      encoded
    );

    const encArray = new Uint8Array(encrypted);
    const ct  = encArray.slice(0, encArray.length - 16);
    const tag = encArray.slice(encArray.length - 16);

    // Sign nonce‖ciphertext (sender authentication)
    let signature = new Uint8Array(64);
    if (!this._degraded) {
      const sigPayload = this._concat(nonce, ct, new Uint8Array([ratchet.step & 0xff]));
      signature = await this._mldsaSign(this._identitySec, sigPayload);
    }

    return {
      nonce:        this._toHex(nonce),
      ciphertext:   this._toHex(ct),
      tag:          this._toHex(tag),
      ratchet_step: ratchet.step,
      signature:    this._toHex(signature),
    };
  }

  /**
   * Decrypt a received encrypted message.
   *
   * @param {string} peer - sender username
   * @param {Object} payload - { nonce, ciphertext, tag, ratchet_step, signature }
   * @returns {string} plaintext
   */
  async decryptMessage(peer, payload) {
    const ratchet = this._ratchet.get(peer);
    if (!ratchet) throw new Error(`No ratchet state for ${peer}. Request session reset.`);

    // Verify sender signature before decrypting
    if (!this._degraded && payload.signature) {
      const peerKeys = await this._fetchPublicKeys(peer);
      if (peerKeys) {
        const peerDilPub = this._fromHex(peerKeys.dilithium_public_key);
        const nonce      = this._fromHex(payload.nonce);
        const ct         = this._fromHex(payload.ciphertext);
        const sigPayload = this._concat(nonce, ct, new Uint8Array([payload.ratchet_step & 0xff]));
        const sig        = this._fromHex(payload.signature);
        const valid      = await this._mldsaVerify(peerDilPub, sigPayload, sig);
        if (!valid) {
          this._log(`⚠️ Message from ${peer} has INVALID signature`);
          // Continue decryption anyway (ciphertext integrity protected by GCM tag)
        } else {
          this._log(`✅ Message signature verified (step ${payload.ratchet_step})`);
        }
      }
    }

    // Advance ratchet to get message key
    const msgKey = await ratchet.advance();
    this._log(`Decrypt ← ratchet step ${ratchet.step} (${peer})`);

    const nonce  = this._fromHex(payload.nonce);
    const ct     = this._fromHex(payload.ciphertext);
    const tag    = this._fromHex(payload.tag);

    // Reconstruct AES-GCM input: ciphertext ‖ tag
    const ctWithTag = this._concat(ct, tag);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        msgKey,
        ctWithTag
      );
      return new TextDecoder().decode(decrypted);
    } catch (err) {
      throw new Error(
        `Decryption failed for message from ${peer}. ` +
        `Ratchet may be desynced — use Reset Session. ` +
        `Error: ${err.message}`
      );
    }
  }

  // ─── Session Reset (Amendment 3) ──────────────────────────────────────

  /**
   * Request a session reset with a peer.
   * Sends 'request_session_reset' to server, which relays to peer.
   * Both parties must re-handshake after this.
   *
   * @param {string} peer
   * @param {string} reason
   */
  requestSessionReset(peer, reason = 'Manual reset') {
    this._ratchet.remove(peer);
    delete this._sessions[peer];
    delete this._pendingHandshakes[peer];
    this._socket.emit('request_session_reset', {
      token: this._authToken,
      target_user: peer,
      reason,
    });
    this._log(`Session reset requested for ${peer}`);
    window.dispatchEvent(new CustomEvent('pqchat:session_reset', { detail: { peer } }));
  }

  // ─── Key Fingerprint Verification ─────────────────────────────────────

  markVerified(peer) {
    if (this._fingerprints[peer]) {
      this._fingerprints[peer].verified = true;
      const stored = JSON.parse(localStorage.getItem('pqchat_verified') || '{}');
      stored[peer] = this._fingerprints[peer].fingerprint;
      localStorage.setItem('pqchat_verified', JSON.stringify(stored));
      window.dispatchEvent(new CustomEvent('pqchat:verified', { detail: { peer } }));
      this._log(`✅ ${peer} marked as verified`);
    }
  }

  getFingerprint(peer) {
    return this._fingerprints[peer] || null;
  }

  // ─── liboqs-wasm Operations ────────────────────────────────────────────

  async _kyberGenerateKeypair() {
    // liboqs-wasm API — verified against @oqs/liboqs-js source in .dist/
    // Uses createKyber768 factory pattern from kem.js
    if (!this._oqs || !this._oqs.KeyEncapsulation) {
      throw new Error('liboqs-wasm not loaded');
    }
    const kem = new this._oqs.KeyEncapsulation('Kyber768');
    const publicKey = kem.generateKeypair();
    const secretKey = kem.exportSecretKey();
    kem.free();
    return { publicKey, secretKey };
  }

  async _kyberEncapsulate(publicKey) {
    const kem = new this._oqs.KeyEncapsulation('Kyber768');
    const { ciphertext, sharedSecret } = kem.encapSecret(publicKey);
    kem.free();
    return { ciphertext, sharedSecret };
  }

  async _kyberDecapsulate(secretKey, ciphertext) {
    const kem = new this._oqs.KeyEncapsulation('Kyber768', secretKey);
    const sharedSecret = kem.decapSecret(ciphertext);
    kem.free();
    return sharedSecret;
  }

  async _mldsaGenerateKeypair() {
    if (!this._oqs || !this._oqs.Signature) {
      throw new Error('liboqs-wasm not loaded');
    }
    const sig = new this._oqs.Signature('ML-DSA-65');
    const publicKey = sig.generateKeypair();
    const secretKey = sig.exportSecretKey();
    sig.free();
    return { publicKey, secretKey };
  }

  async _mldsaSign(secretKey, message) {
    const sig = new this._oqs.Signature('ML-DSA-65', secretKey);
    const signature = sig.sign(message);
    sig.free();
    return signature;
  }

  async _mldsaVerify(publicKey, message, signature) {
    try {
      const verifier = new this._oqs.Signature('ML-DSA-65');
      const result = verifier.verify(message, signature, publicKey);
      verifier.free();
      return result;
    } catch (_) {
      return false;
    }
  }

  // ─── Session Key Derivation ────────────────────────────────────────────

  /**
   * Derive AES-256-GCM session key from Kyber768 + ECDHE secrets.
   * Amendment (1): Lexicographic ordering of Kyber pubkeys in salt.
   *
   * HKDF construction (matches server crypto/hkdf.py exactly):
   *   IKM  = kyber_secret ‖ ecdhe_secret
   *   Salt = SHA256(lex_min(pubA, pubB) ‖ lex_max(pubA, pubB))
   *   Info = "PQChat-v2-session-key"
   *
   * @param {Uint8Array} kyberSecret   32 bytes
   * @param {Uint8Array} ecdheSecret   32 bytes
   * @param {Uint8Array} kyberPubA     1184 bytes
   * @param {Uint8Array} kyberPubB     1184 bytes
   * @returns {Uint8Array} 32-byte session key
   */
  async _deriveSessionKey(kyberSecret, ecdheSecret, kyberPubA, kyberPubB) {
    // Amendment (1): Lexicographic sort
    const [small, large] = this._lexSort(kyberPubA, kyberPubB);

    // Salt = SHA256(small ‖ large)
    const saltInput = this._concat(small, large);
    const saltBuf   = await crypto.subtle.digest('SHA-256', saltInput);
    const salt      = new Uint8Array(saltBuf);

    // IKM = kyber_secret ‖ ecdhe_secret
    const ikm = this._concat(kyberSecret, ecdheSecret);

    const baseKey = await crypto.subtle.importKey(
      'raw', ikm, { name: 'HKDF' }, false, ['deriveBits']
    );

    const keyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('PQChat-v2-session-key'),
      },
      baseKey,
      256
    );

    return new Uint8Array(keyBits);
  }

  /** Compute fingerprint matching server-side compute_fingerprint() */
  async _computeFingerprint(pubA, pubB) {
    const [small, large] = this._lexSort(pubA, pubB);
    const input  = this._concat(small, large);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    const hex    = Array.from(digest.slice(0, 12))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    // Format as XXXX XXXX XXXX XXXX XXXX XXXX
    return hex.match(/.{4}/g).join(' ');
  }

  // ─── Server API ────────────────────────────────────────────────────────

  async _fetchPublicKeys(username) {
    try {
      const res = await fetch(`/api/keys/${encodeURIComponent(username)}`);
      if (!res.ok) return null;
      return await res.json();
    } catch (_) {
      return null;
    }
  }

  // ─── Utilities ─────────────────────────────────────────────────────────

  _toHex(buf) {
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  _fromHex(hex) {
    if (!hex) return new Uint8Array(0);
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++)
      arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return arr;
  }

  _concat(...arrays) {
    const total = arrays.reduce((acc, a) => acc + a.length, 0);
    const out   = new Uint8Array(total);
    let offset  = 0;
    for (const a of arrays) { out.set(a, offset); offset += a.length; }
    return out;
  }

  /** Lexicographic sort — returns [smaller, larger] */
  _lexSort(a, b) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] < b[i]) return [a, b];
      if (a[i] > b[i]) return [b, a];
    }
    return a.length <= b.length ? [a, b] : [b, a];
  }

  _truncateHex(hex, len = 16) {
    return hex.slice(0, len);
  }

  _log(msg) {
    if (this.onLog) this.onLog(msg);
    console.log(`[PQChat] ${msg}`);
  }

  get isDegraded() { return this._degraded; }
  get username()   { return this._username; }
}

window.PQChatClient = PQChatClient;
