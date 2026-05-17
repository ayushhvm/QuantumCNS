/**
 * PQChat v2.0 — Browser-Side Symmetric Ratchet
 *
 * Mirrors the server-side crypto/ratchet.py but runs entirely in the browser
 * using the WebCrypto API (window.crypto.subtle) for HKDF.
 *
 * Forward Secrecy:
 *   Each message_key is derived from chain_key and used exactly once.
 *   After use the message_key is discarded — past keys cannot be recovered.
 *
 * Amendment (3): reset() clears state when user clicks "Reset Session".
 *
 * DH Ratchet: NOT IMPLEMENTED (see crypto/ratchet.py for documented limitation).
 *
 * HKDF info strings must match server-side:
 *   chain key:   "PQChat-v2-chain-key"
 *   message key: "PQChat-v2-message-key"
 */

'use strict';

class SymmetricRatchetClient {
  /**
   * @param {Uint8Array} rootKey - 32-byte session key from handshake HKDF
   */
  constructor(rootKey) {
    this._chainKey = rootKey;   // current chain key state
    this._step = 0;             // message counter for UI display
  }

  get step() { return this._step; }

  /**
   * Advance the ratchet one step.
   * Returns a CryptoKey (AES-GCM, 256-bit) for exactly one encrypt/decrypt.
   * The raw key bytes are never exposed — only a non-extractable CryptoKey.
   *
   * @returns {Promise<CryptoKey>} One-time AES-GCM 256-bit key
   */
  async advance() {
    const enc = new TextEncoder();

    // Import current chain key as raw HKDF material
    const baseKey = await crypto.subtle.importKey(
      'raw',
      this._chainKey,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );

    // Derive new chain key (32 bytes) — replaces current
    const newChainBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),   // null salt → zero-filled per HKDF spec
        info: enc.encode('PQChat-v2-chain-key'),
      },
      baseKey,
      256
    );

    // Derive message key (32 bytes) — used once then discarded
    const msgKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: enc.encode('PQChat-v2-message-key'),
      },
      baseKey,
      256
    );

    // Advance state — chain key changes, message key is NOT stored
    this._chainKey = new Uint8Array(newChainBits);
    this._step += 1;

    // Return non-extractable CryptoKey — message key is never stored as bytes
    return crypto.subtle.importKey(
      'raw',
      msgKeyBits,
      { name: 'AES-GCM' },
      false,           // non-extractable
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Amendment (3): Reset ratchet to a new root key.
   * Called when "Reset Session" button is clicked.
   *
   * @param {Uint8Array} newRootKey - 32-byte key from fresh handshake
   */
  reset(newRootKey) {
    this._chainKey = newRootKey;
    this._step = 0;
  }

  /**
   * Safe summary for crypto terminal display.
   * Never exposes chain key or message key bytes.
   */
  get stateSummary() {
    const preview = Array.from(this._chainKey.slice(0, 8))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    return {
      step: this._step,
      chainKeyPreview: preview + '…',
    };
  }
}

/**
 * Manages per-conversation ratchet instances.
 */
class RatchetManager {
  constructor() {
    this._ratchets = {};  // { username: SymmetricRatchetClient }
  }

  /**
   * Initialize or replace a ratchet for a conversation.
   * @param {string} peer - username of the conversation partner
   * @param {Uint8Array} rootKey - 32-byte session key
   */
  init(peer, rootKey) {
    this._ratchets[peer] = new SymmetricRatchetClient(rootKey);
    return this._ratchets[peer];
  }

  /**
   * Get the active ratchet for a peer, or null if not initialized.
   * @param {string} peer
   */
  get(peer) {
    return this._ratchets[peer] || null;
  }

  /**
   * Amendment (3): Reset ratchet for a peer (session reset).
   * @param {string} peer
   * @param {Uint8Array} newRootKey
   */
  reset(peer, newRootKey) {
    if (this._ratchets[peer]) {
      this._ratchets[peer].reset(newRootKey);
    } else {
      this._ratchets[peer] = new SymmetricRatchetClient(newRootKey);
    }
    return this._ratchets[peer];
  }

  remove(peer) {
    delete this._ratchets[peer];
  }

  has(peer) {
    return !!this._ratchets[peer];
  }
}

// Export as module-level globals for use by crypto_client.js
window.SymmetricRatchetClient = SymmetricRatchetClient;
window.RatchetManager = RatchetManager;
