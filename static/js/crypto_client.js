// static/js/crypto_client.js
// ─────────────────────────────────────────────────────────────────────────────
// PQChat v2.0 — Browser-side post-quantum cryptography
//
// Dependencies:
//   @oqs/liboqs-js  (loaded via unpkg ESM import below)
//   WebCrypto API   (built into all modern browsers)
//   IndexedDB       (for persistent private key storage)
// ─────────────────────────────────────────────────────────────────────────────

import { createMLKEM768, createMLDSA65 }
    from "https://unpkg.com/@oqs/liboqs-js@0.15.1/src/index.js";

// ── Utility helpers ──────────────────────────────────────────────────────────

export function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

export function hexToBuf(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++)
        arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return arr;
}

function concatBufs(...arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out   = new Uint8Array(total);
    let offset  = 0;
    for (const a of arrays) { out.set(a, offset); offset += a.length; }
    return out;
}

// ── Logging ──────────────────────────────────────────────────────────────────
// Logs to console AND dispatches a custom event that the Crypto Terminal
// panel in the UI can listen to and display.

function log(level, msg) {
    const prefix = { debug: "[DEBUG]", info: "[INFO]", warn: "[WARN]", error: "[ERROR]" };
    const line   = `${new Date().toISOString()} ${prefix[level] || "[LOG]"} ${msg}`;
    console[level === "debug" ? "debug" : level === "info" ? "info" : "warn"](line);
    window.dispatchEvent(new CustomEvent("pqchat:log", { detail: { level, msg } }));
}

// ── IndexedDB key storage ────────────────────────────────────────────────────

const IDB_NAME    = "pqchat-identity";
const IDB_STORE   = "keys";
const IDB_VERSION = 1;

function openIDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(IDB_NAME, IDB_VERSION);
        req.onupgradeneeded = e => e.target.result.createObjectStore(IDB_STORE);
        req.onsuccess = e => resolve(e.target.result);
        req.onerror   = e => reject(e.target.error);
    });
}

async function idbGet(key) {
    const db  = await openIDB();
    return new Promise((resolve, reject) => {
        const tx  = db.transaction(IDB_STORE, "readonly");
        const req = tx.objectStore(IDB_STORE).get(key);
        req.onsuccess = e => resolve(e.target.result ?? null);
        req.onerror   = e => reject(e.target.error);
    });
}

async function idbSet(key, value) {
    const db  = await openIDB();
    return new Promise((resolve, reject) => {
        const tx  = db.transaction(IDB_STORE, "readwrite");
        const req = tx.objectStore(IDB_STORE).put(value, key);
        req.onsuccess = () => resolve();
        req.onerror   = e => reject(e.target.error);
    });
}

// ── HKDF (WebCrypto) ─────────────────────────────────────────────────────────
// Must produce identical output to the Python server-side derive_session_key().
// Construction:
//   IKM  = kyber_shared_secret || ecdhe_shared_secret
//   Salt = SHA-256(alice_kyber_pubkey || bob_kyber_pubkey)
//   Info = "PQChat-v2-session-key"
//   Len  = 32 bytes

async function deriveSessionKey(kyberSS, ecdheSS, aliceKyberPub, bobKyberPub) {
    const ikm  = concatBufs(kyberSS, ecdheSS);
    const salt = await crypto.subtle.digest(
        "SHA-256",
        concatBufs(aliceKyberPub, bobKyberPub)
    );

    const baseKey = await crypto.subtle.importKey(
        "raw", ikm, { name: "HKDF" }, false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(salt),
            info: new TextEncoder().encode("PQChat-v2-session-key"),
        },
        baseKey,
        256  // 32 bytes
    );
    log("debug", `HKDF session key derived — ikm_len=${ikm.length}, output=32 bytes`);
    return new Uint8Array(bits);
}

// ── Ratchet (client-side) ────────────────────────────────────────────────────

async function deriveRatchetKeys(chainKey, step) {
    const stepBytes = new Uint8Array(4);
    new DataView(stepBytes.buffer).setUint32(0, step, false);  // big-endian

    const baseKey = await crypto.subtle.importKey(
        "raw", chainKey, { name: "HKDF" }, false, ["deriveBits"]
    );

    const chainBits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: concatBufs(new TextEncoder().encode("PQChat-v2-chain-"), stepBytes),
        },
        baseKey, 256
    );

    const msgBits = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: concatBufs(new TextEncoder().encode("PQChat-v2-msg-"), stepBytes),
        },
        baseKey, 256
    );

    return {
        newChainKey: new Uint8Array(chainBits),
        messageKey:  new Uint8Array(msgBits),
    };
}

// ── AES-256-GCM ──────────────────────────────────────────────────────────────

async function aesEncrypt(messageKey, plaintext) {
    const key   = await crypto.subtle.importKey(
        "raw", messageKey, { name: "AES-GCM" }, false, ["encrypt"]
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct    = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        key,
        new TextEncoder().encode(plaintext)
    );
    // AES-GCM in WebCrypto appends the 16-byte tag to the ciphertext
    const ctArray  = new Uint8Array(ct);
    const ciphBuf  = ctArray.slice(0, ctArray.length - 16);
    const tagBuf   = ctArray.slice(ctArray.length - 16);
    return { nonce, ciphertext: ciphBuf, tag: tagBuf };
}

async function aesDecrypt(messageKey, nonce, ciphertext, tag) {
    const key = await crypto.subtle.importKey(
        "raw", messageKey, { name: "AES-GCM" }, false, ["decrypt"]
    );
    const combined = concatBufs(ciphertext, tag);
    const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        key,
        combined
    );
    return new TextDecoder().decode(pt);
}

// ── Main PQChatCrypto class ───────────────────────────────────────────────────

export class PQChatCrypto {
    constructor() {
        // Identity keys (long-term, stored in IndexedDB)
        this.dilithiumPubKey = null;   // Uint8Array
        this.dilithiumSecKey = null;   // Uint8Array
        this.ecdhIdentityKey = null;   // CryptoKeyPair

        // Per-peer session state
        // { [peerUsername]: { chainKey, step, sessionKey, established } }
        this._sessions = {};

        // Pending handshake state (while waiting for Bob's response)
        // { [peerUsername]: { kyberSecKey, ecdhPrivKey, aliceKyberPub } }
        this._pendingHandshakes = {};

        this.authToken = null;
        this.username  = null;
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    async init(username, authToken) {
        this.username  = username;
        this.authToken = authToken;
        await this._loadOrGenerateIdentityKeys();
        log("info", `PQChatCrypto initialised for ${username}`);
    }

    async _loadOrGenerateIdentityKeys() {
        const stored = await idbGet(`identity:${this.username}`);

        if (stored) {
            this.dilithiumPubKey = stored.dilithiumPubKey;
            this.dilithiumSecKey = stored.dilithiumSecKey;
            this.ecdhIdentityKey = stored.ecdhIdentityKey;
            log("info", "Identity keys loaded from IndexedDB");
            return;
        }

        log("info", "Generating new identity keys...");

        // ML-DSA-65 keypair
        const sig = await createMLDSA65();
        try {
            const { publicKey, secretKey } = sig.generateKeyPair();
            this.dilithiumPubKey = publicKey;
            this.dilithiumSecKey = secretKey;
            log("debug", `ML-DSA-65 identity keypair generated — pubkey_len=${publicKey.length}`);
        } finally {
            sig.destroy();
        }

        // ECDH P-256 identity keypair (for long-term classical identity)
        this.ecdhIdentityKey = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,   // extractable — needed to export for server registration
            ["deriveKey", "deriveBits"]
        );
        log("debug", "ECDH P-256 identity keypair generated");

        // Persist to IndexedDB — private keys never leave the browser
        await idbSet(`identity:${this.username}`, {
            dilithiumPubKey: this.dilithiumPubKey,
            dilithiumSecKey: this.dilithiumSecKey,
            ecdhIdentityKey: this.ecdhIdentityKey,
        });
        log("info", "Identity keys saved to IndexedDB");
    }

    // ── Server registration ───────────────────────────────────────────────────

    async getPublicKeysForRegistration() {
        const ecdhPubRaw = await crypto.subtle.exportKey(
            "raw", this.ecdhIdentityKey.publicKey
        );
        return {
            dilithium_public_key: bufToHex(this.dilithiumPubKey),
            ecdh_public_key:      bufToHex(new Uint8Array(ecdhPubRaw)),
        };
    }

    // ── Fingerprint ───────────────────────────────────────────────────────────

    async computeFingerprint(myDilPub, peerDilPub) {
        // Sort keys lexicographically to ensure identical fingerprints on both sides
        const myHex = bufToHex(myDilPub);
        const peerHex = bufToHex(peerDilPub);
        let combined;
        if (myHex < peerHex) {
            combined = concatBufs(myDilPub, peerDilPub);
        } else {
            combined = concatBufs(peerDilPub, myDilPub);
        }
        
        const hash     = new Uint8Array(
            await crypto.subtle.digest("SHA-256", combined)
        );
        const hex = bufToHex(hash.slice(0, 12));  // 12 bytes = 24 hex chars
        // Format as XXXX XXXX XXXX XXXX XXXX XXXX
        return hex.match(/.{4}/g).join(" ");
    }

    // ── Handshake: Alice initiates ────────────────────────────────────────────

    async initiateHandshake(targetUser, socket) {
        log("info", `Initiating PQ handshake with ${targetUser}...`);

        // 1. Generate ephemeral ML-KEM-768 keypair
        const kem = await createMLKEM768();
        let kyberPub, kyberSec;
        try {
            const kp = kem.generateKeyPair();
            kyberPub = kp.publicKey;
            kyberSec = kp.secretKey;
            log("debug", `ML-KEM-768 ephemeral keypair — pubkey_len=${kyberPub.length}`);
        } finally {
            kem.destroy();
        }

        // 2. Generate ephemeral ECDH P-256 keypair
        const ecdhEphemeral = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveBits"]
        );
        const ecdhPubRaw = new Uint8Array(
            await crypto.subtle.exportKey("raw", ecdhEphemeral.publicKey)
        );
        log("debug", `ECDH P-256 ephemeral keypair — pubkey_len=${ecdhPubRaw.length}`);

        // 3. Sign the bundle with Dilithium identity key
        const timestamp = Date.now().toString();
        const payload   = concatBufs(
            kyberPub,
            ecdhPubRaw,
            new TextEncoder().encode(timestamp)
        );

        const sig = await createMLDSA65();
        let signature;
        try {
            signature = sig.sign(payload, this.dilithiumSecKey);
            log("debug", `ML-DSA-65 handshake signature — sig_len=${signature.length}`);
        } finally {
            sig.destroy();
        }

        // 4. Store ephemeral keys for when Bob's response arrives
        this._pendingHandshakes[targetUser] = {
            kyberSecKey:  kyberSec,
            ecdhPrivKey:  ecdhEphemeral.privateKey,
            aliceKyberPub: kyberPub,
        };

        // 5. Emit to server
        socket.emit("handshake_init", {
            token:                  this.authToken,
            target_user:            targetUser,
            kyber_ephemeral_pubkey: bufToHex(kyberPub),
            ecdhe_ephemeral_pubkey: bufToHex(ecdhPubRaw),
            timestamp,
            signature:              bufToHex(signature),
        });

        log("info", `Handshake bundle sent to server for forwarding to ${targetUser}`);
    }

    // ── Handshake: Bob responds ───────────────────────────────────────────────

    async respondToHandshake(data, socket) {
        const sender = data.from;
        log("info", `Received handshake request from ${sender}`);

        // 1. Fetch sender's Dilithium public key from server
        const resp     = await fetch(`/api/keys/${sender}`);
        const keysData = await resp.json();
        if (!keysData.ok) {
            log("error", `Cannot fetch public keys for ${sender}`);
            return;
        }
        const senderDilPub = hexToBuf(keysData.dilithium_public_key);

        // 2. Verify signature
        const payload = concatBufs(
            hexToBuf(data.kyber_ephemeral_pubkey),
            hexToBuf(data.ecdhe_ephemeral_pubkey),
            new TextEncoder().encode(data.timestamp)
        );

        const sigVerifier = await createMLDSA65();
        let valid;
        try {
            valid = sigVerifier.verify(
                payload,
                hexToBuf(data.signature),
                senderDilPub
            );
        } finally {
            sigVerifier.destroy();
        }

        if (!valid) {
            log("warn", `INVALID signature from ${sender} — aborting handshake`);
            window.dispatchEvent(new CustomEvent("pqchat:security-alert", {
                detail: { msg: `Handshake from ${sender} has an invalid signature!` }
            }));
            return;
        }
        log("info", `ML-DSA-65 signature verified for ${sender}`);

        // 3. ML-KEM-768 encapsulation
        const kem = await createMLKEM768();
        let ciphertext, kyberSS;
        try {
            const enc = kem.encapsulate(hexToBuf(data.kyber_ephemeral_pubkey));
            ciphertext = enc.ciphertext;
            kyberSS    = enc.sharedSecret;
            log("debug", `ML-KEM-768 encapsulation — ct_len=${ciphertext.length}, ss_len=${kyberSS.length}`);
        } finally {
            kem.destroy();
        }

        // 4. Generate Bob's ephemeral ECDH keypair and compute shared secret
        const bobECDH    = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
        );
        const bobECDHPub = new Uint8Array(
            await crypto.subtle.exportKey("raw", bobECDH.publicKey)
        );
        const aliceECDHPub = await crypto.subtle.importKey(
            "raw",
            hexToBuf(data.ecdhe_ephemeral_pubkey),
            { name: "ECDH", namedCurve: "P-256" },
            false, []
        );
        const ecdhSSBits = await crypto.subtle.deriveBits(
            { name: "ECDH", public: aliceECDHPub },
            bobECDH.privateKey,
            256
        );
        const ecdheSS = new Uint8Array(ecdhSSBits);
        log("debug", `ECDH P-256 shared secret computed — len=${ecdheSS.length}`);

        // 5. Derive session key via HKDF
        //    Alice's kyber pub = data.kyber_ephemeral_pubkey (she's alice, we're bob)
        const aliceKyberPub = hexToBuf(data.kyber_ephemeral_pubkey);

        // Bob needs to generate his own kyber pub for HKDF salt
        // We use a fresh keypair for Bob's kyber identity in the salt
        const bobKyberEphemeral = await createMLKEM768();
        let bobKyberEphPub, bobKyberEphSec;
        try {
            const kp = bobKyberEphemeral.generateKeyPair();
            bobKyberEphPub = kp.publicKey;
            bobKyberEphSec = kp.secretKey;
        } finally {
            bobKyberEphemeral.destroy();
        }

        const sessionKey = await deriveSessionKey(
            kyberSS, ecdheSS, aliceKyberPub, bobKyberEphPub
        );
        log("info", `Session key derived — len=${sessionKey.length} bytes`);

        // 6. Initialise ratchet
        this._sessions[sender] = {
            chainKey:    sessionKey,
            step:        0,
            sessionKey,
            established: true,
        };

        // 7. Sign Bob's response bundle


        const timestamp    = Date.now().toString();
        const responsePayload = concatBufs(
            bobKyberEphPub,
            bobECDHPub,
            ciphertext,
            new TextEncoder().encode(timestamp)
        );
        const respSig = await createMLDSA65();
        let responseSig;
        try {
            responseSig = respSig.sign(responsePayload, this.dilithiumSecKey);
        } finally {
            respSig.destroy();
        }

        socket.emit("handshake_response", {
            token:                  this.authToken,
            target_user:            sender,
            kyber_ephemeral_pubkey: bufToHex(bobKyberEphPub),
            ecdhe_ephemeral_pubkey: bufToHex(bobECDHPub),
            kyber_ciphertext:       bufToHex(ciphertext),
            timestamp,
            signature:              bufToHex(responseSig),
        });

        log("info", `Handshake response sent to ${sender} — session established`);
        window.dispatchEvent(new CustomEvent("pqchat:session-established", {
            detail: { peer: sender }
        }));
    }

    // ── Handshake: Alice completes ────────────────────────────────────────────

    async completeHandshake(data) {
        const sender  = data.from;
        const pending = this._pendingHandshakes[sender];
        if (!pending) {
            log("error", `No pending handshake for ${sender}`);
            return;
        }

        log("info", `Completing handshake with ${sender}`);

        // 1. Verify Bob's signature
        const resp     = await fetch(`/api/keys/${sender}`);
        const keysData = await resp.json();
        if (!keysData.ok) {
            log("error", `Cannot fetch public keys for ${sender}`);
            return;
        }
        const senderDilPub = hexToBuf(keysData.dilithium_public_key);

        const payload = concatBufs(
            hexToBuf(data.kyber_ephemeral_pubkey),
            hexToBuf(data.ecdhe_ephemeral_pubkey),
            hexToBuf(data.kyber_ciphertext),
            new TextEncoder().encode(data.timestamp)
        );

        const sigVerifier = await createMLDSA65();
        let valid;
        try {
            valid = sigVerifier.verify(
                payload, hexToBuf(data.signature), senderDilPub
            );
        } finally {
            sigVerifier.destroy();
        }

        if (!valid) {
            log("warn", `INVALID response signature from ${sender}`);
            return;
        }

        // 2. ML-KEM-768 decapsulation
        const kem = await createMLKEM768();
        let kyberSS;
        try {
            kyberSS = kem.decapsulate(
                hexToBuf(data.kyber_ciphertext),
                pending.kyberSecKey
            );
            log("debug", `ML-KEM-768 decapsulation — ss_len=${kyberSS.length}`);
        } finally {
            kem.destroy();
        }

        // 3. ECDH shared secret
        const bobECDHPub = await crypto.subtle.importKey(
            "raw",
            hexToBuf(data.ecdhe_ephemeral_pubkey),
            { name: "ECDH", namedCurve: "P-256" },
            false, []
        );
        const ecdhSSBits = await crypto.subtle.deriveBits(
            { name: "ECDH", public: bobECDHPub },
            pending.ecdhPrivKey,
            256
        );
        const ecdheSS = new Uint8Array(ecdhSSBits);

        // 4. Derive session key — Alice is alice, so her kyber pub goes first
        const sessionKey = await deriveSessionKey(
            kyberSS, ecdheSS,
            pending.aliceKyberPub,
            hexToBuf(data.kyber_ephemeral_pubkey)
        );
        log("info", `Session key derived (Alice side) — len=${sessionKey.length} bytes`);

        // 5. Initialise ratchet
        this._sessions[sender] = {
            chainKey:    sessionKey,
            step:        0,
            sessionKey,
            established: true,
        };

        delete this._pendingHandshakes[sender];
        log("info", `Handshake with ${sender} complete — session established`);

        window.dispatchEvent(new CustomEvent("pqchat:session-established", {
            detail: { peer: sender }
        }));
    }

    // ── Message encryption/decryption ─────────────────────────────────────────

    async encryptMessage(peer, plaintext) {
        const session = this._sessions[peer];
        if (!session?.established) {
            throw new Error(`No established session with ${peer}`);
        }

        const step = session.step;
        const { newChainKey, messageKey } = await deriveRatchetKeys(
            session.chainKey, step
        );
        session.chainKey = newChainKey;
        session.step++;

        const { nonce, ciphertext, tag } = await aesEncrypt(messageKey, plaintext);
        log("debug", `Message encrypted — ratchet_step=${step}, ct_len=${ciphertext.length}`);

        return {
            nonce:        bufToHex(nonce),
            ciphertext:   bufToHex(ciphertext),
            tag:          bufToHex(tag),
            ratchet_step: step,
        };
    }

    async decryptMessage(peer, nonce_hex, ciphertext_hex, tag_hex, ratchet_step) {
        const session = this._sessions[peer];
        if (!session?.established) {
            throw new Error(`No established session with ${peer}`);
        }

        if (session.step !== ratchet_step) {
            throw new Error(
                `Ratchet step mismatch: expected ${session.step}, got ${ratchet_step}. ` +
                `Out-of-order messages are not supported.`
            );
        }

        const { newChainKey, messageKey } = await deriveRatchetKeys(
            session.chainKey, ratchet_step
        );
        session.chainKey = newChainKey;
        session.step++;

        const plaintext = await aesDecrypt(
            messageKey,
            hexToBuf(nonce_hex),
            hexToBuf(ciphertext_hex),
            hexToBuf(tag_hex)
        );
        log("debug", `Message decrypted — ratchet_step=${ratchet_step}`);
        return plaintext;
    }

    // ── Session state helpers ─────────────────────────────────────────────────

    hasSession(peer) {
        return this._sessions[peer]?.established === true;
    }

    getSessionKey(peer) {
        return this._sessions[peer]?.sessionKey ?? null;
    }
}
