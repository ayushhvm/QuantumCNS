/* global OQS */

let clientKyberPub = null;
let clientKyberPriv = null;
let clientEcdhePub = null;
let clientEcdhePriv = null;
let sessionKey = null;
let kyberDecapObj = null;
let kyberSecretKey = null;
let kyberKemDestroy = null;
let kyberFactoryCache = null;

function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToBytes(base64Str) {
  const binary = atob(base64Str);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function getMethod(obj, names) {
  for (const name of names) {
    if (typeof obj[name] === 'function') {
      return obj[name].bind(obj);
    }
  }
  return null;
}

async function ensureOqsReady() {
  if (window.OQS && typeof window.OQS.KeyEncapsulation === 'function') {
    const maybeReady = getMethod(window.OQS, ['ready', 'init']);
    if (maybeReady) {
      await maybeReady();
    }
    return { mode: 'legacy' };
  }

  if (!kyberFactoryCache) {
    try {
      const module = await import('https://cdn.jsdelivr.net/npm/@oqs/liboqs-js/src/kem.js');
      if (typeof module.createKyber512 === 'function') {
        kyberFactoryCache = module.createKyber512;
      }
    } catch (_error) {
      kyberFactoryCache = null;
    }
  }

  if (kyberFactoryCache) {
    return { mode: 'esm', createKyber512: kyberFactoryCache };
  }

  throw new Error('Kyber WASM library failed to load');
}

async function initClientCrypto() {
  const provider = await ensureOqsReady();

  if (provider.mode === 'legacy') {
    kyberDecapObj = new window.OQS.KeyEncapsulation('Kyber512');
    const generateKyberKeypair = getMethod(kyberDecapObj, ['generateKeypair', 'generate_keypair']);
    if (!generateKyberKeypair) {
      throw new Error('Kyber keypair generation method unavailable');
    }

    const kyberPubRaw = generateKyberKeypair();
    const exportKyberSecret = getMethod(kyberDecapObj, ['exportSecretKey', 'export_secret_key']);
    if (!exportKyberSecret) {
      throw new Error('Kyber secret export method unavailable');
    }

    clientKyberPub = new Uint8Array(kyberPubRaw);
    clientKyberPriv = new Uint8Array(exportKyberSecret());
    kyberSecretKey = clientKyberPriv;
  } else {
    const kem = await provider.createKyber512();
    const pair = kem.generateKeyPair();
    clientKyberPub = new Uint8Array(pair.publicKey);
    kyberSecretKey = new Uint8Array(pair.secretKey);
    clientKyberPriv = kyberSecretKey;

    kyberDecapObj = {
      decapSecret(ciphertext) {
        return kem.decapsulate(new Uint8Array(ciphertext), kyberSecretKey);
      },
    };

    kyberKemDestroy = getMethod(kem, ['destroy', 'free']);
  }

  const ecdhePair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );

  clientEcdhePriv = ecdhePair.privateKey;
  clientEcdhePub = new Uint8Array(await window.crypto.subtle.exportKey('spki', ecdhePair.publicKey));

  return {
    kyberPubB64: bytesToBase64(clientKyberPub),
    ecdhePubB64: bytesToBase64(clientEcdhePub),
  };
}

async function processHandshakeResponse(data) {
  if (!kyberDecapObj || !clientEcdhePriv) {
    throw new Error('Client crypto is not initialized');
  }

  const decap = getMethod(kyberDecapObj, ['decapSecret', 'decap_secret']);
  if (!decap) {
    throw new Error('Kyber decapsulation method unavailable');
  }

  const kyberCiphertext = base64ToBytes(data.server_kyber_ciphertext_b64);
  const kyberSharedSecret = new Uint8Array(decap(kyberCiphertext));

  const serverEcdhePub = await window.crypto.subtle.importKey(
    'spki',
    base64ToBytes(data.server_ecdhe_pub_b64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const ecdhSharedRaw = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: serverEcdhePub },
    clientEcdhePriv,
    256
  );
  const ecdhSharedSecret = new Uint8Array(ecdhSharedRaw);

  const ikm = concatBytes(kyberSharedSecret, ecdhSharedSecret);
  const hkdfKey = await window.crypto.subtle.importKey(
    'raw',
    ikm,
    'HKDF',
    false,
    ['deriveKey']
  );

  const salt = new TextEncoder().encode('PQ-Messenger-Salt-v1');
  const info = new TextEncoder().encode('session-key');

  sessionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptMessage(plaintext) {
  if (!sessionKey) {
    throw new Error('Session key is not established yet');
  }

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const encrypted = new Uint8Array(
    await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      sessionKey,
      encoded
    )
  );

  const tagLength = 16;
  const ciphertext = encrypted.slice(0, encrypted.length - tagLength);
  const tag = encrypted.slice(encrypted.length - tagLength);

  return {
    nonce: bytesToHex(iv),
    ciphertext: bytesToHex(ciphertext),
    tag: bytesToHex(tag),
  };
}

async function decryptMessage(payload) {
  if (!sessionKey) {
    return '[tampered message]';
  }

  try {
    const iv = hexToBytes(payload.nonce);
    const ciphertext = hexToBytes(payload.ciphertext);
    const tag = hexToBytes(payload.tag);
    const cipherWithTag = concatBytes(ciphertext, tag);

    const plainBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      sessionKey,
      cipherWithTag
    );
    return new TextDecoder().decode(plainBuffer);
  } catch (_error) {
    return '[tampered message]';
  }
}

window.initClientCrypto = initClientCrypto;
window.processHandshakeResponse = processHandshakeResponse;
window.encryptMessage = encryptMessage;
window.decryptMessage = decryptMessage;

window.addEventListener('beforeunload', () => {
  if (kyberKemDestroy) {
    kyberKemDestroy();
  }
});
