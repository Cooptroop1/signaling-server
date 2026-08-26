function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = window.btoa(binary);
  // Strict validation: Check if it's valid base64
  if (!/^[A-Za-z0-9+/=]+$/.test(base64)) {
    throw new Error('Invalid base64 generated');
  }
  return base64;
}

function base64ToArrayBuffer(base64) {
  // Decode HTML entities (e.g., &#x2F; to /)
  const decodedBase64 = base64.replace(/&#x2F;/g, '/');
  // Strict validation: Check if input is valid base64
  if (!/^[A-Za-z0-9+/=]+$/.test(decodedBase64)) {
    throw new Error('Invalid base64 input');
  }
  const binary = window.atob(decodedBase64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bytesToBigInt(bytes) {
  let hex = '';
  for (let byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return BigInt('0x' + hex);
}

async function exportPublicKey(key) {
  try {
    const exported = await window.crypto.subtle.exportKey('raw', key);
    const base64 = arrayBufferToBase64(exported);
    const curve = key.algorithm && key.algorithm.namedCurve;
    if (curve === 'X25519') {
      if (exported.byteLength !== 32) throw new Error('Invalid X25519 public key length');
    } else if (base64.length < 40 || base64.length > 160) {
      throw new Error(`Invalid public key length: ${base64.length} chars`);
    }
    console.log('Exported public key:', base64);
    return base64;
  } catch (error) {
    console.error('exportPublicKey error:', error);
    throw new Error('Failed to export public key');
  }
}

async function importPublicKey(base64) {
  try {
    let buffer = base64ToArrayBuffer(base64);
    if (buffer.byteLength === 32) {
      const key = await window.crypto.subtle.importKey(
        'raw',
        buffer,
        { name: 'ECDH', namedCurve: 'X25519' },
        false,
        []
      );
      console.log('Imported X25519 public key successfully');
      return key;
    }
    if (buffer.byteLength === 96) {
      const newBuffer = new Uint8Array(97);
      newBuffer[0] = 4;
      newBuffer.set(new Uint8Array(buffer), 1);
      buffer = newBuffer.buffer;
      console.log('Prepended 0x04 to public key buffer for import');
    } else if (buffer.byteLength !== 97) {
      throw new Error(`Invalid public key length: ${buffer.byteLength} bytes (expected 32, 96 or 97)`);
    }
    const bytes = new Uint8Array(buffer);
    if (bytes[0] !== 4) {
      throw new Error('Invalid uncompressed public key prefix');
    }
    const p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319n;
    const a = p - 3n;
    const b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575n;
    const xBytes = bytes.slice(1, 49);
    const yBytes = bytes.slice(49, 97);
    const x = bytesToBigInt(xBytes);
    const y = bytesToBigInt(yBytes);
    if (x >= p || y >= p || x < 0n || y < 0n) {
      throw new Error('Public key coordinates out of range');
    }
    const y2 = (y * y) % p;
    const x3 = (x * x * x) % p;
    const ax = (a * x) % p;
    const right = (x3 + ax + b) % p;
    if (y2 !== right) {
      throw new Error('Public key point not on P-384 curve');
    }
    const key = await window.crypto.subtle.importKey(
      'raw',
      buffer,
      { name: 'ECDH', namedCurve: 'P-384' },
      false,
      []
    );
    console.log('Imported public key successfully');
    return key;
  } catch (error) {
    console.error('importPublicKey error:', error, 'Input base64:', base64);
    throw new Error('Failed to import public key');
  }
}

async function encryptBytes(key, data) {
  try {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );
    const result = {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
    console.log('encryptBytes result:', result);
    return result;
  } catch (error) {
    console.error('encryptBytes error:', error);
    throw new Error('Byte encryption failed');
  }
}

async function decryptBytes(key, encrypted, iv) {
  try {
    const result = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
      key,
      base64ToArrayBuffer(encrypted)
    );
    console.log('decryptBytes successful');
    return result;
  } catch (error) {
    console.error('decryptBytes error:', error, 'Encrypted:', encrypted, 'IV:', iv);
    throw new Error('Byte decryption failed');
  }
}

async function deriveSharedKey(privateKey, publicKey) {
  try {
    const curve = (privateKey.algorithm && privateKey.algorithm.namedCurve) || 'P-384';
    const bitLen = curve === 'X25519' ? 256 : 384;
    const sharedBits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      bitLen
    );
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw',
      sharedBits,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );
    const key = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('anonomoose-ecdh-wrap')
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    console.log('deriveSharedKey successful');
    return key;
  } catch (error) {
    console.error('deriveSharedKey error:', error);
    throw new Error('Shared key derivation failed');
  }
}

async function derivePakeWrapKey(privateKey, publicKey, roomCode) {
  const curve = (privateKey.algorithm && privateKey.algorithm.namedCurve) || 'P-384';
  const bitLen = curve === 'X25519' ? 256 : 384;
  const sharedBits = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    bitLen
  );
  const salt = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode('pake|' + (roomCode || '')));
  const hkdfKey = await window.crypto.subtle.importKey('raw', sharedBits, { name: 'HKDF' }, false, ['deriveKey']);
  return window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(salt),
      info: new TextEncoder().encode('anonomoose-pake-ecdh-v1')
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptRaw(key, data, aad) {
  try {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const params = { name: 'AES-GCM', iv };
    if (aad) {
      params.additionalData = typeof aad === 'string' ? new TextEncoder().encode(aad) : aad;
    }
    const encrypted = await window.crypto.subtle.encrypt(params, key, encoded);
    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
  } catch (error) {
    console.error('encryptRaw error:', error);
    throw new Error('Raw encryption failed');
  }
}

async function decryptRaw(key, encrypted, iv, aad) {
  try {
    const params = { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) };
    if (aad) {
      params.additionalData = typeof aad === 'string' ? new TextEncoder().encode(aad) : aad;
    }
    const decoded = await window.crypto.subtle.decrypt(
      params,
      key,
      base64ToArrayBuffer(encrypted)
    );
    return new TextDecoder().decode(decoded);
  } catch (error) {
    if (aad) {
      try {
        const decoded = await window.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
          key,
          base64ToArrayBuffer(encrypted)
        );
        return new TextDecoder().decode(decoded);
      } catch (e2) {}
    }
    console.error('decryptRaw error');
    throw new Error('Raw decryption failed');
  }
}

async function signMessage(signingKey, data) {
  try {
    const encoded = new TextEncoder().encode(data);
    const signature = arrayBufferToBase64(await window.crypto.subtle.sign(
      { name: 'HMAC' },
      signingKey,
      encoded
    ));
    console.log('signMessage successful, signature:', signature);
    return signature;
  } catch (error) {
    console.error('signMessage error:', error);
    throw new Error('Message signing failed');
  }
}

async function verifyMessage(signingKey, signature, data) {
  try {
    const encoded = new TextEncoder().encode(data);
    const result = await window.crypto.subtle.verify(
      { name: 'HMAC' },
      signingKey,
      base64ToArrayBuffer(signature),
      encoded
    );
    console.log('verifyMessage result:', result);
    return result;
  } catch (error) {
    console.error('verifyMessage error:', error);
    return false;
  }
}

async function deriveSigningKey() {
  try {
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw',
      roomMaster,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );
    const key = await window.crypto.subtle.deriveKey(
      { name: 'HKDF', salt: signingSalt, info: new TextEncoder().encode('signing'), hash: 'SHA-256' },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
    console.log('deriveSigningKey successful');
    return key;
  } catch (error) {
    console.error('deriveSigningKey error:', error);
    throw new Error('Signing key derivation failed');
  }
}

async function deriveMessageKey() {
  try {
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw',
      roomMaster,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );
    const key = await window.crypto.subtle.deriveKey(
      { name: 'HKDF', salt: messageSalt, info: new TextEncoder().encode('message'), hash: 'SHA-256' },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    console.log('deriveMessageKey successful');
    return key;
  } catch (error) {
    console.error('deriveMessageKey error:', error);
    throw new Error('Message key derivation failed');
  }
}

const ANONOMOOSE_KEY_DB = 'anonomoose-keystore';
const ANONOMOOSE_KEY_STORE = 'keys';

function generateRecoveryPhrase() {
  const bytes = window.crypto.getRandomValues(new Uint8Array(16));
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex.match(/.{1,4}/g).join('-').toUpperCase();
}

function normalizeRecoveryPhrase(phrase) {
  return String(phrase || '').toUpperCase().replace(/[^0-9A-F]/g, '');
}

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(ANONOMOOSE_KEY_DB, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(ANONOMOOSE_KEY_STORE)) {
        db.createObjectStore(ANONOMOOSE_KEY_STORE);
      }
      if (!db.objectStoreNames.contains('dr')) {
        db.createObjectStore('dr');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet(key) {
  return openKeyDb().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(ANONOMOOSE_KEY_STORE, 'readonly');
    const req = tx.objectStore(ANONOMOOSE_KEY_STORE).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }));
}

function idbSet(key, value) {
  return openKeyDb().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(ANONOMOOSE_KEY_STORE, 'readwrite');
    const req = tx.objectStore(ANONOMOOSE_KEY_STORE).put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  }));
}

async function deriveWrapKey(phrase) {
  const normalized = normalizeRecoveryPhrase(phrase);
  if (normalized.length !== 32) {
    throw new Error('Recovery phrase must be 32 hex characters');
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  const hkdfKey = await window.crypto.subtle.importKey('raw', bytes, { name: 'HKDF' }, false, ['deriveKey']);
  return window.crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('anonomoose-recovery-v1'), info: new TextEncoder().encode('wrap') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function exportIdentityPublic(key) {
  const exported = await window.crypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(exported);
}

async function importIdentityPublic(base64) {
  let buffer = base64ToArrayBuffer(base64);
  if (buffer.byteLength === 96) {
    const prefixed = new Uint8Array(97);
    prefixed[0] = 4;
    prefixed.set(new Uint8Array(buffer), 1);
    buffer = prefixed.buffer;
  } else if (buffer.byteLength !== 97) {
    throw new Error(`Invalid identity public key length: ${buffer.byteLength}`);
  }
  return window.crypto.subtle.importKey(
    'raw',
    buffer,
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['verify']
  );
}

async function signIdentitySignature(privateKey, text) {
  const signature = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-384' },
    privateKey,
    new TextEncoder().encode(text)
  );
  return arrayBufferToBase64(signature);
}

async function verifyIdentitySignature(publicB64, signatureB64, text) {
  try {
    const key = await importIdentityPublic(publicB64);
    return await window.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-384' },
      key,
      base64ToArrayBuffer(signatureB64),
      new TextEncoder().encode(text)
    );
  } catch (error) {
    console.error('verifyIdentitySignature error:', error);
    return false;
  }
}

async function persistKeyBundle(ecdh, ecdsa, phrase) {
  const wrapKey = await deriveWrapKey(phrase);
  const bundle = {
    ecdh: await window.crypto.subtle.exportKey('jwk', ecdh.privateKey),
    ecdsa: await window.crypto.subtle.exportKey('jwk', ecdsa.privateKey)
  };
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrapKey,
    new TextEncoder().encode(JSON.stringify(bundle))
  );
  const ecdhPrivate = await window.crypto.subtle.importKey(
    'jwk',
    bundle.ecdh,
    { name: 'ECDH', namedCurve: 'P-384' },
    false,
    ['deriveKey', 'deriveBits']
  );
  const ecdsaPrivate = await window.crypto.subtle.importKey(
    'jwk',
    bundle.ecdsa,
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign']
  );
  const ecdhPubB64 = await exportPublicKey(ecdh.publicKey);
  const ecdsaPubB64 = await exportIdentityPublic(ecdsa.publicKey);
  await idbSet('ecdhPrivate', ecdhPrivate);
  await idbSet('ecdsaPrivate', ecdsaPrivate);
  await idbSet('ecdhPublic', ecdh.publicKey);
  await idbSet('ecdsaPublic', ecdsa.publicKey);
  await idbSet('ecdhPubB64', ecdhPubB64);
  await idbSet('ecdsaPubB64', ecdsaPubB64);
  await idbSet('wrapped', { iv: arrayBufferToBase64(iv), data: arrayBufferToBase64(wrapped) });
  const wrappedRecord = { iv: arrayBufferToBase64(iv), data: arrayBufferToBase64(wrapped) };
  try {
    localStorage.setItem('anonomoose-wrapped', JSON.stringify(wrappedRecord));
  } catch (e) {}
  return {
    ecdhPrivate,
    ecdsaPrivate,
    ecdhPublic: ecdh.publicKey,
    ecdsaPublic: ecdsa.publicKey,
    ecdhPubB64,
    ecdsaPubB64,
    wrapped: wrappedRecord
  };
}

async function loadPersistentKeys() {
  try {
    const ecdhPrivate = await idbGet('ecdhPrivate');
    const ecdsaPrivate = await idbGet('ecdsaPrivate');
    const ecdhPublic = await idbGet('ecdhPublic');
    const ecdsaPublic = await idbGet('ecdsaPublic');
    const ecdhPubB64 = await idbGet('ecdhPubB64');
    const ecdsaPubB64 = await idbGet('ecdsaPubB64');
    if (ecdhPrivate && ecdsaPrivate && ecdhPubB64 && ecdsaPubB64) {
      return { ecdhPrivate, ecdsaPrivate, ecdhPublic, ecdsaPublic, ecdhPubB64, ecdsaPubB64 };
    }
  } catch (error) {
    console.error('loadPersistentKeys error:', error);
  }
  return null;
}

async function restorePersistentKeys(phraseOrKit) {
  const raw = String(phraseOrKit || '').trim();
  let phrase = raw;
  let wrapped = await idbGet('wrapped');
  if (!wrapped) {
    try {
      wrapped = JSON.parse(localStorage.getItem('anonomoose-wrapped') || 'null');
    } catch (e) {
      wrapped = null;
    }
  }
  const parts = raw.split('.');
  if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
    phrase = parts[0];
    wrapped = { iv: parts[1], data: parts[2] };
  }
  if (!wrapped || !wrapped.data || !wrapped.iv) {
    throw new Error('No key backup found. Paste the full recovery kit from the original device.');
  }
  const wrapKey = await deriveWrapKey(phrase);
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToArrayBuffer(wrapped.iv) },
    wrapKey,
    base64ToArrayBuffer(wrapped.data)
  );
  const bundle = JSON.parse(new TextDecoder().decode(decrypted));
  const ecdhPrivateExt = await window.crypto.subtle.importKey(
    'jwk',
    bundle.ecdh,
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const ecdsaPrivateExt = await window.crypto.subtle.importKey(
    'jwk',
    bundle.ecdsa,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign']
  );
  const ecdhPubJwk = Object.assign({}, bundle.ecdh);
  delete ecdhPubJwk.d;
  ecdhPubJwk.key_ops = [];
  const ecdsaPubJwk = Object.assign({}, bundle.ecdsa);
  delete ecdsaPubJwk.d;
  ecdsaPubJwk.key_ops = ['verify'];
  const ecdhPublic = await window.crypto.subtle.importKey(
    'jwk',
    ecdhPubJwk,
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    []
  );
  const ecdsaPublic = await window.crypto.subtle.importKey(
    'jwk',
    ecdsaPubJwk,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['verify']
  );
  const ecdh = { privateKey: ecdhPrivateExt, publicKey: ecdhPublic };
  const ecdsa = { privateKey: ecdsaPrivateExt, publicKey: ecdsaPublic };
  return persistKeyBundle(ecdh, ecdsa, phrase);
}

async function createPersistentKeys() {
  const ecdh = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const ecdsa = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify']
  );
  const phrase = generateRecoveryPhrase();
  const keys = await persistKeyBundle(ecdh, ecdsa, phrase);
  keys.recoveryPhrase = phrase;
  keys.recoveryKit = phrase + '.' + keys.wrapped.iv + '.' + keys.wrapped.data;
  return keys;
}

async function migrateLegacyLocalStorageKeys() {
  const raw = localStorage.getItem('userPrivateKey');
  if (!raw) return null;
  try {
    const jwk = JSON.parse(raw);
    const ecdhPrivateExt = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const ecdhPublic = await window.crypto.subtle.importKey(
      'jwk',
      { ...jwk, key_ops: [], d: undefined },
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );
    const ecdsa = await window.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify']
    );
    const phrase = generateRecoveryPhrase();
    const keys = await persistKeyBundle({ privateKey: ecdhPrivateExt, publicKey: ecdhPublic }, ecdsa, phrase);
    keys.recoveryPhrase = phrase;
    keys.recoveryKit = phrase + '.' + keys.wrapped.iv + '.' + keys.wrapped.data;
    localStorage.removeItem('userPrivateKey');
    return keys;
  } catch (error) {
    console.error('Legacy key migration failed:', error);
    return null;
  }
}

async function ensurePersistentKeys() {
  const existing = await loadPersistentKeys();
  if (existing) return existing;
  const migrated = await migrateLegacyLocalStorageKeys();
  if (migrated) return migrated;
  return createPersistentKeys();
}
