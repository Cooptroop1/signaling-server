function arrayBufferToBase64(buffer) {
  let base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const padding = (4 - base64.length % 4) % 4;
  base64 += '='.repeat(padding); // Explicitly ensure padding
  return base64;
}

function base64ToArrayBuffer(base64) {
  let binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(exported);
}

async function importPublicKey(base64) {
  return window.crypto.subtle.importKey(
    'raw',
    base64ToArrayBuffer(base64),
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    []
  );
}

async function encrypt(text, master) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const hkdfKey = await window.crypto.subtle.importKey(
    'raw',
    master,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const derivedKey = await window.crypto.subtle.deriveKey(
    { name: 'HKDF', salt, info: new Uint8Array(0), hash: 'SHA-256' },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    derivedKey,
    encoded
  );
  return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv), salt: arrayBufferToBase64(salt) };
}

async function decrypt(encrypted, iv, salt, master) {
  const hkdfKey = await window.crypto.subtle.importKey(
    'raw',
    master,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const derivedKey = await window.crypto.subtle.deriveKey(
    { name: 'HKDF', salt: base64ToArrayBuffer(salt), info: new Uint8Array(0), hash: 'SHA-256' },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const decoded = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
    derivedKey,
    base64ToArrayBuffer(encrypted)
  );
  return new TextDecoder().decode(decoded);
}

async function encryptBytes(key, data) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv) };
}

async function decryptBytes(key, encrypted, iv) {
  return window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
    key,
    base64ToArrayBuffer(encrypted)
  );
}

async function deriveSharedKey(privateKey, publicKey) {
  const sharedBits = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
  return await window.crypto.subtle.importKey(
    "raw",
    sharedBits,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptRaw(key, data) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(data); // Encode string to bytes
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv) };
}

async function signMessage(signingKey, data) {
  const encoded = new TextEncoder().encode(data);
  return arrayBufferToBase64(await window.crypto.subtle.sign(
    { name: 'HMAC' },
    signingKey,
    encoded
  ));
}

async function verifyMessage(signingKey, signature, data) {
  const encoded = new TextEncoder().encode(data);
  return await window.crypto.subtle.verify(
    { name: 'HMAC' },
    signingKey,
    base64ToArrayBuffer(signature),
    encoded
  );
}

async function deriveSigningKey(master) {
  const hkdfKey = await window.crypto.subtle.importKey(
    'raw',
    master,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  return await window.crypto.subtle.deriveKey(
    { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('signing'), hash: 'SHA-256' },
    hkdfKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}
