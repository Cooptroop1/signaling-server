function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
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
  return new Uint8Array(sharedBits);
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

// New: Double Ratchet Class
class DoubleRatchet {
  constructor(sharedSecret, remotePublicKeyBase64, isSender) {
    this.sharedSecret = sharedSecret;
    this.isSender = isSender;
    this.rootKey = null;
    this.sendingChainKey = null;
    this.receivingChainKey = null;
    this.sendMessageNum = 0;
    this.recvMessageNum = 0;
    this.previousSendNum = 0;
    this.DHs = null;
    this.DHr = null;
    this.remotePublicKeyBase64 = remotePublicKeyBase64;
    this.init();
  }

  async init() {
    this.DHs = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey']);
    this.DHr = await importPublicKey(this.remotePublicKeyBase64);
    this.rootKey = await this.hkdf(this.sharedSecret, null, 'root', 32);
    if (this.isSender) {
      this.dhRatchet(null);
      this.sendingChainKey = this.rootKey;
    } else {
      this.receivingChainKey = this.rootKey;
    }
  }

  async hkdf(input, salt, info, length) {
    const key = await crypto.subtle.importKey('raw', input, { name: 'HKDF' }, false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits({ name: 'HKDF', salt: salt || new Uint8Array(), info: new TextEncoder().encode(info), hash: 'SHA-256' }, key, length * 8);
    return new Uint8Array(derived);
  }

  async kdf_ck(ck) {
    const hmac = await crypto.subtle.importKey('raw', ck, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const messageKey = await crypto.subtle.sign({ name: 'HMAC' }, hmac, new Uint8Array([1]));
    const newCk = await crypto.subtle.sign({ name: 'HMAC' }, hmac, new Uint8Array([2]));
    return { messageKey: new Uint8Array(messageKey), newCk: new Uint8Array(newCk) };
  }

  async dhRatchet(remotePub) {
    if (remotePub) {
      this.previousSendNum = this.sendMessageNum;
      this.sendMessageNum = 0;
      this.recvMessageNum = 0;
      this.DHr = remotePub;
    }
    const dhSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: this.DHr }, this.DHs.privateKey, 256);
    const rkCk = await this.hkdf(new Uint8Array(dhSecret), null, 'dh_ratchet', 64);
    this.rootKey = rkCk.slice(0, 32);
    if (remotePub) {
      this.receivingChainKey = rkCk.slice(32);
    } else {
      this.sendingChainKey = rkCk.slice(32);
    }
    this.DHs = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey']);
  }

  async encrypt(plaintext) {
    if (!this.sendingChainKey) {
      await this.dhRatchet(null);
    }
    const { messageKey, newCk } = await this.kdf_ck(this.sendingChainKey);
    this.sendingChainKey = newCk;
    this.sendMessageNum += 1;
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM' }, false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    const header = { pn: this.previousSendNum, n: this.sendMessageNum };
    const dhPub = await exportPublicKey(this.DHs.publicKey);
    return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv), header, dhPub };
  }

  async decrypt(encrypted, iv, header, dhPub) {
    const remotePub = await importPublicKey(dhPub);
    if (remotePub !== this.DHr) {
      await this.dhRatchet(remotePub);
    }
    const skips = header.n - this.recvMessageNum;
    for (let i = 0; i < skips; i++) {
      const { newCk } = await this.kdf_ck(this.receivingChainKey);
      this.receivingChainKey = newCk;
    }
    const { messageKey, newCk } = await this.kdf_ck(this.receivingChainKey);
    this.receivingChainKey = newCk;
    this.recvMessageNum = header.n;
    const key = await crypto.subtle.importKey('raw', messageKey, { name: 'AES-GCM' }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToArrayBuffer(iv) }, key, base64ToArrayBuffer(encrypted));
    return new TextDecoder().decode(plaintext);
  }
}
