function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// HKDF implementation using HMAC (Web Crypto has no native HKDF)
async function hkdfExtract(salt, ikm) {
  const key = await crypto.subtle.importKey(
    'raw',
    salt,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', key, ikm);
}

async function hkdfExpand(prk, info, length) {
  const hashLen = 32; // SHA-256 output size
  const okm = new Uint8Array(length);
  let previous = new Uint8Array(0);
  let offset = 0;
  let counter = 1;
  while (offset < length) {
    const input = new Uint8Array(previous.byteLength + info.byteLength + 1);
    input.set(previous, 0);
    input.set(info, previous.byteLength);
    input[input.byteLength - 1] = counter;
    const key = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(prk),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const block = await crypto.subtle.sign('HMAC', key, input);
    const toCopy = Math.min(length - offset, block.byteLength);
    okm.set(new Uint8Array(block).slice(0, toCopy), offset);
    offset += toCopy;
    previous = new Uint8Array(block);
    counter++;
  }
  return okm;
}

async function hkdf(ikm, salt, info, length) {
  const prk = await hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

class DoubleRatchet {
  constructor(isInitiator, initialRootKey, remoteRatchetPub = null) {
    this.DHs = initialRootKey; // Root key
    this.DHr = remoteRatchetPub; // Remote ratchet public key
    this.CKs = null; // Sending chain key
    this.CKr = null; // Receiving chain key
    this.Ns = 0; // Sent message count
    this.Nr = 0; // Received message count
    this.PN = 0; // Previous sending chain length
    this.ratchetKeyPair = null;
    this.isInitiator = isInitiator;
    this.skipped = {}; // { MH: { N: mk } } where MH is base64 remote ratchet pub
    this.MAX_SKIP = 500; // Limit skipped keys to prevent DoS
  }

  async init() {
    this.ratchetKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'X25519' },
      true,
      ['deriveBits']
    );
    // Initial chain setup
    const dhOut = await this.calculateInitialDH();
    const rootResult = await this.KDF_RK(this.DHs, dhOut);
    this.DHs = rootResult.rk;
    if (this.isInitiator) {
      this.CKs = rootResult.ck;
    } else {
      this.CKr = rootResult.ck;
    }
  }

  async calculateInitialDH() {
    if (this.DHr == null) return new Uint8Array(32); // Dummy for initial
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'ECDH', public: this.DHr },
      this.ratchetKeyPair.privateKey,
      256
    ));
  }

  async KDF_RK(rk, dh_out) {
    const output = await hkdf(dh_out, rk, new Uint8Array(0), 64);
    return { rk: output.slice(0, 32), ck: output.slice(32) };
  }

  async KDF_CK(ck) {
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      ck,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const mk = await crypto.subtle.sign(
      'HMAC',
      hmacKey,
      new Uint8Array([0x01])
    );
    const new_ck = await crypto.subtle.sign(
      'HMAC',
      hmacKey,
      new Uint8Array([0x02])
    );
    return { mk: new Uint8Array(mk), new_ck: new Uint8Array(new_ck) };
  }

  async ratchetStep() {
    this.PN = this.Ns;
    this.Ns = 0;
    this.Nr = 0;
    // DH with current remote
    const dhOut = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: this.DHr },
      this.ratchetKeyPair.privateKey,
      256
    );
    let rootResult = await this.KDF_RK(this.DHs, new Uint8Array(dhOut));
    this.DHs = rootResult.rk;
    this.CKr = rootResult.ck; // New receiving chain
    // Generate new ratchet key pair
    this.ratchetKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'X25519' },
      true,
      ['deriveBits']
    );
    // Second DH with new private and same remote
    const dhOut2 = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: this.DHr },
      this.ratchetKeyPair.privateKey,
      256
    );
    rootResult = await this.KDF_RK(this.DHs, new Uint8Array(dhOut2));
    this.DHs = rootResult.rk;
    this.CKs = rootResult.ck; // New sending chain
  }

  async encrypt(plaintext) {
    const { mk, new_ck } = await this.KDF_CK(this.CKs);
    this.CKs = new_ck;
    this.Ns += 1;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
      'raw',
      mk,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    const header = {
      ratchetPub: arrayBufferToBase64(await crypto.subtle.exportKey('raw', this.ratchetKeyPair.publicKey)),
      PN: this.PN,
      N: this.Ns
    };
    return { header, iv: arrayBufferToBase64(iv), encrypted: arrayBufferToBase64(encrypted) };
  }

  async decrypt(header, iv, encrypted) {
    const remoteRatchetPubBuffer = base64ToArrayBuffer(header.ratchetPub);
    const remoteRatchetPub = await crypto.subtle.importKey(
      'raw',
      remoteRatchetPubBuffer,
      { name: 'ECDH', namedCurve: 'X25519' },
      false,
      []
    );
    let mk;
    const mh = header.ratchetPub; // base64 as key
    if (this.DHr === null || arrayBufferToBase64(await crypto.subtle.exportKey('raw', this.DHr)) !== mh) {
      await this.trySkippedMessages(mh);
      this.DHr = remoteRatchetPub;
      await this.ratchetStep();
      await this.trySkippedMessages(mh);
    }
    if (mh in this.skipped && header.N in this.skipped[mh]) {
      mk = this.skipped[mh][header.N];
      delete this.skipped[mh][header.N];
    } else {
      await this.trySkippedMessages(mh, header.N);
      const temp = await this.KDF_CK(this.CKr);
      mk = temp.mk;
      this.CKr = temp.new_ck;
      this.Nr += 1;
    }
    const key = await crypto.subtle.importKey(
      'raw',
      mk,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
      key,
      base64ToArrayBuffer(encrypted)
    );
    return new TextDecoder().decode(decrypted);
  }

  async trySkippedMessages(mh, until = -1) {
    if (mh in this.skipped) {
      for (let n = this.Nr; n < until || until === -1; n++) {
        if (n in this.skipped[mh]) {
          // Apply skipped
          const temp = await this.KDF_CK(this.CKr);
          this.CKr = temp.new_ck;
          this.skipped[mh][n] = temp.mk;
          this.Nr += 1;
        } else if (until !== -1) {
          const temp = await this.KDF_CK(this.CKr);
          this.CKr = temp.new_ck;
          if (!(mh in this.skipped)) this.skipped[mh] = {};
          this.skipped[mh][n] = temp.mk;
          this.Nr += 1;
          if (Object.keys(this.skipped).reduce((acc, k) => acc + Object.keys(this.skipped[k]).length, 0) > this.MAX_SKIP) {
            // Drop oldest skipped
            const oldestKey = Object.keys(this.skipped)[0];
            const oldestN = Math.min(...Object.keys(this.skipped[oldestKey]).map(Number));
            delete this.skipped[oldestKey][oldestN];
          }
        }
      }
    }
  }
}

// Old functions for relay mode (kept for compatibility)
async function encrypt(text, master) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    master,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', salt, info: new Uint8Array(0), hash: 'SHA-256' },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    derivedKey,
    encoded
  );
  return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv), salt: arrayBufferToBase64(salt) };
}

async function decrypt(encrypted, iv, salt, master) {
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    master,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', salt: base64ToArrayBuffer(salt), info: new Uint8Array(0), hash: 'SHA-256' },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const decoded = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
    derivedKey,
    base64ToArrayBuffer(encrypted)
  );
  return new TextDecoder().decode(decoded);
}

async function encryptBytes(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv) };
}

async function decryptBytes(key, encrypted, iv) {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
    key,
    base64ToArrayBuffer(encrypted)
  );
}

async function deriveSharedKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function signMessage(signingKey, data) {
  const encoded = new TextEncoder().encode(data);
  return arrayBufferToBase64(await crypto.subtle.sign(
    { name: 'HMAC' },
    signingKey,
    encoded
  ));
}

async function verifyMessage(signingKey, signature, data) {
  const encoded = new TextEncoder().encode(data);
  return crypto.subtle.verify(
    { name: 'HMAC' },
    signingKey,
    base64ToArrayBuffer(signature),
    encoded
  );
}

async function deriveSigningKey(master) {
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    master,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('signing'), hash: 'SHA-256' },
    hkdfKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify']
  );
}
