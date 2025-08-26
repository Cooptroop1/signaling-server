function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = window.btoa(binary);
  if (!/^[A-Za-z0-9+/=]+$/.test(base64)) {
    throw new Error('Invalid base64 generated');
  }
  return base64;
}

function base64ToArrayBuffer(base64) {
  if (!/^[A-Za-z0-9+/=]+$/.test(base64)) {
    throw new Error('Invalid base64 input');
  }
  const binary = window.atob(base64);
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
    if (base64.length < 128 || base64.length > 132) { // P-384 raw key ~128 chars
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
    if (buffer.byteLength === 96) {
      const newBuffer = new Uint8Array(97);
      newBuffer[0] = 4;
      newBuffer.set(new Uint8Array(buffer), 1);
      buffer = newBuffer.buffer;
      console.log('Prepended 0x04 to public key buffer for import');
    } else if (buffer.byteLength !== 97) {
      throw new Error(`Invalid public key length: ${buffer.byteLength} bytes (expected 96 or 97 for P-384 for P-384)`);
    }
    // Validate point on curve
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

async function exportPrivateKey(key) {
  return await window.crypto.subtle.exportKey('jwk', key);
}

async function exportKeyRaw(key) {
  return arrayBufferToBase64(await window.crypto.subtle.exportKey('raw', key));
}

async function importAesKey(rawBase64) {
  return await window.crypto.subtle.importKey("raw", base64ToArrayBuffer(rawBase64), "AES-GCM", true, ["encrypt", "decrypt"]);
}

async function importHmacKey(rawBase64) {
  return await window.crypto.subtle.importKey("raw", base64ToArrayBuffer(rawBase64), { name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
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
      true,
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
      true,
      ['encrypt', 'decrypt']
    );
    console.log('deriveMessageKey successful');
    return key;
  } catch (error) {
    console.error('deriveMessageKey error:', error);
    throw new Error('Message key derivation failed');
  }
}
