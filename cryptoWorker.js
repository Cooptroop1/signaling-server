function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = self.btoa(binary);
  if (!/^[A-Za-z0-9+/=]+$/.test(base64)) {
    throw new Error('Invalid base64 generated');
  }
  return base64;
}

function base64ToArrayBuffer(base64) {
  if (!/^[A-Za-z0-9+/=]+$/.test(base64)) {
    throw new Error('Invalid base64 input');
  }
  const binary = self.atob(base64);
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
      throw new Error(`Invalid public key length: ${buffer.byteLength} bytes (expected 96 or 97 for P-384)`);
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
    const key = await self.crypto.subtle.importKey(
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

self.onmessage = async (e) => {
  const { action, params, id } = e.data;
  try {
    let result;
    switch (action) {
      case 'deriveSharedKey':
        const privateKey = await self.crypto.subtle.importKey('jwk', params.privateJwk, { name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']);
        const publicKey = await importPublicKey(params.publicBase64);
        const sharedBits = await self.crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
        result = arrayBufferToBase64(sharedBits);
        break;
      case 'encryptRaw':
        const keyEncrypt = await self.crypto.subtle.importKey('raw', base64ToArrayBuffer(params.keyBase64), 'AES-GCM', false, ['encrypt']);
        const ivEncrypt = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(params.data);
        const encrypted = await self.crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivEncrypt }, keyEncrypt, encoded);
        result = { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(ivEncrypt) };
        break;
      case 'decryptRaw':
        const keyDecrypt = await self.crypto.subtle.importKey('raw', base64ToArrayBuffer(params.keyBase64), 'AES-GCM', false, ['decrypt']);
        const decrypted = await self.crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToArrayBuffer(params.iv) }, keyDecrypt, base64ToArrayBuffer(params.encrypted));
        result = new TextDecoder().decode(decrypted);
        break;
      case 'signMessage':
        const keySign = await self.crypto.subtle.importKey('raw', base64ToArrayBuffer(params.keyBase64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const encodedSign = new TextEncoder().encode(params.data);
        const signature = await self.crypto.subtle.sign({ name: 'HMAC' }, keySign, encodedSign);
        result = arrayBufferToBase64(signature);
        break;
      case 'verifyMessage':
        const keyVerify = await self.crypto.subtle.importKey('raw', base64ToArrayBuffer(params.keyBase64), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const encodedVerify = new TextEncoder().encode(params.data);
        result = await self.crypto.subtle.verify({ name: 'HMAC' }, keyVerify, base64ToArrayBuffer(params.signature), encodedVerify);
        break;
      case 'deriveSigningKey':
        const hkdfKeySign = await self.crypto.subtle.importKey('raw', base64ToArrayBuffer(params.roomMasterBase64), { name: 'HKDF' }, false, ['deriveKey']);
        const derivedSign = await self.crypto.subtle.deriveKey(
          { name: 'HKDF', salt: base64ToArrayBuffer(params.signingSaltBase64), info: new TextEncoder().encode('signing'), hash: 'SHA-256' },
          hkdfKeySign,
          { name: 'HMAC', hash: 'SHA-256' },
          true,
          ['sign', 'verify']
        );
        result = arrayBufferToBase64(await self.crypto.subtle.exportKey('raw', derivedSign));
        break;
      case 'deriveMessageKey':
        const hkdfKeyMsg = await self.crypto.subtle.importKey('raw', base64ToArrayBuffer(params.roomMasterBase64), { name: 'HKDF' }, false, ['deriveKey']);
        const derivedMsg = await self.crypto.subtle.deriveKey(
          { name: 'HKDF', salt: base64ToArrayBuffer(params.messageSaltBase64), info: new TextEncoder().encode('message'), hash: 'SHA-256' },
          hkdfKeyMsg,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
        result = arrayBufferToBase64(await self.crypto.subtle.exportKey('raw', derivedMsg));
        break;
      default:
        throw new Error('Unknown action');
    }
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: error.message });
  }
};
