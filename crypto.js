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
  // Strict validation: Check if input is valid base64
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

function bigIntToBytes(bigInt, byteLength) {
  let hex = bigInt.toString(16).padStart(byteLength * 2, '0');
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, (i + 1) * 2), 16);
  }
  return bytes;
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
      throw new Error(`Invalid public key length: ${buffer.byteLength} bytes (expected 96 or 97 for P-384)`);
    }
    // Validate point on curve (basic check)
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

    // Manual subgroup validation: Check if [order] * point = infinity
    const order = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643n;
    // Simple scalar multiplication check (not full impl, but for validation: compute [order]G should be O)
    // For received point Q, compute [order]Q and check if x=y=0 (infinity)
    // But full scalar mult in JS BigInt is complex; approximate by checking if Q is not low-order
    // For full check, we'd need to implement point multiplication, but to keep light, check if [cofactor]Q is on curve and not low order
    // P-384 has cofactor 1, so order*Q should be O if Q has order dividing order
    // To implement simple: use double-and-add for scalar mult
    // Implementing basic point mult for validation
    function isInfinity(Px, Py) {
      return Px === 0n && Py === 0n;
    }

    function pointDouble(x, y) {
      if (isInfinity(x, y)) return {x: 0n, y: 0n};
      const lambda = (3n * x * x + a) * modInverse(2n * y, p) % p;
      const xr = (lambda * lambda - 2n * x) % p;
      const yr = (lambda * (x - xr) - y) % p;
      return {x: xr, y: yr};
    }

    function pointAdd(x1, y1, x2, y2) {
      if (isInfinity(x1, y1)) return {x: x2, y: y2};
      if (isInfinity(x2, y2)) return {x: x1, y: y1};
      if (x1 === x2 && y1 === -y2 % p) return {x: 0n, y: 0n};
      const lambda = (y2 - y1) * modInverse(x2 - x1, p) % p;
      const xr = (lambda * lambda - x1 - x2) % p;
      const yr = (lambda * (x1 - xr) - y1) % p;
      return {x: xr, y: yr};
    }

    function modInverse(a, m) {
      let m0 = m;
      let y = 0n, x = 1n;
      if (m === 1n) return 0n;
      while (a > 1n) {
        const q = a / m;
        let t = m;
        m = a % m;
        a = t;
        t = BigInt(y);
        y = BigInt(x) - q * BigInt(y);
        x = t;
      }
      if (x < 0n) x += m0;
      return x;
    }

    function scalarMultiply(k, Px, Py) {
      let Rx = 0n, Ry = 0n;
      let Qx = Px, Qy = Py;
      while (k > 0n) {
        if (k & 1n) {
          const R = pointAdd(Rx, Ry, Qx, Qy);
          Rx = R.x;
          Ry = R.y;
        }
        const Q = pointDouble(Qx, Qy);
        Qx = Q.x;
        Qy = Q.y;
        k >>= 1n;
      }
      return {x: Rx, y: Ry};
    }

    const result = scalarMultiply(order, x, y);
    if (!isInfinity(result.x, result.y)) {
      throw new Error('Public key point has invalid order (not in prime-order subgroup)');
    }
    console.log('Manual subgroup validation passed for public key');

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
    const sharedBits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      256
    );
    const key = await window.crypto.subtle.importKey(
      "raw",
      sharedBits,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );
    console.log('deriveSharedKey successful');
    return key;
  } catch (error) {
    console.error('deriveSharedKey error:', error);
    throw new Error('Shared key derivation failed');
  }
}

async function encryptRaw(key, data) {
  try {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );
    const result = {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
    console.log('encryptRaw result:', result);
    return result;
  } catch (error) {
    console.error('encryptRaw error:', error);
    throw new Error('Raw encryption failed');
  }
}

async function decryptRaw(key, encrypted, iv) {
  try {
    const decoded = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
      key,
      base64ToArrayBuffer(encrypted)
    );
    return new TextDecoder().decode(decoded);
  } catch (error) {
    console.error('decryptRaw error:', error, 'Encrypted:', encrypted, 'IV:', iv);
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
