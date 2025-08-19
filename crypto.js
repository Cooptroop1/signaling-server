function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  let base64 = btoa(binary);
  const padding = (4 - base64.length % 4) % 4;
  base64 += '='.repeat(padding);
  base64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  console.log('Generated base64:', base64);
  return base64;
}

function base64ToArrayBuffer(base64) {
  base64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  const padding = (4 - base64.length % 4) % 4;
  base64 += '='.repeat(padding);
  try {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (error) {
    console.error('base64ToArrayBuffer error:', error, 'Input:', base64);
    throw new Error('Invalid base64 data');
  }
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
    const key = await window.crypto.subtle.importKey(
      'raw',
      buffer,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );
    console.log('Imported public key successfully');
    return key;
  } catch (error) {
    console.error('importPublicKey error:', error, 'Input base64:', base64);
    throw new Error('Failed to import public key');
  }
}

async function encrypt(text, master) {
  try {
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
    const result = {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv),
      salt: arrayBufferToBase64(salt)
    };
    console.log('Encryption result:', result);
    return result;
  } catch (error) {
    console.error('encrypt error:', error);
    throw new Error('Encryption failed');
  }
}

async function decrypt(encrypted, iv, salt, master) {
  try {
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
    const result = new TextDecoder().decode(decoded);
    console.log('Decryption successful, result:', result);
    return result;
  } catch (error) {
    console.error('decrypt error:', error, 'Encrypted:', encrypted, 'IV:', iv, 'Salt:', salt);
    throw new Error('Decryption failed');
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
    const encoded = new TextEncoder().encode(data);
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

async function deriveSigningKey(master) {
  try {
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw',
      master,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );
    const key = await window.crypto.subtle.deriveKey(
      { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('signing'), hash: 'SHA-256' },
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

async function deriveMessageKey(master) {
  try {
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw',
      master,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );
    const key = await window.crypto.subtle.deriveKey(
      { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('message'), hash: 'SHA-256' },
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
