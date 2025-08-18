function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  let base64 = btoa(binary);
  // Ensure proper padding
  const padding = (4 - base64.length % 4) % 4;
  base64 += '='.repeat(padding);
  // Sanitize to remove any non-base64 characters
  base64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  return base64;
}

function base64ToArrayBuffer(base64) {
  // Remove any non-base64 characters and ensure padding
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
    throw error;
  }
}

async function exportPublicKey(key) {
  try {
    const exported = await window.crypto.subtle.exportKey('raw', key);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error('exportPublicKey error:', error);
    throw error;
  }
}

async function importPublicKey(base64) {
  try {
    return await window.crypto.subtle.importKey(
      'raw',
      base64ToArrayBuffer(base64),
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );
  } catch (error) {
    console.error('importPublicKey error:', error, 'Input base64:', base64);
    throw error;
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
    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv),
      salt: arrayBufferToBase64(salt)
    };
  } catch (error) {
    console.error('encrypt error:', error);
    throw error;
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
    return new TextDecoder().decode(decoded);
  } catch (error) {
    console.error('decrypt error:', error, 'Encrypted:', encrypted, 'IV:', iv, 'Salt:', salt);
    throw error;
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
    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
  } catch (error) {
    console.error('encryptBytes error:', error);
    throw error;
  }
}

async function decryptBytes(key, encrypted, iv) {
  try {
    return await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
      key,
      base64ToArrayBuffer(encrypted)
    );
  } catch (error) {
    console.error('decryptBytes error:', error, 'Encrypted:', encrypted, 'IV:', iv);
    throw error;
  }
}

async function deriveSharedKey(privateKey, publicKey) {
  try {
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
  } catch (error) {
    console.error('deriveSharedKey error:', error);
    throw error;
  }
}

async function encryptRaw(key, data) {
  try {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(data); // Encode string to bytes
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );
    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
  } catch (error) {
    console.error('encryptRaw error:', error);
    throw error;
  }
}

async function signMessage(signingKey, data) {
  try {
    const encoded = new TextEncoder().encode(data);
    return arrayBufferToBase64(await window.crypto.subtle.sign(
      { name: 'HMAC' },
      signingKey,
      encoded
    ));
  } catch (error) {
    console.error('signMessage error:', error);
    throw error;
  }
}

async function verifyMessage(signingKey, signature, data) {
  try {
    const encoded = new TextEncoder().encode(data);
    return await window.crypto.subtle.verify(
      { name: 'HMAC' },
      signingKey,
      base64ToArrayBuffer(signature),
      encoded
    );
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
    return await window.crypto.subtle.deriveKey(
      { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('signing'), hash: 'SHA-256' },
      hkdfKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  } catch (error) {
    console.error('deriveSigningKey error:', error);
    throw error;
  }
}
