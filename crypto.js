let MlKem768;
(async () => {
  ({ MlKem768 } = await import('https://esm.sh/mlkem@2.3.1'));
})();

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
    throw new Error('Invalid base64 data');
  }
}

function base64ToUint8Array(base64) {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

async function exportPublicKey(key) {
  try {
    const exported = await window.crypto.subtle.exportKey('raw', key);
    const base64 = arrayBufferToBase64(exported);
    if (base64.length < 128 || base64.length > 132) {
      throw new Error(`Invalid public key length: ${base64.length} chars`);
    }
    return base64;
  } catch (error) {
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
    } else if (buffer.byteLength !== 97) {
      throw new Error(`Invalid public key length: ${buffer.byteLength} bytes`);
    }
    const key = await window.crypto.subtle.importKey(
      'raw',
      buffer,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    );
    return key;
  } catch (error) {
    throw new Error('Failed to import public key');
  }
}

async function hybridDeriveAesEncap(privateEcdh, ecdhPubBase64, kyberPubBase64) {
  try {
    const importedEcdhPub = await importPublicKey(ecdhPubBase64);
    const ecdhBits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: importedEcdhPub },
      privateEcdh,
      384
    );
    const kyberInstance = new MlKem768();
    const kyberPub = base64ToUint8Array(kyberPubBase64);
    const [kyberCt, kyberShared] = await kyberInstance.encap(kyberPub);
    const ecdhShared = new Uint8Array(ecdhBits);
    const combined = new Uint8Array(ecdhShared.length + kyberShared.length);
    combined.set(ecdhShared, 0);
    combined.set(kyberShared, ecdhShared.length);
    const digested = await window.crypto.subtle.digest('SHA-384', combined);
    const keyBits = new Uint8Array(digested).slice(0, 32);
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      keyBits,
      'AES-GCM',
      false,
      ['encrypt', 'decrypt']
    );
    return { aesKey, kyberCt: arrayBufferToBase64(kyberCt) };
  } catch (error) {
    console.error('hybridDeriveAesEncap error:', error);
    throw new Error('Hybrid key derivation (encap) failed');
  }
}

async function hybridDeriveAesDecap(privateEcdh, ecdhPubBase64, kyberCtBase64, kyberSk) {
  try {
    const importedEcdhPub = await importPublicKey(ecdhPubBase64);
    const ecdhBits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: importedEcdhPub },
      privateEcdh,
      384
    );
    const kyberInstance = new MlKem768();
    const kyberCt = base64ToUint8Array(kyberCtBase64);
    const kyberShared = await kyberInstance.decap(kyberCt, kyberSk);
    const ecdhShared = new Uint8Array(ecdhBits);
    const combined = new Uint8Array(ecdhShared.length + kyberShared.length);
    combined.set(ecdhShared, 0);
    combined.set(kyberShared, ecdhShared.length);
    const digested = await window.crypto.subtle.digest('SHA-384', combined);
    const keyBits = new Uint8Array(digested).slice(0, 32);
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      keyBits,
      'AES-GCM',
      false,
      ['encrypt', 'decrypt']
    );
    return aesKey;
  } catch (error) {
    console.error('hybridDeriveAesDecap error:', error);
    throw new Error('Hybrid key derivation (decap) failed');
  }
}

async function encryptBytes(aesKey, data) {
  try {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      data
    );
    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
  } catch (error) {
    throw new Error('Byte encryption failed');
  }
}

async function decryptBytes(aesKey, encrypted, iv) {
  try {
    return await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
      aesKey,
      base64ToArrayBuffer(encrypted)
    );
  } catch (error) {
    throw new Error('Byte decryption failed');
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
    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
  } catch (error) {
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
    throw new Error('Raw decryption failed');
  }
}

async function signMessage(signingKey, data) {
  try {
    const encoded = new TextEncoder().encode(data);
    const signature = await window.crypto.subtle.sign(
      { name: 'HMAC' },
      signingKey,
      encoded
    );
    return arrayBufferToBase64(signature);
  } catch (error) {
    throw new Error('Message signing failed');
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
    return await window.crypto.subtle.deriveKey(
      { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('message'), hash: 'SHA-256' },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    throw new Error('Message key derivation failed');
  }
}
