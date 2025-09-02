import { arrayBufferToBase64, base64ToArrayBuffer, exportPublicKey, importPublicKey, encryptBytes, decryptBytes, deriveSharedKey, encryptRaw, decryptRaw, signMessage, verifyMessage, deriveSigningKey, deriveMessageKey } from './crypto.js';

describe('Crypto Utilities', () => {
  test('arrayBufferToBase64 and base64ToArrayBuffer roundtrip', () => {
    const buffer = new TextEncoder().encode('test').buffer;
    const base64 = arrayBufferToBase64(buffer);
    const result = base64ToArrayBuffer(base64);
    expect(new Uint8Array(result)).toEqual(new Uint8Array(buffer));
  });

  test('exportPublicKey and importPublicKey roundtrip', async () => {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const exported = await exportPublicKey(keyPair.publicKey);
    const imported = await importPublicKey(exported);
    const exportedAgain = await exportPublicKey(imported);
    expect(exportedAgain).toBe(exported);
  });

  test('encryptBytes and decryptBytes roundtrip', async () => {
    const key = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const data = new TextEncoder().encode('secret data');
    const { encrypted, iv } = await encryptBytes(key, data);
    const decrypted = await decryptBytes(key, encrypted, iv);
    expect(new TextDecoder().decode(decrypted)).toBe('secret data');
  });

  test('deriveSharedKey', async () => {
    const keyPair1 = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const keyPair2 = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const shared1 = await deriveSharedKey(keyPair1.privateKey, keyPair2.publicKey);
    const shared2 = await deriveSharedKey(keyPair2.privateKey, keyPair1.publicKey);
    const exported1 = await window.crypto.subtle.exportKey('raw', shared1);
    const exported2 = await window.crypto.subtle.exportKey('raw', shared2);
    expect(arrayBufferToBase64(exported1)).toBe(arrayBufferToBase64(exported2));
  });

  test('encryptRaw and decryptRaw roundtrip', async () => {
    const key = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const data = 'secret raw data';
    const { encrypted, iv } = await encryptRaw(key, data);
    const decrypted = await decryptRaw(key, encrypted, iv);
    expect(decrypted).toBe(data);
  });

  test('signMessage and verifyMessage roundtrip', async () => {
    const signingKey = await window.crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    );
    const data = 'data to sign';
    const signature = await signMessage(signingKey, data);
    const valid = await verifyMessage(signingKey, signature, data);
    expect(valid).toBe(true);
    const invalid = await verifyMessage(signingKey, signature, 'tampered data');
    expect(invalid).toBe(false);
  });

  test('deriveSigningKey', async () => {
    const roomMaster = window.crypto.getRandomValues(new Uint8Array(32));
    const signingSalt = window.crypto.getRandomValues(new Uint8Array(16));
    const key1 = await deriveSigningKey(roomMaster, signingSalt);
    const key2 = await deriveSigningKey(roomMaster, signingSalt);
    const exported1 = await window.crypto.subtle.exportKey('raw', key1);
    const exported2 = await window.crypto.subtle.exportKey('raw', key2);
    expect(arrayBufferToBase64(exported1)).toBe(arrayBufferToBase64(exported2));
  });

  test('deriveMessageKey', async () => {
    const roomMaster = window.crypto.getRandomValues(new Uint8Array(32));
    const messageSalt = window.crypto.getRandomValues(new Uint8Array(16));
    const key1 = await deriveMessageKey(roomMaster, messageSalt);
    const key2 = await deriveMessageKey(roomMaster, messageSalt);
    const exported1 = await window.crypto.subtle.exportKey('raw', key1);
    const exported2 = await window.crypto.subtle.exportKey('raw', key2);
    expect(arrayBufferToBase64(exported1)).toBe(arrayBufferToBase64(exported2));
  });
});
