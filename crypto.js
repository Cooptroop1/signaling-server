// crypto.js
(function () {
  window.CryptoUtils = window.CryptoUtils || {};

  window.CryptoUtils.generateKeyPair = async function () {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        ['deriveKey', 'deriveBits']
      );
      console.log('Generated key pair');
      return keyPair;
    } catch (error) {
      console.error('Error generating key pair:', error);
      throw error;
    }
  };

  window.CryptoUtils.importPublicKey = async function (pem) {
    try {
      const binaryDerString = atob(pem);
      const binaryDer = new Uint8Array(binaryDerString.length);
      for (let i = 0; i < binaryDerString.length; i++) {
        binaryDer[i] = binaryDerString.charCodeAt(i);
      }
      const publicKey = await window.crypto.subtle.importKey(
        'raw',
        binaryDer.buffer,
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
      );
      console.log('Imported public key successfully');
      return publicKey;
    } catch (error) {
      console.error('Error importing public key:', error);
      throw error;
    }
  };

  window.CryptoUtils.deriveSharedKey = async function (privateKey, publicKey) {
    try {
      const sharedKey = await window.crypto.subtle.deriveKey(
        { name: 'ECDH', public: publicKey },
        privateKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      console.log('deriveSharedKey successful');
      return sharedKey;
    } catch (error) {
      console.error('Error deriving shared key:', error);
      throw error;
    }
  };

  window.CryptoUtils.generateRoomKey = async function () {
    try {
      const roomKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      console.log('Generated room key');
      return roomKey;
    } catch (error) {
      console.error('Error generating room key:', error);
      throw error;
    }
  };

  window.CryptoUtils.exportKey = async function (key) {
    try {
      const exported = await window.crypto.subtle.exportKey('raw', key);
      const exportedKeyBuffer = new Uint8Array(exported);
      const exportedKeyString = btoa(String.fromCharCode.apply(null, exportedKeyBuffer));
      console.log('Exported key successfully');
      return exportedKeyString;
    } catch (error) {
      console.error('Error exporting key:', error);
      throw error;
    }
  };

  window.CryptoUtils.encryptBytes = async function (data, key, iv) {
    try {
      let dataBuffer;
      if (typeof data === 'string') {
        // Convert string to ArrayBuffer
        dataBuffer = new TextEncoder().encode(data).buffer;
      } else if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
        // Use directly if already an ArrayBuffer or ArrayBufferView
        dataBuffer = data instanceof ArrayBuffer ? data : data.buffer;
      } else {
        throw new TypeError('Data must be a string, ArrayBuffer, or ArrayBufferView');
      }

      // Ensure IV is an ArrayBuffer or ArrayBufferView
      let ivBuffer;
      if (iv instanceof ArrayBuffer) {
        ivBuffer = iv;
      } else if (ArrayBuffer.isView(iv)) {
        ivBuffer = iv.buffer;
      } else if (typeof iv === 'string') {
        // Convert base64 IV to ArrayBuffer
        const binaryString = atob(iv);
        ivBuffer = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          ivBuffer[i] = binaryString.charCodeAt(i);
        }
        ivBuffer = ivBuffer.buffer;
      } else {
        throw new TypeError('IV must be a string (base64), ArrayBuffer, or ArrayBufferView');
      }

      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: ivBuffer },
        key,
        dataBuffer
      );
      console.log('Encrypted bytes successfully');
      return new Uint8Array(encrypted);
    } catch (error) {
      console.error('encryptBytes error:', error);
      throw new Error('Byte encryption failed');
    }
  };

  window.CryptoUtils.decryptBytes = async function (encryptedData, key, iv) {
    try {
      let encryptedBuffer;
      if (encryptedData instanceof ArrayBuffer) {
        encryptedBuffer = encryptedData;
      } else if (ArrayBuffer.isView(encryptedData)) {
        encryptedBuffer = encryptedData.buffer;
      } else if (typeof encryptedData === 'string') {
        // Convert base64 encrypted data to ArrayBuffer
        const binaryString = atob(encryptedData);
        encryptedBuffer = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          encryptedBuffer[i] = binaryString.charCodeAt(i);
        }
        encryptedBuffer = encryptedBuffer.buffer;
      } else {
        throw new TypeError('Encrypted data must be a string (base64), ArrayBuffer, or ArrayBufferView');
      }

      let ivBuffer;
      if (iv instanceof ArrayBuffer) {
        ivBuffer = iv;
      } else if (ArrayBuffer.isView(iv)) {
        ivBuffer = iv.buffer;
      } else if (typeof iv === 'string') {
        // Convert base64 IV to ArrayBuffer
        const binaryString = atob(iv);
        ivBuffer = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          ivBuffer[i] = binaryString.charCodeAt(i);
        }
        ivBuffer = ivBuffer.buffer;
      } else {
        throw new TypeError('IV must be a string (base64), ArrayBuffer, or ArrayBufferView');
      }

      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBuffer },
        key,
        encryptedBuffer
      );
      console.log('Decrypted bytes successfully');
      return new Uint8Array(decrypted);
    } catch (error) {
      console.error('decryptBytes error:', error);
      throw new Error('Byte decryption failed');
    }
  };

  window.CryptoUtils.exportPublicKey = async function (keyPair) {
    try {
      const exported = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
      const exportedKeyBuffer = new Uint8Array(exported);
      const exportedKeyString = btoa(String.fromCharCode.apply(null, exportedKeyBuffer));
      console.log('Exported public key successfully');
      return exportedKeyString;
    } catch (error) {
      console.error('Error exporting public key:', error);
      throw error;
    }
  };

  window.CryptoUtils.generateIV = async function () {
    try {
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      console.log('Generated IV successfully');
      return iv;
    } catch (error) {
      console.error('Error generating IV:', error);
      throw error;
    }
  };

  window.CryptoUtils.generateSigningKey = async function () {
    try {
      const signingKey = await window.crypto.subtle.generateKey(
        { name: 'HMAC', hash: 'SHA-256' },
        true,
        ['sign', 'verify']
      );
      console.log('Generated signing key successfully');
      return signingKey;
    } catch (error) {
      console.error('Error generating signing key:', error);
      throw error;
    }
  };

  window.CryptoUtils.signMessage = async function (message, signingKey) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(message);
      const signature = await window.crypto.subtle.sign(
        'HMAC',
        signingKey,
        data
      );
      const signatureArray = new Uint8Array(signature);
      const signatureBase64 = btoa(String.fromCharCode.apply(null, signatureArray));
      console.log('Signed message successfully');
      return signatureBase64;
    } catch (error) {
      console.error('Error signing message:', error);
      throw error;
    }
  };

  window.CryptoUtils.verifySignature = async function (message, signatureBase64, signingKey) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(message);
      const signatureBinary = atob(signatureBase64);
      const signatureArray = new Uint8Array(signatureBinary.length);
      for (let i = 0; i < signatureBinary.length; i++) {
        signatureArray[i] = signatureBinary.charCodeAt(i);
      }
      const isValid = await window.crypto.subtle.verify(
        'HMAC',
        signingKey,
        signatureArray,
        data
      );
      console.log('Signature verification result:', isValid);
      return isValid;
    } catch (error) {
      console.error('Error verifying signature:', error);
      throw error;
    }
  };
})();
