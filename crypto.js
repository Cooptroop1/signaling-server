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

async function deriveSharedKey(privateKey, publicKey) {
  const sharedBits = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
  return new Uint8Array(sharedBits);
}

class DoubleRatchet {
  constructor(isAlice, sharedKey, remoteRatchetPub) {
    this.isAlice = isAlice;
    this.rootKey = sharedKey;
    this.sendChainKey = null;
    this.recvChainKey = null;
    this.sendCount = 0;
    this.recvCount = 0;
    this.prevSendCount = 0;
    this.ratchetKeyPair = null;
    this.remoteRatchetPub = remoteRatchetPub;
    this.skippedMessages = {};
    this.maxSkip = 1000;

    this.ratchetKeyPair = this.generateDHKeyPair();

    if (isAlice) {
      this.dhRatchet(remoteRatchetPub);
    }
  }

  async generateDHKeyPair() {
    return await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveBits']
    );
  }

  async dh(privateKey, publicKey) {
    return await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      256
    );
  }

  async hmac(key, data) {
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    return await window.crypto.subtle.sign('HMAC', cryptoKey, data);
  }

  async kdf_rk(rk, dh_out) {
    const temp = await this.hmac(rk, dh_out);
    const new_rk = await this.hmac(temp, new Uint8Array([0x01]));
    const ck = await this.hmac(temp, new Uint8Array([0x02]));
    return [new Uint8Array(new_rk), new Uint8Array(ck)];
  }

  async kdf_ck(ck) {
    const new_ck = await this.hmac(ck, new Uint8Array([0x01]));
    const mk = await this.hmac(ck, new Uint8Array([0x02]));
    return [new Uint8Array(new_ck), new Uint8Array(mk)];
  }

  async dhRatchet(remotePub) {
    this.prevSendCount = this.sendCount;
    this.sendCount = 0;
    this.recvCount = 0;
    this.remoteRatchetPub = remotePub;

    const dh_out = await this.dh(this.ratchetKeyPair.privateKey, this.remoteRatchetPub);

    let new_rk, new_ck;
    if (this.isAlice) {
      [new_rk, new_ck] = await this.kdf_rk(this.rootKey, dh_out);
      this.recvChainKey = new_ck;
      this.sendChainKey = new_ck; // initial
    } else {
      [new_rk, new_ck] = await this.kdf_rk(this.rootKey, dh_out);
      this.sendChainKey = new_ck;
      this.recvChainKey = new_ck;
    }
    this.rootKey = new_rk;

    this.ratchetKeyPair = await this.generateDHKeyPair();

    const dh_out2 = await this.dh(this.ratchetKeyPair.privateKey, this.remoteRatchetPub);
    [this.rootKey, this.sendChainKey] = await this.kdf_rk(this.rootKey, dh_out2);
  }

  async ratchetEncrypt(plaintext) {
    if (this.sendChainKey === null) {
      this.dhRatchet(this.remoteRatchetPub); // initial if not
    }
    const [new_send_ck, mk] = await this.kdf_ck(this.sendChainKey);
    this.sendChainKey = new_send_ck;
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const header = {
      dh: await exportPublicKey(this.ratchetKeyPair.publicKey),
      pn: this.prevSendCount,
      n: this.sendCount
    };
    this.sendCount += 1;
    const headerBytes = new TextEncoder().encode(JSON.stringify(header));
    const key = await window.crypto.subtle.importKey(
      'raw',
      mk,
      'AES-GCM',
      false,
      ['encrypt']
    );
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: headerBytes },
      key,
      new TextEncoder().encode(plaintext)
    );
    return {
      header,
      ciphertext: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv)
    };
  }

  async ratchetDecrypt(header, ciphertext, iv) {
    let plaintext = this.trySkippedMessageKeys(header, ciphertext, iv);
    if (plaintext) return plaintext;

    if (header.dh !== await exportPublicKey(this.remoteRatchetPub)) {
      this.skipMessageKeys(header.pn);
      this.dhRatchet(await importPublicKey(header.dh));
    }

    this.skipMessageKeys(header.n);
    const [new_recv_ck, mk] = await this.kdf_ck(this.recvChainKey);
    this.recvChainKey = new_recv_ck;
    this.recvCount += 1;

    const headerBytes = new TextEncoder().encode(JSON.stringify(header));
    const key = await window.crypto.subtle.importKey(
      'raw',
      mk,
      'AES-GCM',
      false,
      ['decrypt']
    );
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToArrayBuffer(iv), additionalData: headerBytes },
      key,
      base64ToArrayBuffer(ciphertext)
    );
    return new TextDecoder().decode(decrypted);
  }

  async trySkippedMessageKeys(header, ciphertext, iv) {
    const key = `${await exportPublicKey(this.remoteRatchetPub)}-${header.n}`;
    if (this.skippedMessages[key]) {
      const mk = this.skippedMessages[key];
      delete this.skippedMessages[key];
      const headerBytes = new TextEncoder().encode(JSON.stringify(header));
      const keyObj = await window.crypto.subtle.importKey(
        'raw',
        mk,
        'AES-GCM',
        false,
        ['decrypt']
      );
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToArrayBuffer(iv), additionalData: headerBytes },
        keyObj,
        base64ToArrayBuffer(ciphertext)
      );
      return new TextDecoder().decode(decrypted);
    }
    return null;
  }

  async skipMessageKeys(until) {
    if (this.recvCount + this.maxSkip < until) {
      throw new Error('Too many skipped messages');
    }
    if (this.recvChainKey !== null) {
      while (this.recvCount < until) {
        const [new_recv_ck, mk] = await this.kdf_ck(this.recvChainKey);
        this.recvChainKey = new_recv_ck;
        const key = `${await exportPublicKey(this.remoteRatchetPub)}-${this.recvCount}`;
        this.skippedMessages[key] = mk;
        this.recvCount += 1;
      }
    }
  }
}

async function generateTotpSecret() {
  return otplib.authenticator.generateSecret(32); // Changed to 32 characters
}

function generateTotpUri(roomCode, secret) {
  return otplib.authenticator.keyuri(roomCode, 'Anonomoose Chat', secret);
}
