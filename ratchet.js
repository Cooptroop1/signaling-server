const DR_STORE = 'dr';
const DR_MAX_SKIP = 64;

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function generateRatchetDhPair() {
  return window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    false,
    ['deriveKey', 'deriveBits']
  );
}

async function dhBytes(privateKey, publicKey) {
  const bits = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    384
  );
  return new Uint8Array(bits);
}

async function hmacSha256(keyBytes, data) {
  const key = await window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await window.crypto.subtle.sign('HMAC', key, data));
}

async function kdfCk(ck) {
  const mk = await hmacSha256(ck, new Uint8Array([0x01]));
  const nextCk = await hmacSha256(ck, new Uint8Array([0x02]));
  return { mk: mk.slice(0, 32), ck: nextCk.slice(0, 32) };
}

async function kdfRk(rk, dhOut) {
  const hkdfKey = await window.crypto.subtle.importKey('raw', dhOut, 'HKDF', false, ['deriveBits']);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: rk,
      info: new TextEncoder().encode('anonomoose-dr-v1')
    },
    hkdfKey,
    512
  );
  const u = new Uint8Array(bits);
  return { rk: u.slice(0, 32), ck: u.slice(32, 64) };
}

async function hkdfSk(ikm) {
  const hkdfKey = await window.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('anonomoose-x3dh-v1')
    },
    hkdfKey,
    256
  );
  return new Uint8Array(bits);
}

async function importMk(mkBytes) {
  return window.crypto.subtle.importKey('raw', mkBytes, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function openDrDb() {
  return openKeyDb();
}

function drGet(id) {
  return openDrDb().then(db => new Promise((resolve, reject) => {
    if (!db.objectStoreNames.contains(DR_STORE)) {
      resolve(null);
      return;
    }
    const tx = db.transaction(DR_STORE, 'readonly');
    const req = tx.objectStore(DR_STORE).get(id);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  }));
}

function drSet(id, state) {
  return openDrDb().then(db => new Promise((resolve, reject) => {
    if (!db.objectStoreNames.contains(DR_STORE)) {
      resolve();
      return;
    }
    const tx = db.transaction(DR_STORE, 'readwrite');
    const req = tx.objectStore(DR_STORE).put(state, id);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  }));
}

async function saveDrState(username, theirEcdh, state) {
  await drSet('user:' + username, state);
  if (theirEcdh) await drSet('ecdh:' + theirEcdh, state);
}

async function loadDrState(username, theirEcdh) {
  if (username) {
    const byUser = await drGet('user:' + username);
    if (byUser) return byUser;
  }
  if (theirEcdh) return drGet('ecdh:' + theirEcdh);
  return null;
}

async function drInitAlice(me, theirEcdhB64) {
  const eph = await generateRatchetDhPair();
  const theirPub = await importPublicKey(theirEcdhB64);
  const dh1 = await dhBytes(me.ecdhPrivate, theirPub);
  const dh2 = await dhBytes(eph.privateKey, theirPub);
  const sk = await hkdfSk(concatBytes(dh1, dh2));
  const { rk, ck } = await kdfRk(sk, dh2);
  return {
    dhsPrivate: eph.privateKey,
    dhsPublic: eph.publicKey,
    dhsPubB64: await exportPublicKey(eph.publicKey),
    dhr: theirEcdhB64,
    rk,
    cks: ck,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
    theirEcdh: theirEcdhB64
  };
}

async function drInitBob(me, aliceIdentityEcdh, aliceEphB64) {
  const aliceIk = await importPublicKey(aliceIdentityEcdh);
  const aliceEph = await importPublicKey(aliceEphB64);
  const dh1 = await dhBytes(me.ecdhPrivate, aliceIk);
  const dh2 = await dhBytes(me.ecdhPrivate, aliceEph);
  const sk = await hkdfSk(concatBytes(dh1, dh2));
  const { rk, ck } = await kdfRk(sk, dh2);
  return {
    dhsPrivate: me.ecdhPrivate,
    dhsPublic: me.ecdhPublic,
    dhsPubB64: me.ecdhPubB64,
    dhr: aliceEphB64,
    rk,
    cks: null,
    ckr: ck,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: {},
    theirEcdh: aliceIdentityEcdh
  };
}

async function drDhRatchet(state, theirDhB64) {
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
  state.dhr = theirDhB64;
  const theirPub = await importPublicKey(theirDhB64);
  const dhOut1 = await dhBytes(state.dhsPrivate, theirPub);
  const k1 = await kdfRk(state.rk, dhOut1);
  state.rk = k1.rk;
  state.ckr = k1.ck;
  const newPair = await generateRatchetDhPair();
  state.dhsPrivate = newPair.privateKey;
  state.dhsPublic = newPair.publicKey;
  state.dhsPubB64 = await exportPublicKey(newPair.publicKey);
  const dhOut2 = await dhBytes(state.dhsPrivate, theirPub);
  const k2 = await kdfRk(state.rk, dhOut2);
  state.rk = k2.rk;
  state.cks = k2.ck;
}

async function skipKeys(state, until) {
  if (!state.ckr) throw new Error('No receiving chain');
  if (until - state.nr > DR_MAX_SKIP) throw new Error('Too many skipped message keys');
  while (state.nr < until) {
    const { ck, mk } = await kdfCk(state.ckr);
    state.ckr = ck;
    state.skipped[state.dhr + ':' + state.nr] = arrayBufferToBase64(mk);
    state.nr++;
  }
}

async function trySkipped(state, header, bodyEnc, bodyIv, messageId) {
  const key = header.dh + ':' + header.n;
  const mkB64 = state.skipped && state.skipped[key];
  if (!mkB64) return null;
  delete state.skipped[key];
  const mk = new Uint8Array(base64ToArrayBuffer(mkB64));
  const aes = await importMk(mk);
  const aad = messageId + '|' + header.n + '|' + header.pn + '|' + header.dh;
  try {
    return await decryptRaw(aes, bodyEnc, bodyIv, aad);
  } catch (e) {
    return null;
  }
}

async function drEncrypt(username, theirEcdhB64, plaintext, messageId) {
  const me = await loadPersistentKeys();
  if (!me) throw new Error('No identity keys');
  let state = await loadDrState(username, theirEcdhB64);
  if (!state) {
    state = await drInitAlice(me, theirEcdhB64);
  } else if (!state.cks) {
    await drDhRatchet(state, state.dhr);
  }
  const n = state.ns;
  const pn = state.pn;
  const dh = state.dhsPubB64;
  const { ck, mk } = await kdfCk(state.cks);
  state.cks = ck;
  state.ns = n + 1;
  const aes = await importMk(mk);
  const aad = messageId + '|' + n + '|' + pn + '|' + dh;
  const body = await encryptRaw(aes, plaintext, aad);
  const identitySig = await signIdentitySignature(me.ecdsaPrivate, aad + body.encrypted);
  await saveDrState(username, theirEcdhB64, state);
  return {
    header: { dh, n, pn },
    body,
    identityPublic: me.ecdsaPubB64,
    identityEcdh: me.ecdhPubB64,
    identitySig
  };
}

async function drDecrypt(packet, messageId, usernameHint) {
  const me = await loadPersistentKeys();
  if (!me) throw new Error('No identity keys');
  const header = packet.header;
  if (!header || !packet.body || !packet.identityEcdh || !packet.identitySig) {
    throw new Error('Invalid ratchet packet');
  }
  const aad = messageId + '|' + header.n + '|' + header.pn + '|' + header.dh;
  const sigOk = await verifyIdentitySignature(packet.identityPublic, packet.identitySig, aad + packet.body.encrypted);
  if (!sigOk) throw new Error('Ratchet identity signature failed');
  let state = await loadDrState(usernameHint, packet.identityEcdh);
  if (!state) {
    state = await drInitBob(me, packet.identityEcdh, header.dh);
  }
  const skippedPlain = await trySkipped(state, header, packet.body.encrypted, packet.body.iv, messageId);
  if (skippedPlain !== null) {
    await saveDrState(usernameHint || 'peer', packet.identityEcdh, state);
    return skippedPlain;
  }
  if (header.dh !== state.dhr) {
    if (state.ckr) await skipKeys(state, header.pn);
    await drDhRatchet(state, header.dh);
  }
  await skipKeys(state, header.n);
  const { ck, mk } = await kdfCk(state.ckr);
  state.ckr = ck;
  state.nr = header.n + 1;
  const aes = await importMk(mk);
  const plain = await decryptRaw(aes, packet.body.encrypted, packet.body.iv, aad);
  await saveDrState(usernameHint || 'peer', packet.identityEcdh, state);
  return plain;
}

async function sealOfflinePayload(theirEcdhB64, username, plaintext, messageId) {
  const packet = await drEncrypt(username, theirEcdhB64, plaintext, messageId);
  const me = await loadPersistentKeys();
  const eph = await generateRatchetDhPair();
  const theirPub = await importPublicKey(theirEcdhB64);
  const shared = await deriveSharedKey(eph.privateKey, theirPub);
  const outer = JSON.stringify(packet);
  const { encrypted, iv } = await encryptRaw(shared, outer, messageId);
  return {
    encrypted,
    iv,
    ephemeral_public: await exportPublicKey(eph.publicKey),
    messageId
  };
}

async function openOfflinePayload(msg) {
  const me = await loadPersistentKeys();
  if (!me) throw new Error('No identity keys');
  const eph = await importPublicKey(msg.ephemeral_public);
  const shared = await deriveSharedKey(me.ecdhPrivate, eph);
  let outer;
  try {
    outer = await decryptRaw(shared, msg.encrypted, msg.iv, msg.messageId);
  } catch (e) {
    outer = await decryptRaw(shared, msg.encrypted, msg.iv);
  }
  let packet;
  try {
    packet = JSON.parse(outer);
  } catch (e) {
    return outer;
  }
  if (packet.header && packet.body) {
    return drDecrypt(packet, msg.messageId || String(msg.id || ''), msg.from);
  }
  if (packet.inner && packet.identitySig) {
    const ok = await verifyIdentitySignature(packet.identityPublic, packet.identitySig, packet.inner);
    if (!ok) throw new Error('identity');
    return packet.inner;
  }
  return outer;
}
