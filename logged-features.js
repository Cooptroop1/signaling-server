function hwDeviceId() {
  try {
    let id = localStorage.getItem('moose_hw_id');
    if (!id) {
      id = (crypto.randomUUID && crypto.randomUUID()) || ('d' + Math.random().toString(36).slice(2) + Date.now());
      localStorage.setItem('moose_hw_id', id);
    }
    return id;
  } catch (e) {
    return 'unknown';
  }
}
function deviceLabel() {
  const ua = navigator.userAgent || '';
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Mac/.test(ua)) return 'Mac';
  if (/Win/.test(ua)) return 'Windows';
  return 'This device';
}
async function hashPin(pin) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('moose-pin|' + accUid() + '|' + pin));
  return Array.from(new Uint8Array(buf)).map((x) => x.toString(16).padStart(2, '0')).join('');
}
function isPanicMode() { return !!window.__moosePanic; }
function isBookUnlocked() {
  if (!accGet('realPin', '')) return true;
  return !!window.__bookUnlocked && !window.__moosePanic;
}

async function requireUnlock(reason) {
  if (isPanicMode()) return false;
  if (!accGet('realPin', '')) {
    window.__bookUnlocked = true;
    return true;
  }
  if (window.__bookUnlocked) return true;
  if (typeof passkeySupported === 'function' && passkeySupported()) {
    try {
      const chal = crypto.getRandomValues(new Uint8Array(32));
      await navigator.credentials.get({
        publicKey: {
          challenge: chal,
          timeout: 60000,
          userVerification: 'required',
          rpId: location.hostname.replace(/^www\./, '')
        }
      });
      window.__bookUnlocked = true;
      return true;
    } catch (e) {}
  }
  return await promptPinModal(reason || 'Unlock moose book');
}

function promptPinModal(title) {
  return new Promise((resolve) => {
    const modal = document.getElementById('pinUnlockModal');
    const input = document.getElementById('pinUnlockInput');
    const label = document.getElementById('pinUnlockTitle');
    const err = document.getElementById('pinUnlockError');
    if (!modal || !input) {
      const typed = prompt(title || 'PIN');
      checkPinValue(typed).then(resolve);
      return;
    }
    label.textContent = title || 'Enter PIN';
    err.textContent = '';
    input.value = '';
    modal.classList.remove('hidden');
    modal.classList.add('active');
    const go = document.getElementById('pinUnlockSubmit');
    const cancel = document.getElementById('pinUnlockCancel');
    const finish = (ok) => {
      modal.classList.add('hidden');
      modal.classList.remove('active');
      go.onclick = null;
      cancel.onclick = null;
      resolve(ok);
    };
    go.onclick = async () => {
      const ok = await checkPinValue(input.value);
      if (!ok && !isPanicMode()) {
        err.textContent = 'Wrong PIN';
        return;
      }
      finish(ok || isPanicMode());
    };
    cancel.onclick = () => finish(false);
    input.focus();
  });
}

async function checkPinValue(pin) {
  if (!pin) return false;
  const h = await hashPin(pin);
  const panic = accGet('panicPin', '');
  if (panic && h === panic) {
    window.__moosePanic = true;
    window.__bookUnlocked = true;
    if (typeof renderMooseInbox === 'function') renderMooseInbox();
    if (typeof renderMooseBook === 'function') renderMooseBook();
    return true;
  }
  const real = accGet('realPin', '');
  if (real && h === real) {
    window.__moosePanic = false;
    window.__bookUnlocked = true;
    accSet('pinFails', 0);
    return true;
  }
  const fails = (Number(accGet('pinFails', 0)) || 0) + 1;
  accSet('pinFails', fails);
  if (fails >= 3) {
    accSet('pinFails', 0);
    if (typeof playBurnFlash === 'function') {
      playBurnFlash().then(() => {
        if (typeof burnAccountLocal === 'function') burnAccountLocal();
        if (typeof showStatusMessage === 'function') showStatusMessage('Three wrong PINs — book and notes burned on this phone.');
      });
    } else if (typeof burnAccountLocal === 'function') {
      burnAccountLocal();
    }
  }
  return false;
}

function getTrusted() {
  const v = accGet('trusted', []);
  return Array.isArray(v) ? v : [];
}
function isTrustedName(name) {
  return getTrusted().map((n) => String(n).toLowerCase()).includes(String(name || '').toLowerCase());
}
function setTrustedName(name, on) {
  if (!name) return;
  let list = getTrusted().filter((n) => n.toLowerCase() !== name.toLowerCase());
  if (on) list.unshift(name);
  accSet('trusted', list.slice(0, 80));
  if (typeof renderMooseBook === 'function') renderMooseBook();
}

async function trustOnServer(peerId, on) {
  const sb = window.supabaseClient;
  if (!sb || !peerId || !window.__sbSession) return;
  try {
    const uid = window.__sbSession.user.id;
    if (on) {
      await sb.from('moose_trust').upsert({ owner_id: uid, peer_id: peerId });
    } else {
      await sb.from('moose_trust').delete().eq('owner_id', uid).eq('peer_id', peerId);
    }
  } catch (e) {}
}

function setCircle(name, circle) {
  const book = getBook().map((b) => {
    if (b.name.toLowerCase() === String(name).toLowerCase()) b.circle = circle;
    return b;
  });
  accSet('book', book);
  renderMooseBook();
}

async function compressPhotoFile(file) {
  if (!file) return null;
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => {
      const i = new Image();
      i.onload = () => res(i);
      i.onerror = rej;
      i.src = url;
    });
    const max = 800;
    let w = img.width;
    let h = img.height;
    if (w > max || h > max) {
      const s = Math.min(max / w, max / h);
      w = Math.round(w * s);
      h = Math.round(h * s);
    }
    const c = document.createElement('canvas');
    c.width = w;
    c.height = h;
    c.getContext('2d').drawImage(img, 0, 0, w, h);
    return c.toDataURL('image/jpeg', 0.62);
  } finally {
    URL.revokeObjectURL(url);
  }
}

function guardScreenshots(on) {
  document.documentElement.classList.toggle('shot-guard', !!on);
}

function showSealedNoteView(opts) {
  return new Promise((resolve) => {
    const modal = document.getElementById('sealedNoteModal');
    const fromEl = document.getElementById('sealedNoteFrom');
    const meta = document.getElementById('sealedNoteMeta');
    const text = document.getElementById('sealedNoteText');
    const img = document.getElementById('sealedNoteImg');
    const ok = document.getElementById('sealedNoteOk');
    const join = document.getElementById('sealedNoteJoin');
    fromEl.textContent = opts.from || 'Someone';
    meta.textContent = opts.meta || '';
    text.textContent = opts.text || '';
    text.classList.toggle('hidden', !opts.text);
    if (opts.photo) {
      img.src = opts.photo;
      img.classList.remove('hidden');
    } else {
      img.removeAttribute('src');
      img.classList.add('hidden');
    }
    const audio = document.getElementById('sealedNoteAudio');
    if (audio) {
      if (opts.voice) {
        audio.src = opts.voice;
        audio.classList.remove('hidden');
      } else {
        audio.removeAttribute('src');
        audio.classList.add('hidden');
      }
    }
    join.classList.toggle('hidden', !opts.code);
    modal.classList.remove('hidden');
    modal.classList.add('active');
    guardScreenshots(true);
    const hide = (action) => {
      guardScreenshots(false);
      modal.classList.add('hidden');
      modal.classList.remove('active');
      ok.onclick = null;
      join.onclick = null;
      resolve(action);
    };
    ok.onclick = () => hide('burn');
    join.onclick = () => hide('join');
  });
}

async function claimThisDevice() {
  const sb = window.supabaseClient;
  if (!sb || !window.__sbSession) return;
  const uid = window.__sbSession.user.id;
  const did = hwDeviceId();
  const label = deviceLabel();
  try {
    await sb.from('profiles').update({ device_id: did, device_name: label }).eq('id', uid);
  } catch (e) {}
  try {
    await sb.from('moose_devices').upsert({
      user_id: uid,
      device_id: did,
      label,
      last_seen: new Date().toISOString(),
      revoked: false
    }, { onConflict: 'user_id,device_id' });
  } catch (e) {}
}

async function checkDeviceLock() {
  const sb = window.supabaseClient;
  if (!sb || !window.__sbSession) return;
  const uid = window.__sbSession.user.id;
  const did = hwDeviceId();
  try {
    const { data: row } = await sb.from('moose_devices')
      .select('revoked')
      .eq('user_id', uid)
      .eq('device_id', did)
      .maybeSingle();
    if (row && row.revoked) {
      kickThisDevice('This phone was revoked.');
      return;
    }
  } catch (e) {}
  try {
    const { data } = await sb.from('profiles').select('device_id').eq('id', uid).maybeSingle();
    if (data && data.device_id && data.device_id !== did) {
      kickThisDevice('Signed in on another phone.');
    }
  } catch (e) {}
}

function kickThisDevice(msg) {
  if (typeof showStatusMessage === 'function') showStatusMessage(msg || 'Signed out on this phone.');
  if (typeof playBurnFlash === 'function') {
    playBurnFlash().then(() => {
      if (typeof burnAccountLocal === 'function') burnAccountLocal();
    });
  } else if (typeof burnAccountLocal === 'function') {
    burnAccountLocal();
  }
}

async function runDeadManSwitch() {
  const hours = Number(accGet('deadManHours', 0)) || 0;
  const last = Number(accGet('lastAppOpen', 0)) || 0;
  accSet('lastAppOpen', Date.now());
  if (!hours || !last) return;
  if (Date.now() - last < hours * 3600000) return;
  if (typeof showStatusMessage === 'function') {
    showStatusMessage('Dead-man switch: unread notes burned.');
  }
  await burnAllInbox(true);
}

async function burnAllInbox(skipFlash) {
  const rows = (window.pendingInbox || []).slice();
  if (!skipFlash && typeof playBurnFlash === 'function') await playBurnFlash();
  window.pendingInbox = [];
  if (typeof renderMooseInbox === 'function') renderMooseInbox();
  if (window.sbAuth && window.sbAuth.burnAllOffline) {
    await window.sbAuth.burnAllOffline();
  } else {
    for (const msg of rows) {
      try { if (window.sbAuth) await window.sbAuth.confirmOffline(msg.id); } catch (e) {}
    }
  }
}

async function loadDeviceList() {
  const box = document.getElementById('deviceList');
  if (!box || !window.supabaseClient || !window.__sbSession) return;
  box.innerHTML = '';
  try {
    const { data, error } = await window.supabaseClient.from('moose_devices')
      .select('id, device_id, label, last_seen, revoked')
      .eq('user_id', window.__sbSession.user.id)
      .order('last_seen', { ascending: false });
    if (error || !data) {
      box.innerHTML = '<p class="text-xs text-gray-500">Run the new SQL in Supabase to list devices.</p>';
      return;
    }
    const mine = hwDeviceId();
    data.forEach((d) => {
      const row = document.createElement('div');
      row.className = 'book-row';
      const when = d.last_seen ? new Date(d.last_seen).toLocaleString() : '';
      row.innerHTML = '<strong>' + (d.label || 'Device') + '</strong> ' +
        (d.device_id === mine ? '<span class="presence-on">(this phone)</span> ' : '') +
        (d.revoked ? '<span class="presence-off">revoked</span> ' : '') +
        '<div class="text-xs text-gray-500">' + when + '</div>';
      if (d.device_id !== mine && !d.revoked) {
        const btn = document.createElement('button');
        btn.className = 'block';
        btn.textContent = 'Revoke';
        btn.onclick = async () => {
          await window.supabaseClient.from('moose_devices').update({ revoked: true }).eq('id', d.id);
          const { data: prof } = await window.supabaseClient.from('profiles').select('device_id').eq('id', window.__sbSession.user.id).maybeSingle();
          if (prof && prof.device_id === d.device_id) {
            await window.supabaseClient.from('profiles').update({ device_id: mine, device_name: deviceLabel() }).eq('id', window.__sbSession.user.id);
          }
          loadDeviceList();
        };
        row.appendChild(btn);
      }
      box.appendChild(row);
    });
  } catch (e) {
    box.innerHTML = '<p class="text-xs text-gray-500">Could not load devices.</p>';
  }
}

function fillSettingsForm() {
  const hide = document.getElementById('setHideLastSeen');
  const disc = document.getElementById('setDiscover');
  const dead = document.getElementById('setDeadMan');
  if (hide) hide.checked = !!accGet('hideLastSeen', false);
  if (disc) disc.value = accGet('discover', 'anyone') || 'anyone';
  if (dead) dead.value = String(accGet('deadManHours', 0) || 0);
}

async function saveSettings() {
  const hide = document.getElementById('setHideLastSeen');
  const disc = document.getElementById('setDiscover');
  const dead = document.getElementById('setDeadMan');
  const hideVal = !!(hide && hide.checked);
  const discVal = (disc && disc.value) || 'anyone';
  const deadVal = Number(dead && dead.value) || 0;
  accSet('hideLastSeen', hideVal);
  accSet('discover', discVal);
  accSet('deadManHours', deadVal);
  const sb = window.supabaseClient;
  if (sb && window.__sbSession) {
    const patch = { hide_last_seen: hideVal, discover: discVal };
    const { error } = await sb.from('profiles').update(patch).eq('id', window.__sbSession.user.id);
    if (error) console.warn('settings', error.message);
  }
  if (typeof showStatusMessage === 'function') showStatusMessage('Safety settings saved.');
}

async function savePinsFromForm() {
  const real = (document.getElementById('setRealPin') || {}).value || '';
  const panic = (document.getElementById('setPanicPin') || {}).value || '';
  if (real && real.length < 4) return alert('PIN must be 4+ digits');
  if (panic && panic === real) return alert('Panic PIN must be different');
  if (real) accSet('realPin', await hashPin(real));
  if (panic) accSet('panicPin', await hashPin(panic));
  if (!real && document.getElementById('clearPins') && document.getElementById('clearPins').checked) {
    accSet('realPin', '');
    accSet('panicPin', '');
    window.__bookUnlocked = true;
  }
  document.getElementById('setRealPin').value = '';
  document.getElementById('setPanicPin').value = '';
  if (typeof showStatusMessage === 'function') showStatusMessage('PIN saved on this phone only.');
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden && document.documentElement.classList.contains('shot-guard')) {
    const img = document.getElementById('sealedNoteImg');
    const text = document.getElementById('sealedNoteText');
    if (img) img.classList.add('hidden');
    if (text) text.textContent = 'Hidden';
  }
});

async function hashSecret(kind, value) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('moose|' + kind + '|' + value));
  return Array.from(new Uint8Array(buf)).map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function saveDuressPassword(pass) {
  if (!pass || pass.length < 6) throw new Error('Duress password must be 6+ characters');
  localStorage.setItem('moose_duress_hash', await hashSecret('duress', pass));
}
async function isDuressPassword(pass) {
  try {
    const stored = localStorage.getItem('moose_duress_hash');
    if (!stored || !pass) return false;
    return stored === await hashSecret('duress', pass);
  } catch (e) { return false; }
}
function enterDuressSession() {
  window.__duress = true;
  window.__moosePanic = true;
  window.__bookUnlocked = true;
  window.__sbSession = { user: { id: 'duress-local', user_metadata: { display_name: 'User' }, email: '' } };
  ['supabaseLoginModal', 'supabaseSignUpModal'].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.add('hidden');
    el.classList.remove('active');
  });
  const userInfo = document.getElementById('userInfo');
  const authLinks = document.getElementById('authLinks');
  const nameEl = document.getElementById('userDisplayName');
  if (nameEl) nameEl.textContent = 'User';
  if (userInfo) userInfo.classList.remove('hidden');
  if (authLinks) authLinks.style.display = 'none';
  window.pendingInbox = [];
  if (typeof renderMooseInbox === 'function') renderMooseInbox();
  if (typeof renderMooseBook === 'function') renderMooseBook();
  if (typeof showStatusMessage === 'function') showStatusMessage('Logged in.');
}

function watchToken() {
  try {
    let t = localStorage.getItem('moose_watch_token');
    if (!t) {
      t = (crypto.randomUUID && crypto.randomUUID()) || ('w' + Math.random().toString(36).slice(2));
      localStorage.setItem('moose_watch_token', t);
    }
    return t;
  } catch (e) { return ''; }
}
function watchBurnUrl() {
  return 'https://www.anonomoose.com/w.html#' + watchToken();
}
function bindWatchBurn() {
  try {
    if (typeof socket === 'undefined' || !socket || socket.readyState !== 1 || !code || !token) return;
    socket.send(JSON.stringify({ type: 'watch-bind', token: watchToken(), code, clientId, token }));
  } catch (e) {}
}

function dropSignalingAfterP2P() {
  const a = document.getElementById('lanDropCheck');
  const b = document.getElementById('lanDropCheckConnect');
  const on = (a && a.checked) || (b && b.checked);
  if (!on) return;
  window.__lanLock = true;
  try {
    if (socket && socket.readyState === 1) socket.close();
  } catch (e) {}
  if (typeof showStatusMessage === 'function') {
    showStatusMessage('Internet dropped. Stay on this Wi‑Fi. Refreshing burns the room.');
  }
}

function goCoverStory() {
  try { location.replace('/cover.html'); } catch (e) { location.href = '/cover.html'; }
}

const STEGO_MAGIC = [77, 79, 79, 83, 69, 49];

function embedTextInPng(image, text) {
  const srcW = image.naturalWidth || image.width;
  const srcH = image.naturalHeight || image.height;
  if (!srcW || !srcH) throw new Error('Could not read that photo');
  const minSide = 1400;
  const scale = Math.max(1, minSide / Math.min(srcW, srcH));
  const c = document.createElement('canvas');
  c.width = Math.min(2000, Math.round(srcW * scale));
  c.height = Math.min(2000, Math.round(srcH * scale));
  const ctx = c.getContext('2d');
  ctx.imageSmoothingEnabled = true;
  ctx.drawImage(image, 0, 0, c.width, c.height);
  const imgd = ctx.getImageData(0, 0, c.width, c.height);
  const bytes = STEGO_MAGIC.concat([text.length], Array.from(new TextEncoder().encode(text)));
  let bit = 0;
  for (let b = 0; b < bytes.length; b++) {
    for (let i = 7; i >= 0; i--) {
      const pi = bit * 4;
      if (pi + 3 >= imgd.data.length) throw new Error('Photo too small');
      const v = (bytes[b] >> i) & 1;
      imgd.data[pi] = (imgd.data[pi] & 0xfe) | v;
      bit++;
    }
  }
  ctx.putImageData(imgd, 0, 0);
  return c;
}
function extractTextFromPng(image) {
  const c = document.createElement('canvas');
  c.width = image.naturalWidth || image.width;
  c.height = image.naturalHeight || image.height;
  const ctx = c.getContext('2d');
  ctx.drawImage(image, 0, 0);
  const imgd = ctx.getImageData(0, 0, c.width, c.height);
  const readByte = (startBit) => {
    let v = 0;
    for (let i = 0; i < 8; i++) {
      const pi = (startBit + i) * 4;
      v = (v << 1) | (imgd.data[pi] & 1);
    }
    return v;
  };
  for (let i = 0; i < STEGO_MAGIC.length; i++) {
    if (readByte(i * 8) !== STEGO_MAGIC[i]) throw new Error('No invite in that photo');
  }
  const len = readByte(STEGO_MAGIC.length * 8);
  if (len < 1 || len > 80) throw new Error('No invite in that photo');
  const arr = [];
  for (let i = 0; i < len; i++) arr.push(readByte((STEGO_MAGIC.length + 1 + i) * 8));
  return new TextDecoder().decode(new Uint8Array(arr));
}
function canvasToBlob(canvas, mime) {
  return new Promise((resolve, reject) => {
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('Could not make photo'))), mime || 'image/png');
  });
}
async function makeStegoBlob(image, text) {
  const png = embedTextInPng(image, text);
  const blob = await canvasToBlob(png, 'image/png');
  return { blob, name: 'holiday.png', mime: 'application/octet-stream' };
}
async function offerStegoFile(blob, fileName, mime) {
  if (typeof suppressAutoBurnUntil !== 'undefined') suppressAutoBurnUntil = Date.now() + 180000;
  const file = new File([blob], fileName || 'holiday.png', { type: mime || 'application/octet-stream' });
  const mobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent || '');
  if (navigator.share && (!navigator.canShare || navigator.canShare({ files: [file] }))) {
    try {
      await navigator.share({ files: [file], title: file.name });
      return 'shared';
    } catch (e) {
      if (e && e.name === 'AbortError') return 'cancel';
    }
  }
  if (mobile) {
    showStegoKeepModal(blob, file);
    return 'modal';
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = file.name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 20000);
  return 'download';
}
function showStegoKeepModal(blob, file) {
  const m = document.getElementById('stegoShareModal');
  const img = document.getElementById('stegoSharePreview');
  if (!m || !img) return;
  const url = URL.createObjectURL(blob);
  img.src = url;
  m.classList.add('open');
  const send = document.getElementById('stegoShareSend');
  const close = document.getElementById('stegoShareClose');
  send.onclick = async () => {
    try {
      if (navigator.share) await navigator.share({ files: [file], title: file.name });
    } catch (e) {}
  };
  close.onclick = () => {
    m.classList.remove('open');
    URL.revokeObjectURL(url);
  };
}
async function fileToImage(file) {
  const url = URL.createObjectURL(file);
  try {
    return await new Promise((res, rej) => {
      const img = new Image();
      img.onload = () => res(img);
      img.onerror = rej;
      img.src = url;
    });
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
}

async function compressVoiceBlob(blob) {
  if (!blob) return null;
  if (blob.size > 350000) throw new Error('Voice note too long');
  return await new Promise((res) => {
    const r = new FileReader();
    r.onload = () => res(r.result);
    r.readAsDataURL(blob);
  });
}

async function dropToFamily(text, extra) {
  extra = extra || {};
  const book = (typeof getBook === 'function') ? getBook() : [];
  const targets = book.filter((b) => (b.circle === 'family' || (typeof isTrustedName === 'function' && isTrustedName(b.name))) && b.public_key && !isBlocked(b.name));
  const family = book.filter((b) => b.circle === 'family' && b.public_key && !isBlocked(b.name));
  const list = family.length ? family : targets.filter((b) => isTrustedName(b.name));
  if (!list.length) throw new Error('No family names with keys. Trust them and tag Family first.');
  let n = 0;
  for (const row of list) {
    try {
      userPublicKey = row.public_key;
      await sendOfflineMessage(row.name, text, extra);
      n++;
    } catch (e) { console.warn('family drop', row.name, e); }
  }
  return n;
}

let qrTimer = null;
async function rotateMooseQr() {
  const name = (typeof username !== 'undefined' && username) || '';
  const box = document.getElementById('mooseQrBox');
  const label = document.getElementById('mooseQrName');
  const hint = document.getElementById('mooseQrHint');
  if (!box) return;
  const token = (crypto.randomUUID && crypto.randomUUID()) || Math.random().toString(36).slice(2);
  const exp = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  if (window.supabaseClient && window.__sbSession && !window.__duress) {
    try {
      await window.supabaseClient.from('profiles').update({ qr_token: token, qr_expires: exp }).eq('id', window.__sbSession.user.id);
    } catch (e) {}
  }
  const url = 'https://www.anonomoose.com/?mq=' + encodeURIComponent(token);
  box.innerHTML = '';
  if (label) label.textContent = name + ' · dies in 10 min';
  if (hint) hint.textContent = 'This QR dies in 10 minutes. Open My QR again for a new one.';
  try { new QRCode(box, { text: url, width: 180, height: 180 }); } catch (e) { box.textContent = url; }
}

window.loggedFeatures = {
  requireUnlock,
  isPanicMode,
  isTrustedName,
  setTrustedName,
  trustOnServer,
  setCircle,
  compressPhotoFile,
  showSealedNoteView,
  claimThisDevice,
  checkDeviceLock,
  runDeadManSwitch,
  burnAllInbox,
  hwDeviceId,
  deviceLabel,
  isDuressPassword,
  enterDuressSession,
  dropSignalingAfterP2P,
  bindWatchBurn,
  goCoverStory,
  compressVoiceBlob,
  dropToFamily
};

document.addEventListener('DOMContentLoaded', () => {
  const safetyBtn = document.getElementById('safetySettingsBtn');
  if (safetyBtn) safetyBtn.onclick = async () => {
    const ok = await requireUnlock('Unlock settings');
    if (!ok && !isPanicMode()) return;
    fillSettingsForm();
    loadDeviceList();
    const m = document.getElementById('safetySettingsModal');
    m.classList.remove('hidden');
    m.classList.add('active');
  };
  const closeSafety = document.getElementById('closeSafetySettings');
  if (closeSafety) closeSafety.onclick = () => {
    document.getElementById('safetySettingsModal').classList.add('hidden');
    document.getElementById('safetySettingsModal').classList.remove('active');
  };
  const saveSafety = document.getElementById('saveSafetySettings');
  if (saveSafety) saveSafety.onclick = () => saveSettings();
  const savePinBtn = document.getElementById('savePinSettings');
  if (savePinBtn) savePinBtn.onclick = () => savePinsFromForm();
  const burnAllBtn = document.getElementById('burnAllInboxBtn');
  if (burnAllBtn) burnAllBtn.onclick = async () => {
    if (!confirm('Burn every sealed note in your inbox?')) return;
    await burnAllInbox(false);
  };
  const saveDuress = document.getElementById('saveDuressBtn');
  if (saveDuress) saveDuress.onclick = async () => {
    const p = (document.getElementById('setDuressPass') || {}).value || '';
    try {
      await saveDuressPassword(p);
      document.getElementById('setDuressPass').value = '';
      if (typeof showStatusMessage === 'function') showStatusMessage('Duress password saved on this phone.');
    } catch (e) { alert(e.message); }
  };
  const copyWatch = document.getElementById('copyWatchLink');
  if (copyWatch) copyWatch.onclick = async () => {
    const u = watchBurnUrl();
    try { await navigator.clipboard.writeText(u); copyWatch.textContent = 'Copied'; }
    catch (e) { prompt('Copy watch burn link', u); }
    setTimeout(() => { copyWatch.textContent = 'Copy watch burn link'; }, 1500);
  };
  const familyBtn = document.getElementById('familyDropBtn');
  if (familyBtn) familyBtn.onclick = async () => {
    const text = prompt('Note to everyone tagged Family (or trusted if none tagged):');
    if (!text) return;
    try {
      const n = await dropToFamily(text, {});
      showStatusMessage('Sealed to ' + n + ' people.');
    } catch (e) { alert(e.message); }
  };
  const encodeStego = document.getElementById('stegoEncodeBtn');
  const stegoFile = document.getElementById('stegoFile');
  if (encodeStego && stegoFile) encodeStego.onclick = async () => {
    if (!stegoFile.files || !stegoFile.files[0]) return alert('Pick a normal-looking photo first.');
    const chatOn = document.getElementById('chatContainer') && !document.getElementById('chatContainer').classList.contains('hidden');
    if (!chatOn) {
      username = (username || sessionStorage.getItem('username') || localStorage.getItem('username') || '').trim();
      if (typeof validateUsername !== 'function' || !validateUsername(username)) {
        alert('Put your name in first: tap Start Chat, type a name, come back and hide the photo — or log in.');
        document.getElementById('startChatToggleButton')?.click();
        return;
      }
      if (typeof generateCode === 'function' && (typeof validateCode !== 'function' || !validateCode(code))) {
        code = generateCode();
      }
    }
    try {
      const img = await fileToImage(stegoFile.files[0]);
      const packed = await makeStegoBlob(img, code);
      if (!chatOn && typeof window.enterHostedRoom === 'function') window.enterHostedRoom();
      await offerStegoFile(packed.blob, packed.name, packed.mime);
      showStatusMessage('Stay in this room. Send holiday.png as a FILE, not a compressed photo.');
    } catch (e) { alert(e.message || 'Could not hide the code'); }
  };
  const decodeStego = document.getElementById('stegoDecodeBtn');
  const stegoIn = document.getElementById('stegoDecodeFile');
  if (decodeStego && stegoIn) decodeStego.onclick = async () => {
    if (!stegoIn.files || !stegoIn.files[0]) return alert('Pick the photo they sent.');
    try {
      const img = await fileToImage(stegoIn.files[0]);
      const found = extractTextFromPng(img);
      showStatusMessage('Joining their room: ' + found);
      if (typeof autoConnect === 'function') autoConnect(found);
    } catch (e) { alert(e.message || 'No invite in that photo'); }
  };
});
