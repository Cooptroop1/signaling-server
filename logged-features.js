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
    return true;
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
  deviceLabel
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
});
