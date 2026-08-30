function accUid() {
  try { return (window.__sbSession && window.__sbSession.user && window.__sbSession.user.id) || 'guest'; } catch (e) { return 'guest'; }
}
function accGet(key, fallback) {
  try {
    const v = localStorage.getItem('moose_' + accUid() + '_' + key);
    return v ? JSON.parse(v) : fallback;
  } catch (e) { return fallback; }
}
function accSet(key, val) {
  try { localStorage.setItem('moose_' + accUid() + '_' + key, JSON.stringify(val)); } catch (e) {}
}
function getBlocked() {
  const v = accGet('blocked', []);
  return Array.isArray(v) ? v : [];
}
function isBlocked(name) { return getBlocked().map(n => String(n).toLowerCase()).includes(String(name || '').toLowerCase()); }
function blockName(name) {
  const list = getBlocked();
  if (name && !isBlocked(name)) { list.push(name); accSet('blocked', list); }
  renderMooseBook();
  renderMooseInbox();
}
function getBook() { return accGet('book', []); }
function saveBookEntry(entry) {
  if (!entry || !entry.name) return;
  const book = getBook().filter(b => b.name.toLowerCase() !== entry.name.toLowerCase());
  book.unshift({ name: entry.name, public_key: entry.public_key || '', identity_public_key: entry.identity_public_key || '', last: Date.now(), circle: entry.circle || 'other', id: entry.id || '' });
  accSet('book', book.slice(0, 40));
  renderMooseBook();
}
function lastSeenLabel(iso, status) {
  if (status === 'online') return 'on a phone now';
  if (!iso) return 'last seen unknown';
  const t = new Date(iso).getTime();
  if (!t) return 'last seen unknown';
  const mins = Math.round((Date.now() - t) / 60000);
  if (mins < 2) return 'just now';
  if (mins < 60) return mins + ' min ago';
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return hrs + ' hr ago';
  return Math.round(hrs / 24) + ' days ago';
}
async function safetyNumber(theirB64) {
  const mine = (typeof identityPubB64 !== 'undefined' && identityPubB64) ? identityPubB64 : '';
  if (!mine || !theirB64) return '';
  const a = mine < theirB64 ? mine : theirB64;
  const b = mine < theirB64 ? theirB64 : mine;
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(a + '|' + b));
  const hex = Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, '0')).join('').slice(0, 12).toUpperCase();
  return hex.slice(0, 4) + ' ' + hex.slice(4, 8) + ' ' + hex.slice(8, 12);
}
async function rememberSafety(name, theirB64) {
  if (!name || !theirB64) return { num: '', warn: false };
  const num = await safetyNumber(theirB64);
  const map = accGet('safety', {});
  const prev = map[name.toLowerCase()];
  let warn = false;
  if (prev && prev !== num) warn = true;
  map[name.toLowerCase()] = num;
  accSet('safety', map);
  return { num, warn };
}

window.pendingInbox = window.pendingInbox || [];

function updateSealedNotesBadge() {
  const wrap = document.getElementById('sealedNotesWrap');
  const dot = document.getElementById('sealedNotesDot');
  const logged = window.sbAuth && window.sbAuth.isLoggedIn();
  const n = (window.pendingInbox || []).length;
  if (wrap) {
    wrap.classList.toggle('hidden', !logged);
    wrap.classList.toggle('has-mail', !!(logged && n > 0));
  }
  if (dot) dot.classList.toggle('hidden', !(logged && n > 0));
}

function renderMooseInbox() {
  const list = document.getElementById('inboxList');
  const count = document.getElementById('inboxCount');
  updateSealedNotesBadge();
  if (!list) return;
  const logged = window.sbAuth && window.sbAuth.isLoggedIn();
  const panic = !!(window.__moosePanic);
  const allowed = !!(window.__notesUnlocked) && !panic;
  const rows = allowed ? (window.pendingInbox || []) : [];
  if (!logged) return;
  if (count) count.textContent = allowed && rows.length ? '(' + rows.length + ')' : '';
  if (!rows.length) {
    list.innerHTML = '<p class="text-sm text-gray-500">No sealed notes.</p>';
    return;
  }
  list.innerHTML = '';
  rows.forEach((msg) => {
    const row = document.createElement('div');
    row.className = 'inbox-row';
    row.innerHTML = '<div>' + (msg.kind === 'photo' ? 'Sealed photo' : msg.kind === 'meet' ? 'Meet code' : msg.kind === 'invite' ? 'Room invite' : 'Sealed note') + '</div>';
    const openBtn = document.createElement('button');
    openBtn.textContent = 'Open';
    openBtn.onclick = async () => {
      if (window.__moosePanic || !window.__notesUnlocked) return;
      if (window.loggedFeatures && window.loggedFeatures.requireUnlock) {
        const ok = await window.loggedFeatures.requireUnlock('Unlock note', true);
        if (!ok || window.__moosePanic) return;
      }
      openInboxItem(msg);
    };
    const burnBtn = document.createElement('button');
    burnBtn.textContent = 'Burn';
    burnBtn.className = 'burn';
    burnBtn.onclick = async () => {
      await playBurnFlash();
      await burnInboxItem(msg);
    };
    row.appendChild(openBtn);
    row.appendChild(burnBtn);
    list.appendChild(row);
  });
}

async function openSealedNotes() {
  window.__notesUnlocked = false;
  if (window.loggedFeatures && window.loggedFeatures.requireUnlock) {
    const ok = await window.loggedFeatures.requireUnlock('Unlock notes', true);
    if (window.__moosePanic) {
      window.__notesUnlocked = false;
      renderMooseInbox();
      const decoy = document.getElementById('sealedNotesModal');
      if (decoy) {
        decoy.classList.remove('hidden');
        decoy.classList.add('active');
      }
      return;
    }
    if (!ok) return;
  }
  window.__notesUnlocked = true;
  renderMooseInbox();
  const m = document.getElementById('sealedNotesModal');
  if (!m) return;
  m.classList.remove('hidden');
  m.classList.add('active');
}

async function openInboxItem(msg) {
  if (window.loggedFeatures && window.loggedFeatures.isPanicMode && window.loggedFeatures.isPanicMode()) return;
  try {
    const opened = await openOfflinePayload(msg);
    let parsed = null;
    try { parsed = JSON.parse(opened); } catch (e) {}
    if (parsed && (parsed.header || parsed.body || parsed.identitySig) && !parsed.text && !parsed.code) {
      throw new Error('Old sealed note. Burn it and send a new one.');
    }
    const fromName = (parsed && parsed.from) || 'Someone';
    if (isBlocked(fromName)) {
      await playBurnFlash();
      await burnInboxItem(msg);
      showStatusMessage('Blocked note burned.');
      return;
    }
    if (parsed && parsed.identity) {
      const s = await rememberSafety(fromName, parsed.identity);
      if (s.warn) {
        setTrustedName(fromName, false);
        alert('Safety number CHANGED for ' + fromName + '. Treat this as a new person until you verify.');
      }
    }
    if (parsed && parsed.type === 'meet' && parsed.code) {
      const unlockAt = Number(parsed.unlock_at) || 0;
      if (Date.now() < unlockAt) {
        const when = new Date(unlockAt).toLocaleString();
        await showSealedNoteView({
          from: fromName,
          meta: 'Meet locked until ' + when,
          text: 'Code hidden until then. Note stays sealed.'
        });
        return;
      }
      if (parsed.burn_at && Date.now() > Number(parsed.burn_at)) {
        await playBurnFlash();
        await burnInboxItem(msg);
        showStatusMessage('That meet code already burned.');
        return;
      }
      const act = await showSealedNoteView({
        from: fromName,
        meta: 'Meet code ready',
        text: parsed.text || 'Join now. Code burns after you OK.',
        code: parsed.code
      });
      if (act === 'join') {
        await playBurnFlash();
        await burnInboxItem(msg);
        if (typeof autoConnect === 'function') autoConnect(parsed.code);
        return;
      }
      await playBurnFlash();
      await burnInboxItem(msg);
      return;
    }
    if (parsed && parsed.type === 'connection-request' && parsed.code) {
      const act = await showSealedNoteView({
        from: fromName,
        meta: 'Room invite (10 min)',
        text: 'Join their room? Opening burns this invite.',
        code: parsed.code
      });
      if (act === 'join') {
        await playBurnFlash();
        await burnInboxItem(msg);
        if (typeof autoConnect === 'function') autoConnect(parsed.code);
      }
      return;
    }
    const text = (parsed && parsed.text) || (parsed && (parsed.photo || parsed.voice) ? '' : opened);
    const act = await showSealedNoteView({
      from: fromName,
      meta: parsed && parsed.voice ? 'Read-once voice' : (parsed && parsed.photo ? 'Read-once photo' : 'Sealed note'),
      text: text,
      photo: parsed && parsed.photo,
      voice: parsed && parsed.voice
    });
    await playBurnFlash();
    await burnInboxItem(msg);
  } catch (e) {
    const msgText = (e && e.message) ? e.message : 'Could not open that note.';
    const burn = confirm(msgText + '\n\nBurn this note?');
    if (burn) {
      await playBurnFlash();
      await burnInboxItem(msg);
    }
  }
}

async function burnInboxItem(msg) {
  window.pendingInbox = (window.pendingInbox || []).filter(m => m.id !== msg.id);
  if (window.sbAuth) await window.sbAuth.confirmOffline(msg.id);
  renderMooseInbox();
}

function renderMooseBook() {
  const box = document.getElementById('mooseBook');
  const list = document.getElementById('bookList');
  if (!box || !list) return;
  const logged = window.sbAuth && window.sbAuth.isLoggedIn();
  const panic = window.loggedFeatures && window.loggedFeatures.isPanicMode && window.loggedFeatures.isPanicMode();
  const book = panic ? [] : getBook();
  box.classList.toggle('hidden', !logged);
  if (!logged) return;
  if (!book.length) {
    list.innerHTML = '<p class="text-sm text-gray-500">Names you search stay here on this phone.</p>';
    return;
  }
  list.innerHTML = '';
  book.forEach((entry) => {
    const row = document.createElement('div');
    row.className = 'book-row';
    const blocked = isBlocked(entry.name);
    const trusted = typeof isTrustedName === 'function' && isTrustedName(entry.name);
    const circ = entry.circle || 'other';
    row.innerHTML = '<strong>' + entry.name + '</strong>' +
      (trusted ? ' <span class="presence-on">trusted</span>' : '') +
      ' <span class="presence-off">' + circ + '</span>' +
      (blocked ? ' <span class="presence-off">(blocked)</span>' : '');
    const circleSel = document.createElement('select');
    circleSel.className = 'circle-select';
    ['family', 'work', 'other'].forEach((c) => {
      const o = document.createElement('option');
      o.value = c;
      o.textContent = c;
      if (c === circ) o.selected = true;
      circleSel.appendChild(o);
    });
    circleSel.onchange = () => setCircle(entry.name, circleSel.value);
    const trustBtn = document.createElement('button');
    trustBtn.textContent = trusted ? 'Untrust' : 'Trust';
    trustBtn.onclick = () => {
      setTrustedName(entry.name, !trusted);
      if (entry.id) trustOnServer(entry.id, !trusted);
    };
    const openBtn = document.createElement('button');
    openBtn.textContent = 'Open';
    openBtn.onclick = () => {
      document.getElementById('searchUsernameInput').value = entry.name;
      document.getElementById('searchUserModal').classList.remove('hidden');
      document.getElementById('searchUserModal').classList.add('active');
      document.getElementById('searchSubmitButton').click();
    };
    const blockBtn = document.createElement('button');
    blockBtn.className = 'block';
    blockBtn.textContent = blocked ? 'Unblock' : 'Block';
    blockBtn.onclick = () => {
      if (blocked) {
        accSet('blocked', getBlocked().filter(n => n.toLowerCase() !== entry.name.toLowerCase()));
      } else blockName(entry.name);
      renderMooseBook();
    };
    row.appendChild(circleSel);
    row.appendChild(trustBtn);
    row.appendChild(openBtn);
    row.appendChild(blockBtn);
    list.appendChild(row);
  });
}

function showMooseQr() {
  const modal = document.getElementById('mooseQrModal');
  if (!modal) return;
  modal.classList.remove('hidden');
  modal.classList.add('active');
  if (typeof rotateMooseQr === 'function') rotateMooseQr();
  if (window._mooseQrTimer) clearInterval(window._mooseQrTimer);
  window._mooseQrTimer = setInterval(() => { if (typeof rotateMooseQr === 'function') rotateMooseQr(); }, 10 * 60 * 1000);
}

window.updateSealedNotesBadge = updateSealedNotesBadge;
window.renderMooseInbox = renderMooseInbox;
window.renderMooseBook = renderMooseBook;
window.openSealedNotes = openSealedNotes;
window.saveBookEntry = saveBookEntry;
window.isBlocked = isBlocked;
window.blockName = blockName;
window.rememberSafety = rememberSafety;
window.lastSeenLabel = lastSeenLabel;

document.addEventListener('DOMContentLoaded', () => {
  const notesBtn = document.getElementById('sealedNotesBtn');
  if (notesBtn) notesBtn.onclick = () => openSealedNotes();
  const closeNotes = document.getElementById('closeSealedNotes');
  if (closeNotes) closeNotes.onclick = () => {
    const m = document.getElementById('sealedNotesModal');
    if (!m) return;
    m.classList.add('hidden');
    m.classList.remove('active');
    window.__notesUnlocked = false;
    window.__bookUnlocked = false;
  };
  const ethBtn = document.getElementById('copyEthDonate');
  if (ethBtn) {
    ethBtn.onclick = async () => {
      const addr = '0x9D1AC5323583683666588B567C92FFCB1f41ba02';
      try {
        await navigator.clipboard.writeText(addr);
        ethBtn.textContent = 'Copied ETH address';
      } catch (e) {
        window.prompt('Copy ETH address', addr);
      }
      setTimeout(() => { ethBtn.textContent = 'ETH ' + addr; }, 1600);
    };
  }
  const qrBtn = document.getElementById('myQrButton');
  if (qrBtn) qrBtn.onclick = showMooseQr;
  const closeQr = document.getElementById('closeMooseQrButton');
  if (closeQr) closeQr.onclick = () => {
    document.getElementById('mooseQrModal').classList.add('hidden');
    document.getElementById('mooseQrModal').classList.remove('active');
  };
  const closeKit = document.getElementById('closeRecoveryKitButton');
  if (closeKit) {
    const prev = closeKit.onclick;
    closeKit.onclick = (e) => {
      const ack = document.getElementById('recoveryKitAck');
      if (ack && !ack.checked) {
        alert('Tick the box after you copy the kit.');
        return;
      }
      accSet('kitSaved', true);
      if (typeof prev === 'function') prev(e);
      document.getElementById('recoveryKitModal').classList.add('hidden');
      document.getElementById('recoveryKitModal').classList.remove('active');
    };
  }
  const find = new URLSearchParams(location.search).get('find');
  const mq = new URLSearchParams(location.search).get('mq');
  if (mq && window.sbAuth) {
    setTimeout(async () => {
      try {
        const found = await window.sbAuth.findByQr(mq);
        if (!found) {
          showStatusMessage('That QR has died. Ask them for a new one.');
          return;
        }
        const modal = document.getElementById('searchUserModal');
        modal.classList.remove('hidden');
        modal.classList.add('active');
        if (typeof showUserSearchResult === 'function') showUserSearchResult(found.display_name || found.name, found);
      } catch (e) {
        showStatusMessage('That QR has died.');
      }
    }, 900);
  } else if (find) {
    setTimeout(() => {
      const modal = document.getElementById('searchUserModal');
      const input = document.getElementById('searchUsernameInput');
      if (modal && input) {
        input.value = find;
        modal.classList.remove('hidden');
        modal.classList.add('active');
        document.getElementById('searchSubmitButton')?.click();
      }
    }, 800);
  }
  renderMooseInbox();
  renderMooseBook();
});
