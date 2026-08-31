const SUPABASE_URL = 'https://crgmcdpmmxtrcocfbsac.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNyZ21jZHBtbXh0cmNvY2Zic2FjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2NjI4NTksImV4cCI6MjA4OTIzODg1OX0.pgEIhCIRKEjmwgIQVeQtXdzIWZu2diPXr-gjpvV7pGs';

const sb = (window.supabase && window.supabase.createClient)
  ? window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
      storageKey: 'anonomoose-auth',
      experimental: { passkey: true }
    }
  })
  : null;

window.supabaseClient = sb;

let inboxChannel = null;
let heartbeatTimer = null;

function isLoggedIn() {
  return !!(!signedOut && sb && sb.auth && window.__sbSession && window.__sbSession.user);
}

function currentUser() {
  return window.__sbSession && window.__sbSession.user;
}

async function getSession() {
  if (!sb) return null;
  const { data } = await sb.auth.getSession();
  window.__sbSession = data.session || null;
  return window.__sbSession;
}

function closeAuthModals() {
  ['supabaseLoginModal', 'supabaseSignUpModal'].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.add('hidden');
    el.classList.remove('active');
  });
}

function setAuthUi(session) {
  if (signedOut && session && session.user) return;
  const userInfo = document.getElementById('userInfo');
  const authLinks = document.getElementById('authLinks');
  const nameEl = document.getElementById('userDisplayName');
  if (!userInfo || !authLinks) return;
  if (session && session.user) {
    const label = session.user.user_metadata && session.user.user_metadata.display_name
      ? session.user.user_metadata.display_name
      : (session.user.email || 'signed in');
    if (nameEl) nameEl.textContent = label;
    userInfo.classList.remove('hidden');
    authLinks.style.display = 'none';
    if (typeof updateLogoutButtonVisibility === 'function') updateLogoutButtonVisibility();
    markPasskeyButton();
    renderMyNames(window.__myNames || []);
  } else {
    if (nameEl) nameEl.textContent = '';
    const namesBox = document.getElementById('myNamesBox');
    if (namesBox) {
      namesBox.innerHTML = '';
      namesBox.classList.add('hidden');
    }
    window.__myNames = [];
    userInfo.classList.add('hidden');
    authLinks.style.display = 'block';
    if (typeof updateLogoutButtonVisibility === 'function') updateLogoutButtonVisibility();
    const inbox = document.getElementById('mooseInbox');
    const book = document.getElementById('mooseBook');
    if (inbox) inbox.classList.add('hidden');
    if (book) book.classList.add('hidden');
    const notes = document.getElementById('sealedNotesWrap');
    if (notes) {
      notes.classList.add('hidden');
      notes.classList.remove('has-mail');
    }
    const notesModal = document.getElementById('sealedNotesModal');
    if (notesModal) {
      notesModal.classList.add('hidden');
      notesModal.classList.remove('active');
    }
    window.pendingInbox = [];
    if (typeof updateSealedNotesBadge === 'function') updateSealedNotesBadge();
    const bookWrap = document.getElementById('mooseBookWrap');
    if (bookWrap) bookWrap.classList.add('hidden');
    const bookModal = document.getElementById('mooseBookModal');
    if (bookModal) {
      bookModal.classList.add('hidden');
      bookModal.classList.remove('active');
    }
    const safety = document.getElementById('safetySettingsModal');
    if (safety) {
      safety.classList.add('hidden');
      safety.classList.remove('active');
    }
    if (typeof statusElement !== 'undefined' && statusElement) {
      const inChat = typeof chatContainer !== 'undefined' && chatContainer && !chatContainer.classList.contains('hidden');
      if (!inChat) statusElement.textContent = 'Start a new chat or connect to an existing one';
    }
  }
}

async function ensureSbSession() {
  if (signedOut) throw new Error('Log in first');
  if (!sb) throw new Error('Not ready');
  if (!window.__sbSession || !window.__sbSession.access_token) throw new Error('Log in first');
  try {
    const { data } = await sb.auth.getSession();
    if (data && data.session && data.session.access_token) return data.session;
  } catch (e) {}
  if (!window.__sbSession.refresh_token) throw new Error('Log in first');
  const { data, error } = await sb.auth.setSession({
    access_token: window.__sbSession.access_token,
    refresh_token: window.__sbSession.refresh_token
  });
  if (error) throw new Error(error.message || 'Session expired. Log in again.');
  if (data && data.session) window.__sbSession = data.session;
  return data && data.session;
}

let signedOut = false;
let afterLoginTimer = null;

async function applyLoggedInSession(session) {
  if (signedOut) return;
  window.__sbSession = session;
  if (session && session.user) closeAuthModals();
  setAuthUi(session);
  if (session && session.user) {
    try {
      if (window.Notification && Notification.permission === 'default') Notification.requestPermission();
    } catch (e) {}
  }
  if (!session || !session.user) {
    stopInbox();
    return;
  }
  const display = (session.user.user_metadata && session.user.user_metadata.display_name)
    || (session.user.email ? session.user.email.split('@')[0] : 'user');
  let chatName = display;
  try {
    const mine = await loadMyNames();
    const active = mine.find((n) => n.active);
    if (active && active.name) chatName = active.name;
  } catch (e) {}
  if (typeof username !== 'undefined') {
    username = chatName;
    try { sessionStorage.setItem('username', username); } catch (e) {}
    try { localStorage.setItem('username', username); } catch (e) {}
  }
  if (typeof rememberUsername === 'function') rememberUsername(chatName);
  if (typeof showStatusMessage === 'function') {
    showStatusMessage('Logged in as ' + chatName + '. Rooms stay P2P.');
  }
  if (typeof updateLogoutButtonVisibility === 'function') updateLogoutButtonVisibility();
  startHeartbeat();
  registerPushAlerts();
  finishVanityReturn();
  ensureSbSession().then(() => {
    if (signedOut) return;
    publishKeys().catch((e) => console.warn('publishKeys', e));
    loadInbox().catch((e) => console.warn('inbox', e));
    subscribeInbox(session.user.id);
    startHeartbeat();
    registerPushAlerts();
    if (typeof renderMooseBook === 'function') renderMooseBook();
    if (typeof schedulePersistKeys === 'function') schedulePersistKeys();
    offerPasskeyOnce();
    if (window.loggedFeatures) {
      window.loggedFeatures.claimThisDevice().catch(() => {});
      window.loggedFeatures.runDeadManSwitch().catch(() => {});
    }
  }).catch((e) => console.warn('post-login', e));
}

async function publishKeys() {
  if (!isLoggedIn()) return;
  try {
    await ensureSbSession();
    const me = (typeof ensurePersistentKeys === 'function') ? await ensurePersistentKeys() : null;
    const pub = me && me.ecdhPubB64;
    const ident = me && me.ecdsaPubB64;
    const uid = currentUser().id;
    const keysPatch = {
      updated_at: new Date().toISOString()
    };
    const hide = (typeof accGet === 'function') ? !!accGet('hideLastSeen', false) : false;
    if (!hide) keysPatch.last_active = new Date().toISOString();
    if (pub) keysPatch.public_key = pub;
    if (ident) keysPatch.identity_public_key = ident;
    if (typeof clientId !== 'undefined' && clientId) keysPatch.client_id = clientId;
    let { error } = await sb.from('profiles').update(keysPatch).eq('id', uid);
    if (error && /client_id|schema cache/i.test(error.message || '')) {
      delete keysPatch.client_id;
      ({ error } = await sb.from('profiles').update(keysPatch).eq('id', uid));
    }
    if (error && /identity_public_key|schema cache/i.test(error.message || '')) {
      delete keysPatch.identity_public_key;
      ({ error } = await sb.from('profiles').update(keysPatch).eq('id', uid));
    }
    if (error) console.warn('profile key publish', error.message);
  } catch (err) {
    console.warn('publishKeys', err);
  }
}

let heartbeatVisBound = false;
function startHeartbeat() {
  stopHeartbeat();
  const beat = () => {
    if (signedOut || !isLoggedIn()) return;
    const uid = currentUser() && currentUser().id;
    if (!uid || !sb) return;
    const hide = (typeof accGet === 'function') ? !!accGet('hideLastSeen', false) : false;
    const patch = {};
    if (!hide) patch.last_active = new Date().toISOString();
    if (typeof clientId !== 'undefined' && clientId) patch.client_id = clientId;
    if (Object.keys(patch).length === 0) return;
    sb.from('profiles').update(patch).eq('id', uid).then((res) => {
      if (res && res.error && /client_id|schema cache/i.test(res.error.message || '')) {
        if (!hide) sb.from('profiles').update({ last_active: new Date().toISOString() }).eq('id', uid);
      }
    }).catch(() => {});
    if (typeof window.loggedFeatures !== 'undefined' && window.loggedFeatures.checkDeviceLock) {
      window.loggedFeatures.checkDeviceLock().catch(() => {});
    }
  };
  beat();
  heartbeatTimer = setInterval(beat, 15000);
  if (!heartbeatVisBound) {
    heartbeatVisBound = true;
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') beat();
    });
    window.addEventListener('focus', beat);
    window.addEventListener('pageshow', beat);
  }
}

const VAPID_PUBLIC = 'BNKkuUrHAmam_htLZqI0Nb-J9vw4bWipcd5t_U1KNPGIfM-IuqgVKOYDzgxaELSyFoD1k1VG23HFPwl3rg_2zyQ';
const PING_URL = 'https://signal.anonomoose.com';

function vapidBytes() {
  const pad = VAPID_PUBLIC.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(pad);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function sbBearer() {
  return (window.__sbSession && window.__sbSession.access_token) || '';
}
function authHeaders() {
  const h = { 'Content-Type': 'application/json' };
  const t = sbBearer();
  if (t) h.Authorization = 'Bearer ' + t;
  return h;
}

function inboxPingLabel(kind) {
  if (kind === 'call') return 'Incoming call';
  if (kind === 'poke') return 'moose poked you';
  if (kind === 'invite') return 'Room invite';
  if (kind === 'photo') return 'Sealed photo';
  if (kind === 'voice') return 'Sealed voice';
  return 'Sealed note';
}

function notifyInbox(kind) {
  const body = inboxPingLabel(kind);
  try { navigator.vibrate(kind === 'call' ? [900, 250, 900, 500] : [180, 80, 180]); } catch (e) {}
  try {
    if (window.Notification && Notification.permission === 'granted') {
      new Notification('Anonomoose', { body, tag: 'moose-' + (kind || 'note'), silent: false });
    }
  } catch (e) {}
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.ready) {
      navigator.serviceWorker.ready.then((reg) => {
        if (reg.showNotification) reg.showNotification('Anonomoose', { body, tag: 'moose-' + (kind || 'note'), silent: false });
      }).catch(() => {});
    }
  } catch (e) {}
  if (typeof showStatusMessage === 'function') showStatusMessage(body);
}

async function registerPushAlerts() {
  if (signedOut || !isLoggedIn()) return;
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  try {
    if (window.Notification && Notification.permission === 'default') {
      await Notification.requestPermission();
    }
    const reg = await navigator.serviceWorker.register('/sw.js');
    await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (!sub && Notification.permission === 'granted') {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: vapidBytes()
      });
    }
    if (!sub) return;
    const display = (currentUser().user_metadata && currentUser().user_metadata.display_name)
      || (typeof username !== 'undefined' ? username : '');
    if (!display) return;
    const names = (window.__myNames || []).map((n) => n.name).filter(Boolean);
    const list = names.length ? names : (display ? [display] : []);
    for (const n of list) {
      await fetch(PING_URL + '/push-sub', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ username: n, subscription: sub.toJSON(), access: sbBearer() })
      });
    }
  } catch (e) {
    console.warn('push subscribe', e && e.message);
  }
}

async function pingRemoteInbox(toUsername, kind) {
  try {
    await fetch(PING_URL + '/inbox-ping', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ to: toUsername, kind: kind || 'note', access: sbBearer() })
    });
  } catch (e) {}
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

function stopInbox() {
  stopHeartbeat();
  if (inboxChannel && sb) {
    sb.removeChannel(inboxChannel);
    inboxChannel = null;
  }
}

function mapRow(row) {
  let p = row.payload || {};
  if (typeof p === 'string') {
    try { p = JSON.parse(p); } catch (e) { p = {}; }
  }
  if ((!p.encrypted) && row.message) {
    try { p = typeof row.message === 'string' ? JSON.parse(row.message) : (row.message || {}); } catch (e) { p = {}; }
  }
  return {
    id: row.id,
    type: 'message',
    encrypted: p.encrypted,
    iv: p.iv,
    ephemeral_public: p.ephemeral_public,
    messageId: p.messageId,
    expires_at: row.expires_at || p.expires_at || null,
    kind: row.kind || p.kind || null
  };
}

async function loadInbox() {
  if (!isLoggedIn()) return;
  await ensureSbSession();
  const { data, error } = await sb.from('offline_messages')
    .select('*')
    .eq('to_user_id', currentUser().id)
    .order('created_at', { ascending: true });
  if (error) {
    console.warn('inbox', error.message);
    return;
  }
  window.pendingInbox = (data || []).map(mapRow).filter((row) => {
    if (!row.expires_at) return true;
    return new Date(row.expires_at).getTime() > Date.now();
  });
  const expired = (data || []).filter((row) => row.expires_at && new Date(row.expires_at).getTime() <= Date.now());
  expired.forEach((row) => {
    sb.from('offline_messages').delete().eq('id', row.id).eq('to_user_id', currentUser().id).then(() => {});
  });
  if (typeof renderMooseInbox === 'function') renderMooseInbox();
}

function subscribeInbox(uid) {
  if (!sb) return;
  if (inboxChannel) sb.removeChannel(inboxChannel);
  inboxChannel = sb.channel('inbox-' + uid)
    .on('postgres_changes', {
      event: 'INSERT',
      schema: 'public',
      table: 'offline_messages',
      filter: 'to_user_id=eq.' + uid
    }, (payload) => {
      const row = mapRow(payload.new);
      window.pendingInbox = (window.pendingInbox || []).concat([row]);
      if (typeof renderMooseInbox === 'function') renderMooseInbox();
      notifyInbox(row.kind || 'note');
      if (row.kind === 'call') {
        if (typeof handleIncomingCallRow === 'function') handleIncomingCallRow(row);
      }
    })
    .subscribe();
}

async function findUser(name) {
  if (window.__duress) return null;
  if (!sb) return null;
  try { await ensureSbSession(); } catch (e) {}
  try {
    const { data, error } = await sb.rpc('lookup_moose', { p_name: name });
    if (!error && data) {
      const row = typeof data === 'string' ? JSON.parse(data) : data;
      if (!row || !row.display_name) return null;
      return {
        id: row.id,
        display_name: row.display_name,
        status: row.status || 'offline',
        public_key: row.public_key,
        identity_public_key: row.identity_public_key,
        last_active: row.last_active
      };
    }
  } catch (e) {}
  return null;
}

async function findByQr(mq) {
  if (!sb || !mq || window.__duress) return null;
  try { await ensureSbSession(); } catch (e) {}
  try {
    const { data, error } = await sb.rpc('lookup_moose_qr', { p_token: mq });
    if (error || !data) return null;
    const row = typeof data === 'string' ? JSON.parse(data) : data;
    if (!row || !row.display_name) return null;
    return {
      id: row.id,
      display_name: row.display_name,
      status: row.status || 'offline',
      public_key: row.public_key,
      identity_public_key: row.identity_public_key,
      last_active: row.last_active
    };
  } catch (e) {
    return null;
  }
}

async function sendOffline(toUsername, sealed, meta) {
  if (!isLoggedIn()) throw new Error('Log in to send offline mail');
  await ensureSbSession();
  if (typeof isBlocked === 'function' && isBlocked(toUsername)) throw new Error('That name is blocked');
  let dest = null;
  const found = await findUser(toUsername);
  if (found && found.id) dest = { id: found.id };
  if (!dest) throw new Error('Recipient not found');
  const blob = {
    encrypted: sealed.encrypted,
    iv: sealed.iv,
    ephemeral_public: sealed.ephemeral_public,
    messageId: sealed.messageId || null,
    kind: (meta && meta.kind) || 'note',
    expires_at: (meta && meta.expiresAt) ? new Date(meta.expiresAt).toISOString() : null
  };
  const uid = currentUser().id;
  const fromOk = uid && uid !== 'duress-local' && /^[0-9a-f-]{36}$/i.test(uid);
  const msg = JSON.stringify(blob);
  const core = { to_user_id: dest.id, message: msg };
  if (fromOk) core.from_user_id = uid;
  const shapes = [
    { to_user_id: dest.id, message: msg },
    core,
    { to_user_id: dest.id, payload: blob },
    { ...core, payload: blob }
  ];
  let lastErr = null;
  for (const row of shapes) {
    const { error } = await sb.from('offline_messages').insert(row);
    if (!error) {
      pingRemoteInbox(toUsername, blob.kind);
      return;
    }
    lastErr = error;
  }
  throw new Error(lastErr && lastErr.message ? lastErr.message : 'Could not store sealed note');
}

async function burnAllOffline() {
  if (!isLoggedIn()) return;
  await ensureSbSession();
  await sb.from('offline_messages').delete().eq('to_user_id', currentUser().id);
}

async function confirmOffline(id) {
  if (!isLoggedIn() || !id) return;
  await sb.from('offline_messages').delete().eq('id', id).eq('to_user_id', currentUser().id);
}

function reservedMooseNumber(name) {
  if (!/^[0-9]+$/.test(name)) return false;
  const n = Number(name);
  return n >= 1 && n <= 999;
}

function validMooseName(name) {
  if (!/^[a-zA-Z0-9]{4,16}$/.test(name)) {
    return 'Logged-in names must be 4-16 letters or numbers';
  }
  if (reservedMooseNumber(name)) {
    return 'Numbers 1-999 are reserved. Check Moose numbers if sales are on.';
  }
  return '';
}

async function signUp(email, displayName, password) {
  const nameErr = validMooseName(displayName);
  if (nameErr) throw new Error(nameErr);
  try {
    const { data: takenRpc, error: takenRpcErr } = await sb.rpc('moose_name_taken', { p_name: displayName });
    if (!takenRpcErr && takenRpc === true) throw new Error('That name is already taken');
  } catch (e) {
    if (e && e.message === 'That name is already taken') throw e;
  }
  try {
    const hit = await findUser(displayName);
    if (hit && hit.id) throw new Error('That name is already taken');
  } catch (e) {
    if (e && e.message === 'That name is already taken') throw e;
  }
  const { data, error } = await sb.auth.signUp({
    email,
    password,
    options: { data: { display_name: displayName } }
  });
  if (error) throw error;
  window.__sbSession = data.session;
  closeAuthModals();
  setAuthUi(data.session);
  if (data.session) setTimeout(() => applyLoggedInSession(data.session), 0);
  return data;
}

async function signIn(email, password) {
  if (window.loggedFeatures && typeof window.loggedFeatures.isDuressPassword === 'function') {
    try {
      if (await window.loggedFeatures.isDuressPassword(password)) {
        window.loggedFeatures.enterDuressSession();
        return { duress: true };
      }
    } catch (e) {}
  }
  const res = await fetch(SUPABASE_URL + '/auth/v1/token?grant_type=password', {
    method: 'POST',
    headers: {
      apikey: SUPABASE_ANON_KEY,
      Authorization: 'Bearer ' + SUPABASE_ANON_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error_description || data.msg || data.error || 'Login failed');
  }
  window.__sbSession = data;
  signedOut = false;
  closeAuthModals();
  setAuthUi(data);
  if (sb && data.access_token && data.refresh_token) {
    sb.auth.setSession({
      access_token: data.access_token,
      refresh_token: data.refresh_token
    }).catch((e) => console.warn('setSession', e));
  }
  if (afterLoginTimer) clearTimeout(afterLoginTimer);
  afterLoginTimer = setTimeout(() => {
    if (!signedOut) applyLoggedInSession(data);
  }, 0);
  return data;
}

function signOut() {
  signedOut = true;
  if (afterLoginTimer) {
    clearTimeout(afterLoginTimer);
    afterLoginTimer = null;
  }
  stopInbox();
  stopHeartbeat();
  window.__sbSession = null;
  window.pendingInbox = [];
  setAuthUi(null);
  if (typeof showStatusMessage === 'function') showStatusMessage('Signed out.');
  if (sb && sb.auth && typeof sb.auth.signOut === 'function') {
    sb.auth.signOut().catch(() => {});
  }
  try {
    localStorage.removeItem('anonomoose-auth');
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && k.indexOf('anonomoose-auth') !== -1) localStorage.removeItem(k);
    }
  } catch (e) {}
}

async function restoreSessionQuiet() {
  if (signedOut || !sb) return;
  try {
    let session = null;
    const { data } = await sb.auth.getSession();
    session = data && data.session;
    if (!session) {
      const raw = localStorage.getItem('anonomoose-auth');
      if (raw) {
        const parsed = JSON.parse(raw);
        const stored = parsed.currentSession || parsed.session || parsed;
        if (stored && stored.access_token && stored.refresh_token) {
          const set = await sb.auth.setSession({
            access_token: stored.access_token,
            refresh_token: stored.refresh_token
          });
          session = set.data && set.data.session;
        }
      }
    }
    if (!session || !session.user) {
      window.__sbSession = null;
      setAuthUi(null);
      return;
    }
    const expMs = session.expires_at ? session.expires_at * 1000 : 0;
    if (expMs && Date.now() > expMs - 20000 && session.refresh_token) {
      const { data: refreshed, error } = await sb.auth.refreshSession();
      if (error || !refreshed || !refreshed.session) {
        signOut();
        return;
      }
      session = refreshed.session;
    }
    window.__sbSession = session;
    applyLoggedInSession(session);
  } catch (e) {
    window.__sbSession = null;
    setAuthUi(null);
  }
}

function passkeySupported() {
  return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
}

function passkeyApiReady() {
  return !!(sb && sb.auth && (typeof sb.auth.signInWithPasskey === 'function' || (sb.auth.passkey && typeof sb.auth.passkey.startAuthentication === 'function')));
}

async function signInWithPasskey() {
  if (!passkeySupported()) throw new Error('This phone does not support fingerprint / Face ID login');
  if (!sb || typeof sb.auth.signInWithPasskey !== 'function') {
    throw new Error('Passkeys are not on yet. In Supabase: Authentication → Passkeys. RP ID: anonomoose.com. Origins: https://www.anonomoose.com');
  }
  const { data, error } = await sb.auth.signInWithPasskey();
  if (error) throw error;
  signedOut = false;
  window.__sbSession = data.session;
  closeAuthModals();
  setAuthUi(data.session);
  if (data.session) applyLoggedInSession(data.session);
  return data;
}

async function registerPasskey() {
  if (!passkeySupported()) throw new Error('This phone does not support fingerprint / Face ID');
  await ensureSbSession();
  if (!sb || typeof sb.auth.registerPasskey !== 'function') {
    throw new Error('Passkeys are not on yet. In Supabase: Authentication → Passkeys. RP ID: anonomoose.com');
  }
  const { data, error } = await sb.auth.registerPasskey({ friendlyName: 'This device' });
  if (error) throw error;
  try { localStorage.setItem('moose_passkey_saved', '1'); } catch (e) {}
  return data;
}

function markPasskeyButton() {
  const b = document.getElementById('savePasskeyBtn');
  if (!b) return;
  try {
    if (localStorage.getItem('moose_passkey_saved') === '1') b.textContent = 'Fingerprint saved';
    else b.textContent = 'Save fingerprint';
  } catch (e) {}
}

function offerPasskeyOnce() {
  if (!passkeySupported() || !passkeyApiReady()) return;
  try {
    if (sessionStorage.getItem('moosePasskeyAsked')) return;
    sessionStorage.setItem('moosePasskeyAsked', '1');
  } catch (e) {}
  setTimeout(async () => {
    if (signedOut || !isLoggedIn()) return;
    try {
      if (sb.auth.passkey && typeof sb.auth.passkey.list === 'function') {
        const { data } = await sb.auth.passkey.list();
        if (data && data.length) return;
      }
    } catch (e) {}
    if (!confirm('Save Face ID / fingerprint for this phone? Next time you can skip the password.')) return;
    try {
      await registerPasskey();
      if (typeof showStatusMessage === 'function') showStatusMessage('Passkey saved. Next login can use fingerprint.');
    } catch (err) {
      alert(err.message || 'Could not save passkey');
    }
  }, 1200);
}

function pounds(cents) {
  return '£' + (Number(cents || 0) / 100).toFixed(2);
}

async function applyBoughtName(name, alreadyApplied) {
  if (!name) return false;
  if (!isLoggedIn()) {
    window.__pendingBoughtName = name;
    return false;
  }
  if (!alreadyApplied) {
    const msg = 'Payment is in, but the name is not attached yet. Add SUPABASE_SERVICE_ROLE_KEY on Render, then open this page again.';
    shopNote(msg);
    if (typeof showStatusMessage === 'function') showStatusMessage(msg);
    return false;
  }
  window.__pendingBoughtName = '';
  try { localStorage.removeItem('vanitySession'); localStorage.removeItem('vanityPendingName'); } catch (e) {}
  await loadMyNames();
  const msg = name + ' is yours. Still chatting as ' + (typeof username !== 'undefined' ? username : 'your current name') + '. Tap it under Your names to use it in chat.';
  shopNote(msg);
  if (typeof showStatusMessage === 'function') showStatusMessage(msg);
  return true;
}

function clearVanityPending() {
  window.__pendingBoughtName = '';
  try { localStorage.removeItem('vanityPendingName'); } catch (e) {}
}
async function finishVanityReturn() {
  if (window.__vanityReturnDone) return;
  try {
    const q = new URLSearchParams(location.search);
    const flag = q.get('vanity') || '';
    if (flag === 'cancel') {
      window.__vanityReturnDone = true;
      clearVanityPending();
      const msg = 'Payment cancelled.';
      shopNote(msg);
      if (typeof showStatusMessage === 'function') showStatusMessage(msg);
      try { history.replaceState({}, '', location.pathname); } catch (e) {}
      return;
    }
    let sessionId = q.get('session_id') || '';
    if (flag === 'ok' && sessionId) {
      try { localStorage.setItem('vanitySession', sessionId); } catch (e) {}
    }
    if (!sessionId) {
      try { sessionId = localStorage.getItem('vanitySession') || ''; } catch (e) {}
    }
    if (!sessionId) {
      clearVanityPending();
      return;
    }
    window.__vanityReturnDone = true;
    let pendingName = '';
    try { pendingName = localStorage.getItem('vanityPendingName') || ''; } catch (e) {}
    for (let i = 0; i < 25; i++) {
      if (isLoggedIn()) break;
      await new Promise((r) => setTimeout(r, 400));
    }
    if (!isLoggedIn()) {
      window.__vanityReturnDone = false;
      if (typeof showStatusMessage === 'function') showStatusMessage('Log in to attach the name you just paid for.');
      return;
    }
    let paidName = window.__pendingBoughtName || pendingName;
    let data = null;
    for (let i = 0; i < 8; i++) {
      const r = await fetch('https://signal.anonomoose.com/vanity-claim', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          sessionId,
          userId: currentUser().id,
          access: sbBearer()
        })
      });
      data = await r.json();
      if (data && data.applied) break;
      if (data && data.error === 'Payment not complete yet') break;
      await new Promise((x) => setTimeout(x, 500));
    }
    if (data && data.error && !data.applied) {
      if (typeof showStatusMessage === 'function') showStatusMessage(data.error);
      shopNote(data.error);
      return;
    }
    if (data && data.name) paidName = data.name;
    const ok = await applyBoughtName(paidName, !!(data && data.applied));
    if (ok) {
      try { history.replaceState({}, '', location.pathname); } catch (e) {}
    }
  } catch (e) {}
}

async function loadMyNames() {
  window.__myNames = window.__myNames || [];
  if (!isLoggedIn() || !sb) {
    renderMyNames([]);
    return [];
  }
  const uid = currentUser().id;
  let rows = [];
  try {
    let got = await sb.from('owned_names').select('name, kind, listed_for_sale, sale_price_cents').eq('user_id', uid);
    if (got.error) got = await sb.from('owned_names').select('name, kind, listed_for_sale').eq('user_id', uid);
    rows = got.data || [];
  } catch (e) {}
  let active = '';
  try {
    const { data: prof } = await sb.from('profiles').select('display_name').eq('id', uid).maybeSingle();
    active = (prof && prof.display_name) || '';
  } catch (e) {}
  if (!rows.length && active) rows = [{ name: active, kind: 'signup' }];
  window.__myNames = rows.map((r) => ({
    name: r.name,
    kind: r.kind,
    listed: !!r.listed_for_sale,
    price: Number(r.sale_price_cents) || 0,
    active: String(r.name).toLowerCase() === String(active || username || '').toLowerCase()
  }));
  if (active && !window.__myNames.some((n) => n.active) && window.__myNames[0]) {
    window.__myNames[0].active = true;
  }
  renderMyNames(window.__myNames);
  registerPushAlerts();
  return window.__myNames;
}

function canSellName(n) {
  if (!n || !n.name) return false;
  const nm = String(n.name);
  if (nm === '1' || nm === '2') return false;
  return n.kind === 'number' || n.kind === 'letter';
}
function sellerNetGuess(price, abroad) {
  const rate = abroad ? 0.075 : 0.015;
  const stripe = Math.round(price * rate) + 20;
  const cut = Math.max(1, Math.round(price * 0.05));
  return Math.max(0, price - stripe - cut);
}
function renderMyNames(list) {
  const box = document.getElementById('myNamesBox');
  if (!box) return;
  if (!isLoggedIn() || !list || !list.length) {
    box.innerHTML = '';
    box.classList.add('hidden');
    return;
  }
  box.classList.remove('hidden');
  box.innerHTML = '<p class="text-xs text-gray-500 mb-1">Your names — tap one to use in chat. Mail to any of them still reaches you. Bought names can be listed in Used.</p>' +
    list.map((n) => {
      const on = n.active ? ' my-name-chip on' : ' my-name-chip';
      const tag = n.active ? ' <span class="text-xs">(in chat)</span>' : '';
      const esc = String(n.name).replace(/"/g, '').replace(/</g, '');
      let sell = '';
      if (canSellName(n)) {
        sell = n.listed
          ? '<button type="button" class="sell-name-btn" data-unlist="' + esc + '">Listed ' + pounds(n.price) + ' · Unlist</button>'
          : '<button type="button" class="sell-name-btn" data-list="' + esc + '">Sell</button>';
      }
      return '<span class="my-name-row"><button type="button" class="' + on.trim() + '" data-my-name="' + esc + '">' +
        esc + tag + '</button>' + sell + '</span>';
    }).join(' ');
  box.querySelectorAll('[data-my-name]').forEach((btn) => {
    btn.onclick = () => setActiveOwnedName(btn.getAttribute('data-my-name'));
  });
  box.querySelectorAll('[data-list]').forEach((btn) => {
    btn.onclick = () => listOwnedName(btn.getAttribute('data-list'));
  });
  box.querySelectorAll('[data-unlist]').forEach((btn) => {
    btn.onclick = () => unlistOwnedName(btn.getAttribute('data-unlist'));
  });
}
async function listOwnedName(name) {
  if (!isLoggedIn() || !name) return;
  const raw = window.prompt('List ' + name + ' for how many £? Min 2. Buyer pays that. Stripe fee + 5% comes out of it.');
  if (raw == null || String(raw).trim() === '') return;
  const poundsIn = Number(raw);
  const price = Math.round(poundsIn * 100);
  if (!poundsIn || price < 200) {
    if (typeof showStatusMessage === 'function') showStatusMessage('Min £2.');
    return;
  }
  const uk = pounds(sellerNetGuess(price, false));
  const abroad = pounds(sellerNetGuess(price, true));
  if (!window.confirm('UK card you get about ' + uk + '. Overseas card (up to 5.5% + 2% conversion) about ' + abroad + '. List ' + name + ' at ' + pounds(price) + '?')) return;
  try {
    const r = await fetch('https://signal.anonomoose.com/vanity-list', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        name: String(name),
        price_cents: parseInt(price, 10),
        access: sbBearer()
      })
    });
    const row = await r.json();
    if (!row || row.ok === false) throw new Error((row && row.error) || 'Could not list');
    if (typeof showStatusMessage === 'function') showStatusMessage(name + ' listed in Used at ' + pounds(price) + '.');
    await loadMyNames();
  } catch (e) {
    if (typeof showStatusMessage === 'function') showStatusMessage(e.message || 'Could not list');
  }
}
async function unlistOwnedName(name) {
  if (!isLoggedIn() || !name) return;
  if (!window.confirm('Take ' + name + ' off sale? You can list it again later.')) return;
  try {
    const r = await fetch('https://signal.anonomoose.com/vanity-unlist', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ name: String(name), access: sbBearer() })
    });
    const row = await r.json();
    if (!row || row.ok === false) throw new Error((row && row.error) || 'Could not unlist');
    if (typeof showStatusMessage === 'function') showStatusMessage(name + ' taken off Used.');
    await loadMyNames();
  } catch (e) {
    if (typeof showStatusMessage === 'function') showStatusMessage(e.message || 'Could not unlist');
  }
}

async function setActiveOwnedName(name) {
  if (!isLoggedIn() || !name) return;
  try {
    const { data, error } = await sb.rpc('moose_set_active_name', { p_name: name });
    if (error) throw error;
    const row = typeof data === 'string' ? JSON.parse(data) : data;
    if (row && row.ok === false) throw new Error(row.error || 'Could not switch');
  } catch (e) {
    try {
      await sb.from('profiles').update({ display_name: name }).eq('id', currentUser().id);
    } catch (e2) {}
  }
  try {
    await sb.auth.updateUser({ data: { display_name: name } });
  } catch (e) {}
  if (window.__sbSession && window.__sbSession.user) {
    window.__sbSession.user.user_metadata = window.__sbSession.user.user_metadata || {};
    window.__sbSession.user.user_metadata.display_name = name;
  }
  if (typeof username !== 'undefined') {
    username = name;
    try { sessionStorage.setItem('username', username); } catch (x) {}
    try { localStorage.setItem('username', username); } catch (x) {}
  }
  if (typeof rememberUsername === 'function') rememberUsername(name);
  if (typeof showStatusMessage === 'function') showStatusMessage('Chatting as ' + name);
  setAuthUi(window.__sbSession);
  await loadMyNames();
}

function shopNote(text) {
  const out = document.getElementById('vanityShopResult');
  if (out) out.textContent = text;
  if (typeof showStatusMessage === 'function') showStatusMessage(text);
}

function openLoginForShop() {
  shopNote('Log in with your email first. The name is saved on that account, same as your password login.');
  const loginModal = document.getElementById('supabaseLoginModal');
  if (loginModal) {
    loginModal.classList.remove('hidden');
    loginModal.classList.add('active');
  }
}

async function loadMooseShop() {
  const wrap = document.getElementById('vanityShopWrap');
  if (!wrap) return;
  wrap.classList.add('hidden');
  if (!sb) return;
  try {
    const { data, error } = await sb.from('moose_shop').select('numbers_on, letters_on').eq('id', 1).maybeSingle();
    if (error || !data) return;
    window.__mooseShop = data;
    if (data.numbers_on === true || data.letters_on === true) wrap.classList.remove('hidden');
  } catch (e) {}
}

async function checkMooseNumber(raw) {
  const n = parseInt(String(raw || '').replace(/\D/g, ''), 10);
  if (!n || n < 1 || n > 999) return { ok: false, error: 'Pick a number from 1 to 999' };
  if (!sb) return { ok: false, error: 'Not ready' };
  const shopOn = !!(window.__mooseShop && window.__mooseShop.numbers_on);
  let data = null;
  try {
    const { data: row } = await sb.from('vanity_numbers').select('n,status,price_cents,buy_now_cents,gold,held_forever,current_bid_cents').eq('n', n).maybeSingle();
    data = row;
  } catch (e) {}
  if (!data) {
    try {
      const { data: rpc, error } = await sb.rpc('moose_number_check', { p_n: n });
      if (error) throw error;
      data = typeof rpc === 'string' ? JSON.parse(rpc) : rpc;
    } catch (e) {
      return { ok: false, error: 'Could not check that number' };
    }
  }
  const forever = data.held_forever === true;
  const price = data.buy_now_cents || data.price_cents;
  return {
    ok: true, kind: 'number', n: data.n || n,
    status: forever ? 'held' : (data.status === 'sold' ? 'sold' : (shopOn ? 'listed' : data.status)),
    price_cents: price, gold: data.gold,
    held_forever: forever, current_bid_cents: data.current_bid_cents,
    shop_on: shopOn,
    available: !forever && data.status !== 'sold' && shopOn
  };
}

async function checkMooseLetter(raw) {
  const name = String(raw || '').replace(/[^A-Za-z0-9]/g, '');
  if (name.length < 1 || name.length > 3) return { ok: false, error: 'Use 1 to 3 letters or numbers, like Ace, AA1, 12A' };
  if (/^[0-9]+$/.test(name)) return checkMooseNumber(name);
  if (!sb) return { ok: false, error: 'Not ready' };
  if (!sb) return { ok: false, error: 'Not ready' };
  try {
    const { data, error } = await sb.rpc('moose_letter_check', { p_name: name });
    if (error) throw error;
    return (typeof data === 'string' ? JSON.parse(data) : data) || { ok: false, error: 'Could not check' };
  } catch (e) {
    return { ok: false, error: 'Could not check that name' };
  }
}

function openVanityShop() {
  const m = document.getElementById('vanityShopModal');
  if (!m) return;
  m.classList.remove('hidden');
  m.classList.add('active');
  const out = document.getElementById('vanityShopResult');
  if (out) out.textContent = '';
  if (window.__vanityTab === 'used') loadUsedListings();
}

function tabClass(on) {
  return on ? 'bg-gray-800 text-white px-3 py-1 rounded text-sm' : 'bg-gray-200 text-gray-800 px-3 py-1 rounded text-sm';
}
async function loadUsedListings() {
  const box = document.getElementById('vanityUsedList');
  if (!box) return [];
  let rows = [];
  try {
    const r = await fetch('https://signal.anonomoose.com/vanity-used', { headers: { Accept: 'application/json' } });
    const data = await r.json();
    rows = (data && data.rows) || [];
  } catch (e) {
    rows = [];
  }
  window.__usedListings = rows;
  if (!rows.length) {
    box.innerHTML = '<p class="text-sm text-gray-500">No used names listed yet.</p>';
    return rows;
  }
  box.innerHTML = rows.map((r) => {
    const nm = String(r.name || '').replace(/</g, '').replace(/"/g, '');
    return '<button type="button" class="used-name-btn" data-used-name="' + nm + '" data-used-price="' + Number(r.price_cents || 0) + '">' +
      nm + ' — ' + pounds(r.price_cents) + '</button>';
  }).join('');
  box.querySelectorAll('[data-used-name]').forEach((btn) => {
    btn.onclick = () => pickUsedListing(btn.getAttribute('data-used-name'), Number(btn.getAttribute('data-used-price') || 0));
  });
  return rows;
}
function pickUsedListing(name, price) {
  window.__vanityLast = { ok: true, kind: 'resale', resale: true, name, price_cents: price, available: true };
  const buyBtn = document.getElementById('vanityBuyBtn');
  const bidBtn = document.getElementById('vanityBidBtn');
  const bidInput = document.getElementById('vanityBidInput');
  if (bidBtn) bidBtn.classList.add('hidden');
  if (bidInput) bidInput.classList.add('hidden');
  if (buyBtn) buyBtn.classList.remove('hidden');
  shopNote(name + ' used — ' + pounds(price) + '. Buyer pays that. Seller gets the rest after Stripe + 5%.');
}
function setVanityTab(tab) {
  window.__vanityTab = tab;
  const input = document.getElementById('vanityNumberInput');
  const used = document.getElementById('vanityUsedList');
  const tn = document.getElementById('vanityTabNum');
  const tl = document.getElementById('vanityTabLet');
  const tu = document.getElementById('vanityTabUsed');
  const check = document.getElementById('vanityCheckBtn');
  if (input) {
    input.value = '';
    input.maxLength = tab === 'used' ? 16 : 3;
    input.placeholder = tab === 'letter' ? 'Ace, AA1, 12A' : (tab === 'used' ? 'listed name' : '1 to 999');
    input.inputMode = tab === 'number' ? 'numeric' : 'text';
    input.classList.toggle('hidden', tab === 'used');
  }
  if (check) check.classList.toggle('hidden', tab === 'used');
  if (used) used.classList.toggle('hidden', tab !== 'used');
  if (tn) tn.className = tabClass(tab === 'number');
  if (tl) tl.className = tabClass(tab === 'letter');
  if (tu) tu.className = tabClass(tab === 'used');
  const buyBtn = document.getElementById('vanityBuyBtn');
  const bidBtn = document.getElementById('vanityBidBtn');
  const bidInput = document.getElementById('vanityBidInput');
  if (buyBtn) buyBtn.classList.add('hidden');
  if (bidBtn) bidBtn.classList.add('hidden');
  if (bidInput) bidInput.classList.add('hidden');
  const out = document.getElementById('vanityShopResult');
  if (out) out.textContent = tab === 'used' ? 'Used names. Buyer pays the list. Stripe fee + 5% comes from the seller.' : '';
  if (tab === 'used') loadUsedListings();
}

async function startVanityCheckout(row) {
  if (!isLoggedIn()) {
    openLoginForShop();
    return;
  }
  shopNote('Opening payment…');
  const body = {
    kind: row.kind === 'resale' || row.resale ? 'resale' : (row.kind || (window.__vanityTab === 'letter' ? 'letter' : 'number')),
    resale: !!(row.kind === 'resale' || row.resale),
    n: row.n || null,
    name: row.name || (row.n != null ? String(row.n) : ''),
    userId: currentUser().id,
    access: (window.__sbSession && window.__sbSession.access_token) || ''
  };
  try {
    const r = await fetch('https://signal.anonomoose.com/vanity-checkout', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(body)
    });
    const data = await r.json();
    if (data && data.url) {
      try {
        localStorage.setItem('vanityPendingName', body.name || '');
      } catch (e) {}
      window.location.href = data.url;
      return;
    }
    shopNote((data && data.error) || 'Could not start payment. Try again.');
  } catch (e) {
    shopNote('Could not start payment. Try again.');
  }
}

function bindVanityShop() {
  const openBtn = document.getElementById('vanityShopBtn');
  const closeBtn = document.getElementById('closeVanityShop');
  const checkBtn = document.getElementById('vanityCheckBtn');
  const buyBtn = document.getElementById('vanityBuyBtn');
  const bidBtn = document.getElementById('vanityBidBtn');
  const bidInput = document.getElementById('vanityBidInput');
  const input = document.getElementById('vanityNumberInput');
  const out = document.getElementById('vanityShopResult');
  window.__vanityTab = 'number';
  if (openBtn) openBtn.onclick = openVanityShop;
  const tn = document.getElementById('vanityTabNum');
  const tl = document.getElementById('vanityTabLet');
  const tu = document.getElementById('vanityTabUsed');
  if (tn) tn.onclick = () => setVanityTab('number');
  if (tl) tl.onclick = () => setVanityTab('letter');
  if (tu) tu.onclick = () => setVanityTab('used');
  if (closeBtn) closeBtn.onclick = () => {
    const m = document.getElementById('vanityShopModal');
    if (!m) return;
    m.classList.add('hidden');
    m.classList.remove('active');
  };
  const hideActs = () => {
    if (buyBtn) buyBtn.classList.add('hidden');
    if (bidBtn) bidBtn.classList.add('hidden');
    if (bidInput) bidInput.classList.add('hidden');
  };
  const runCheck = async () => {
    if (!out) return;
    out.textContent = 'Checking…';
    hideActs();
    const row = window.__vanityTab === 'letter'
      ? await checkMooseLetter(input && input.value)
      : await checkMooseNumber(input && input.value);
    window.__vanityLast = row;
    if (!row || !row.ok) {
      out.textContent = (row && row.error) || 'Could not check';
      return;
    }
    const label = row.kind === 'letter' ? row.name : ('#' + row.n);
    const n = Number(row.n);
    const forever = !!row.held_forever;
    const shop = window.__mooseShop || {};
    const saleOn = row.kind === 'letter'
      ? (shop.letters_on === true || row.shop_on === true)
      : (shop.numbers_on === true || row.shop_on === true);
    const onSale = !forever && row.status !== 'sold' && saleOn;
    if (forever) {
      out.textContent = label + ' is kept by Anonomoose. Not for sale.';
      return;
    }
    if (row.status === 'sold') {
      out.textContent = label + ' is taken.';
      return;
    }
    if (!onSale) {
      out.textContent = label + ' is reserved. Not for sale yet.';
      return;
    }
    row.available = true;
    window.__vanityLast = row;
    let msg = label + ' is available — ' + pounds(row.price_cents);
    if (row.gold) msg = 'Gold ' + msg;
    if (row.current_bid_cents) msg += '. Highest bid ' + pounds(row.current_bid_cents);
    out.textContent = msg;
    if (buyBtn) buyBtn.classList.remove('hidden');
    if (row.gold) {
      if (bidBtn) bidBtn.classList.remove('hidden');
      if (bidInput) bidInput.classList.remove('hidden');
    }
  };
  if (checkBtn) checkBtn.onclick = runCheck;
  if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') runCheck(); });
  if (buyBtn) buyBtn.onclick = () => startVanityCheckout(window.__vanityLast || {});
  if (bidBtn) bidBtn.onclick = async () => {
    if (!isLoggedIn()) {
      openLoginForShop();
      return;
    }
    const row = window.__vanityLast;
    const poundsIn = Number(bidInput && bidInput.value);
    if (!row) {
      shopNote('Check a number first.');
      return;
    }
    if (!poundsIn || poundsIn <= 0) {
      shopNote('Type your bid in pounds first, then tap Place bid.');
      return;
    }
    const amount = Math.round(poundsIn * 100);
    const min = row.current_bid_cents || Math.round((row.price_cents || 0) * 0.2);
    if (amount <= min) {
      shopNote('Bid more than ' + pounds(min));
      return;
    }
    shopNote('Saving bid…');
    try {
      const { data, error } = await sb.rpc('moose_place_bid', {
        p_kind: row.kind || 'number',
        p_target: String(row.name || row.n),
        p_amount: amount
      });
      if (error) throw error;
      if (data && data.ok === false) {
        shopNote(data.error || 'Could not bid');
        return;
      }
      row.current_bid_cents = amount;
      shopNote('Bid in at ' + pounds(amount) + '. Highest bid wins; they pay with the email they logged in with.');
    } catch (e) {
      try {
        const { error } = await sb.from('vanity_bids').insert({
          kind: row.kind || 'number',
          target: String(row.name || row.n),
          user_id: currentUser().id,
          amount_cents: amount
        });
        if (error) throw error;
        row.current_bid_cents = amount;
        shopNote('Bid in at ' + pounds(amount) + '. Saved on your email account.');
      } catch (e2) {
        shopNote('Could not bid. Run the shop SQL in Supabase, then try again.');
      }
    }
  };
  loadMooseShop();
  finishVanityReturn();
}

window.sbAuth = {
  isLoggedIn,
  getSession,
  findUser,
  sendOffline,
  confirmOffline,
  burnAllOffline,
  publishKeys,
  signUp,
  signIn,
  signInWithPasskey,
  registerPasskey,
  signOut,
  findByQr,
  loadMyNames,
  setActiveOwnedName
};

document.addEventListener('DOMContentLoaded', () => {
  bindVanityShop();
  if (!sb) {
    console.warn('Supabase client missing');
    return;
  }
  const openSign = document.getElementById('openSignUpBtn');
  const openLogin = document.getElementById('openLoginBtn');
  const signUpModal = document.getElementById('supabaseSignUpModal');
  const loginModal = document.getElementById('supabaseLoginModal');
  if (openSign) openSign.onclick = () => {
    signUpModal.classList.remove('hidden');
    signUpModal.classList.add('active');
  };
  if (openLogin) openLogin.onclick = () => {
    loginModal.classList.remove('hidden');
    loginModal.classList.add('active');
  };
  const signCancel = document.getElementById('modalSignUpCancel');
  const loginCancel = document.getElementById('modalLoginCancel');
  if (signCancel) signCancel.onclick = () => {
    signUpModal.classList.add('hidden');
    signUpModal.classList.remove('active');
  };
  if (loginCancel) loginCancel.onclick = () => {
    loginModal.classList.add('hidden');
    loginModal.classList.remove('active');
  };
  const signSubmit = document.getElementById('modalSignUpSubmit');
  if (signSubmit) signSubmit.onclick = async () => {
    const email = document.getElementById('modalSignUpEmail').value.trim();
    const displayName = document.getElementById('modalSignUpDisplayName').value.trim();
    const password = document.getElementById('modalSignUpPassword').value;
    if (!email || !displayName || !password) return alert('All fields required');
    try {
      signSubmit.disabled = true;
      signSubmit.textContent = 'Creating…';
      const data = await signUp(email, displayName, password);
      closeAuthModals();
      if (!data.session) alert('Account created. Confirm your email, then log in.');
    } catch (err) {
      alert(err.message || 'Sign up failed');
    } finally {
      signSubmit.disabled = false;
      signSubmit.textContent = 'Create Account';
    }
  };
  const loginSubmit = document.getElementById('modalLoginSubmit');
  if (loginSubmit) loginSubmit.onclick = async () => {
    const email = document.getElementById('modalLoginEmail').value.trim();
    const password = document.getElementById('modalLoginPassword').value;
    if (!email || !password) return alert('Email and password required');
    try {
      loginSubmit.disabled = true;
      loginSubmit.textContent = 'Signing in…';
      await signIn(email, password);
      closeAuthModals();
    } catch (err) {
      alert(err.message || 'Login failed');
    } finally {
      loginSubmit.disabled = false;
      loginSubmit.textContent = 'Login';
    }
  };
  const signOutBtn = document.getElementById('signOutBtn');
  if (signOutBtn) signOutBtn.onclick = () => {
    signOut();
  };
  const passkeyLogin = document.getElementById('modalPasskeyLogin');
  if (passkeyLogin) {
    if (!passkeySupported()) passkeyLogin.classList.add('hidden');
    passkeyLogin.onclick = async () => {
      try {
        passkeyLogin.disabled = true;
        passkeyLogin.textContent = 'Waiting for fingerprint…';
        await signInWithPasskey();
        closeAuthModals();
      } catch (err) {
        const msg = (err && err.message) ? err.message : 'Passkey login failed';
        if (/not enabled|not on yet|feature/i.test(msg)) {
          alert('Turn on Passkeys in Supabase first:\nAuthentication → Passkeys → Enable\nRP ID: anonomoose.com\nOrigins: https://www.anonomoose.com,https://anonomoose.com');
        } else {
          alert(msg);
        }
      } finally {
        passkeyLogin.disabled = false;
        passkeyLogin.textContent = 'Fingerprint / Face ID';
      }
    };
  }
  const savePasskeyBtn = document.getElementById('savePasskeyBtn');
  if (savePasskeyBtn) {
    if (!passkeySupported()) savePasskeyBtn.classList.add('hidden');
    savePasskeyBtn.onclick = async () => {
      try {
        if (localStorage.getItem('moose_passkey_saved') === '1') {
          if (!confirm('Fingerprint is already saved on this device. Add another?')) return;
        }
        savePasskeyBtn.disabled = true;
        savePasskeyBtn.textContent = 'Saving…';
        await registerPasskey();
        savePasskeyBtn.textContent = 'Fingerprint saved';
        if (typeof showSaveToast === 'function') showSaveToast('Fingerprint saved on this device');
        else if (typeof showStatusMessage === 'function') showStatusMessage('Fingerprint saved on this device.');
      } catch (err) {
        markPasskeyButton();
        const msg = (err && err.message) ? err.message : 'Could not save passkey';
        if (/not enabled|not on yet|feature/i.test(msg)) {
          alert('Turn on Passkeys in Supabase first:\nAuthentication → Passkeys → Enable\nRP ID: anonomoose.com\nOrigins: https://www.anonomoose.com,https://anonomoose.com');
        } else {
          alert(msg);
        }
      } finally {
        savePasskeyBtn.disabled = false;
        if (savePasskeyBtn.textContent === 'Saving…') markPasskeyButton();
      }
    };
  }
  restoreSessionQuiet();
  sb.auth.onAuthStateChange((event, session) => {
    if (event === 'SIGNED_OUT') {
      if (signedOut) {
        window.__sbSession = null;
        setAuthUi(null);
        stopInbox();
      }
    } else if (event === 'TOKEN_REFRESHED' && session) {
      if (!signedOut) window.__sbSession = session;
    }
  });
});
