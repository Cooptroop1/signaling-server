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
  const note = document.getElementById('signupAgainNote');
  if (session && session.user) {
    const label = session.user.user_metadata && session.user.user_metadata.display_name
      ? session.user.user_metadata.display_name
      : (session.user.email || 'signed in');
    if (nameEl) nameEl.textContent = label;
    userInfo.classList.remove('hidden');
    authLinks.style.display = 'none';
    if (note) note.classList.add('hidden');
    if (typeof updateLogoutButtonVisibility === 'function') updateLogoutButtonVisibility();
    markPasskeyButton();
  } else {
    if (nameEl) nameEl.textContent = '';
    userInfo.classList.add('hidden');
    authLinks.style.display = 'block';
    if (note) note.classList.remove('hidden');
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
  if (!session || !session.user) {
    stopInbox();
    return;
  }
  const display = (session.user.user_metadata && session.user.user_metadata.display_name)
    || (session.user.email ? session.user.email.split('@')[0] : 'user');
  if (typeof username !== 'undefined') {
    username = display;
    try { sessionStorage.setItem('username', username); } catch (e) {}
    try { localStorage.setItem('username', username); } catch (e) {}
  }
  if (typeof rememberUsername === 'function') rememberUsername(display);
  if (typeof showStatusMessage === 'function') {
    showStatusMessage('Logged in as ' + display + '. Rooms stay P2P.');
  }
  if (typeof updateLogoutButtonVisibility === 'function') updateLogoutButtonVisibility();
  ensureSbSession().then(() => {
    if (signedOut) return;
    publishKeys().catch((e) => console.warn('publishKeys', e));
    loadInbox().catch((e) => console.warn('inbox', e));
    subscribeInbox(session.user.id);
    startHeartbeat();
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

function startHeartbeat() {
  stopHeartbeat();
  const beat = () => {
    if (signedOut || !isLoggedIn()) return;
    ensureSbSession().then(() => {
      if (typeof window.loggedFeatures !== 'undefined' && window.loggedFeatures.checkDeviceLock) {
        return window.loggedFeatures.checkDeviceLock();
      }
    }).then(() => {
      const hide = (typeof accGet === 'function') ? !!accGet('hideLastSeen', false) : false;
      const patch = {};
      if (!hide) patch.last_active = new Date().toISOString();
      if (typeof clientId !== 'undefined' && clientId) patch.client_id = clientId;
      if (Object.keys(patch).length === 0) return null;
      return sb.from('profiles').update(patch).eq('id', currentUser().id);
    }).then((res) => {
      if (res && res.error && /client_id|schema cache/i.test(res.error.message || '')) {
        return sb.from('profiles').update({ last_active: new Date().toISOString() }).eq('id', currentUser().id);
      }
    }).catch(() => {});
  };
  beat();
  heartbeatTimer = setInterval(beat, 20000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') beat();
  });
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
      if (row.kind === 'call') {
        try {
          if (window.Notification && Notification.permission === 'granted') {
            new Notification('Anonomoose', { body: 'Incoming call', silent: false });
          } else if (window.Notification && Notification.permission === 'default') {
            Notification.requestPermission();
          }
        } catch (e) {}
        if (typeof handleIncomingCallRow === 'function') handleIncomingCallRow(row);
        else if (typeof showStatusMessage === 'function') showStatusMessage('Incoming call');
      }
      if (row.kind === 'poke') {
        try {
          if (window.Notification && Notification.permission === 'granted') {
            new Notification('Anonomoose', { body: 'moose poked you', silent: true });
          } else if (window.Notification && Notification.permission === 'default') {
            Notification.requestPermission().then((p) => {
              if (p === 'granted') new Notification('Anonomoose', { body: 'moose poked you', silent: true });
            });
          }
        } catch (e) {}
        if (typeof showStatusMessage === 'function') showStatusMessage('moose poked you');
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
  const { data, error } = await sb.from('profiles')
    .select('id, display_name, public_key, identity_public_key, last_active, hide_last_seen')
    .eq('display_name', name)
    .maybeSingle();
  if (error || !data) return null;
  const hide = !!data.hide_last_seen;
  const last = data.last_active ? new Date(data.last_active).getTime() : 0;
  const online = !hide && last && (Date.now() - last < 5 * 60 * 1000);
  return {
    id: data.id,
    display_name: data.display_name,
    status: online ? 'online' : 'offline',
    public_key: data.public_key,
    identity_public_key: data.identity_public_key,
    last_active: hide ? null : data.last_active
  };
}

async function findByQr(mq) {
  if (!sb || !mq || window.__duress) return null;
  try { await ensureSbSession(); } catch (e) {}
  const { data, error } = await sb.from('profiles')
    .select('id, display_name, public_key, identity_public_key, last_active, qr_expires')
    .eq('qr_token', mq)
    .maybeSingle();
  if (error || !data) return null;
  if (data.qr_expires && new Date(data.qr_expires).getTime() < Date.now()) return null;
  return findUser(data.display_name);
}

async function sendOffline(toUsername, sealed, meta) {
  if (!isLoggedIn()) throw new Error('Log in to send offline mail');
  await ensureSbSession();
  if (typeof isBlocked === 'function' && isBlocked(toUsername)) throw new Error('That name is blocked');
  const { data: dest, error: findErr } = await sb.from('profiles')
    .select('id')
    .eq('display_name', toUsername)
    .maybeSingle();
  if (findErr) throw new Error(findErr.message || 'Could not look up that name');
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
    if (!error) return;
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

async function signUp(email, displayName, password) {
  if (!/^[a-zA-Z0-9]{1,16}$/.test(displayName)) {
    throw new Error('Display name must be 1-16 letters or numbers');
  }
  const { data: taken } = await sb.from('profiles')
    .select('id')
    .eq('display_name', displayName)
    .maybeSingle();
  if (taken) throw new Error('Display name already taken');
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
  findByQr
};

document.addEventListener('DOMContentLoaded', () => {
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
