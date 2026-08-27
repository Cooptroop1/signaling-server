const SUPABASE_URL = 'https://crgmcdpmmxtrcocfbsac.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNyZ21jZHBtbXh0cmNvY2Zic2FjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2NjI4NTksImV4cCI6MjA4OTIzODg1OX0.pgEIhCIRKEjmwgIQVeQtXdzIWZu2diPXr-gjpvV7pGs';

const sb = (window.supabase && window.supabase.createClient)
  ? window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
      storageKey: 'anonomoose-auth'
    }
  })
  : null;

window.supabaseClient = sb;

let inboxChannel = null;
let heartbeatTimer = null;

function isLoggedIn() {
  return !!(sb && sb.auth && window.__sbSession && window.__sbSession.user);
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
  } else {
    if (nameEl) nameEl.textContent = '';
    userInfo.classList.add('hidden');
    authLinks.style.display = 'block';
    const inbox = document.getElementById('mooseInbox');
    const book = document.getElementById('mooseBook');
    if (inbox) inbox.classList.add('hidden');
    if (book) book.classList.add('hidden');
  }
}

function withTimeout(promise, ms, message) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms))
  ]);
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
  setTimeout(() => {
    publishKeys().catch((e) => console.warn('publishKeys', e));
    loadInbox().catch((e) => console.warn('inbox', e));
    subscribeInbox(session.user.id);
    startHeartbeat();
    if (typeof renderMooseBook === 'function') renderMooseBook();
    if (typeof schedulePersistKeys === 'function') schedulePersistKeys();
  }, 1500);
}

async function publishKeys() {
  if (!isLoggedIn()) return;
  try {
    let me = (typeof sessionKeyBundle !== 'undefined' && sessionKeyBundle) ? sessionKeyBundle : null;
    if (!me && typeof loadPersistentKeys === 'function') me = await loadPersistentKeys();
    if (!me || !me.ecdhPubB64) return;
    const pub = me.ecdhPubB64;
    const ident = me.ecdsaPubB64;
    const uid = currentUser().id;
    const keysPatch = {
      last_active: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
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
  heartbeatTimer = setInterval(() => {
    if (!isLoggedIn()) return;
    const patch = { last_active: new Date().toISOString() };
    if (typeof clientId !== 'undefined' && clientId) patch.client_id = clientId;
    sb.from('profiles').update(patch).eq('id', currentUser().id).then(() => {});
  }, 60000);
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
    messageId: p.messageId
  };
}

async function loadInbox() {
  if (!isLoggedIn()) return;
  const { data, error } = await sb.from('offline_messages')
    .select('*')
    .eq('to_user_id', currentUser().id)
    .order('created_at', { ascending: true });
  if (error) {
    console.warn('inbox', error.message);
    return;
  }
  window.pendingInbox = (data || []).map(mapRow);
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
    })
    .subscribe();
}

async function findUser(name) {
  if (!sb) return null;
  const { data, error } = await sb.from('profiles')
    .select('display_name, public_key, identity_public_key, last_active')
    .eq('display_name', name)
    .maybeSingle();
  if (error || !data) return null;
  const last = data.last_active ? new Date(data.last_active).getTime() : 0;
  const online = Date.now() - last < 2 * 60 * 1000;
  return {
    status: online ? 'online' : 'offline',
    public_key: data.public_key,
    identity_public_key: data.identity_public_key,
    last_active: data.last_active
  };
}

async function sendOffline(toUsername, sealed) {
  if (!isLoggedIn()) throw new Error('Log in to send offline mail');
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
    messageId: sealed.messageId || null
  };
  const uid = currentUser().id;
  const tries = [
    { to_user_id: dest.id, payload: blob },
    { to_user_id: dest.id, from_user_id: uid, payload: blob },
    { to_user_id: dest.id, from_user_id: uid, message: JSON.stringify(blob) },
    { to_user_id: dest.id, message: JSON.stringify(blob) }
  ];
  let lastErr = null;
  for (const row of tries) {
    const { error } = await sb.from('offline_messages').insert(row);
    if (!error) return;
    lastErr = error;
  }
  throw new Error(lastErr && lastErr.message ? lastErr.message : 'Could not store sealed note');
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
  }, 2000);
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
  setAuthUi(null);
  try {
    localStorage.removeItem('anonomoose-auth');
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && k.indexOf('anonomoose-auth') !== -1) localStorage.removeItem(k);
    }
  } catch (e) {}
}

window.sbAuth = {
  isLoggedIn,
  getSession,
  findUser,
  sendOffline,
  confirmOffline,
  publishKeys,
  signUp,
  signIn,
  signOut
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
  setTimeout(async () => {
    if (signedOut) return;
    try {
      const { data } = await sb.auth.getSession();
      if (signedOut) return;
      if (data && data.session && data.session.user) {
        window.__sbSession = data.session;
        closeAuthModals();
        setAuthUi(data.session);
        applyLoggedInSession(data.session);
      }
    } catch (e) {}
  }, 2500);
  sb.auth.onAuthStateChange((event, session) => {
    if (event === 'SIGNED_OUT') {
      window.__sbSession = null;
      setAuthUi(null);
      stopInbox();
    }
  });
});
