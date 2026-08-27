const SUPABASE_URL = 'https://crgmcdpmmxtrcocfbsac.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNyZ21jZHBtbXh0cmNvY2Zic2FjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2NjI4NTksImV4cCI6MjA4OTIzODg1OX0.pgEIhCIRKEjmwgIQVeQtXdzIWZu2diPXr-gjpvV7pGs';

const sb = (window.supabase && window.supabase.createClient)
  ? window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
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

function setAuthUi(session) {
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
    userInfo.classList.add('hidden');
    authLinks.style.display = 'block';
  }
}

async function applyLoggedInSession(session) {
  window.__sbSession = session;
  setAuthUi(session);
  if (!session || !session.user) {
    stopInbox();
    return;
  }
  const { data: profile } = await sb.from('profiles')
    .select('display_name')
    .eq('id', session.user.id)
    .maybeSingle();
  const display = (profile && profile.display_name)
    || (session.user.user_metadata && session.user.user_metadata.display_name)
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
  await publishKeys();
  await loadInbox();
  subscribeInbox(session.user.id);
  startHeartbeat();
  if (typeof renderMooseBook === 'function') renderMooseBook();
  if (!localStorage.getItem('moose_' + session.user.id + '_kitSaved')) {
    try {
      if (typeof loadPersistentKeys === 'function') {
        const keys = await loadPersistentKeys();
        if (keys && keys.recoveryKit && typeof showRecoveryKitModal === 'function') showRecoveryKitModal(keys.recoveryKit);
      }
    } catch (e) {}
  }
}

async function publishKeys() {
  if (!isLoggedIn()) return;
  try {
    if (typeof initIdentityKeys === 'function') await initIdentityKeys();
    if (typeof ensurePersistentKeys === 'function') await ensurePersistentKeys();
    let pub = null;
    if (typeof keyPair !== 'undefined' && keyPair && keyPair.publicKey && typeof exportPublicKey === 'function') {
      pub = await exportPublicKey(keyPair.publicKey);
    } else if (typeof generateUserKeypair === 'function') {
      pub = await generateUserKeypair();
    }
    const uid = currentUser().id;
    const keysPatch = {
      last_active: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    if (pub) keysPatch.public_key = pub;
    if (typeof identityPubB64 !== 'undefined' && identityPubB64) keysPatch.identity_public_key = identityPubB64;
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
  const p = row.payload || {};
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
    .select('id, payload, created_at')
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
  if (findErr || !dest) throw new Error('Recipient not found');
  const { error } = await sb.from('offline_messages').insert({
    to_user_id: dest.id,
    payload: {
      encrypted: sealed.encrypted,
      iv: sealed.iv,
      ephemeral_public: sealed.ephemeral_public,
      messageId: sealed.messageId || null
    }
  });
  if (error) throw error;
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
  if (data.session) await applyLoggedInSession(data.session);
  return data;
}

async function signIn(email, password) {
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error) throw error;
  await applyLoggedInSession(data.session);
  return data;
}

async function signOut() {
  stopInbox();
  if (sb) await sb.auth.signOut();
  window.__sbSession = null;
  setAuthUi(null);
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
      const data = await signUp(email, displayName, password);
      signUpModal.classList.add('hidden');
      signUpModal.classList.remove('active');
      if (!data.session) alert('Account created. Confirm your email, then log in.');
    } catch (err) {
      alert(err.message || 'Sign up failed');
    }
  };
  const loginSubmit = document.getElementById('modalLoginSubmit');
  if (loginSubmit) loginSubmit.onclick = async () => {
    const email = document.getElementById('modalLoginEmail').value.trim();
    const password = document.getElementById('modalLoginPassword').value;
    if (!email || !password) return alert('Email and password required');
    try {
      await signIn(email, password);
      loginModal.classList.add('hidden');
      loginModal.classList.remove('active');
    } catch (err) {
      alert(err.message || 'Login failed');
    }
  };
  const signOutBtn = document.getElementById('signOutBtn');
  if (signOutBtn) signOutBtn.onclick = async () => {
    await signOut();
    location.reload();
  };
  sb.auth.onAuthStateChange((event, session) => {
    if (event === 'INITIAL_SESSION' || event === 'SIGNED_IN') {
      applyLoggedInSession(session);
    } else if (event === 'SIGNED_OUT') {
      window.__sbSession = null;
      setAuthUi(null);
      stopInbox();
    }
  });
});
