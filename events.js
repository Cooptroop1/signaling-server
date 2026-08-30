// Add this new function at the top
function detectImageMime(base64) {
  try {
    const bin = atob(base64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      arr[i] = bin.charCodeAt(i);
    }
    // PNG signature
    if (arr[0] === 137 && arr[1] === 80 && arr[2] === 78 && arr[3] === 71 && arr[4] === 13 && arr[5] === 10 && arr[6] === 26 && arr[7] === 10) {
      return 'image/png';
    }
    // JPEG signature
    if (arr[0] === 255 && arr[1] === 216 && arr[2] === 255) {
      return 'image/jpeg';
    }
    // GIF signature
    if (arr[0] === 71 && arr[1] === 73 && arr[2] === 70 && arr[3] === 56) {
      return 'image/gif';
    }
    // WEBP signature
    if (bin.slice(0, 4) === 'RIFF' && bin.slice(8, 12) === 'WEBP') {
      return 'image/webp';
    }
    return null;
  } catch (e) {
    console.error('Mime detection error:', e);
    return null;
  }
}
// generateUserKeypair moved to top to ensure it's defined before onclick handlers
async function generateUserKeypair() {
  try {
    const keys = await getSessionKeys();
    if (!isGuestUser() && keys.recoveryKit) {
      showRecoveryKitModal(keys.recoveryKit);
    }
    applyPersistentIdentity(keys);
    console.log('Generated/loaded session user keypair');
    return keys.ecdhPubB64;
  } catch (error) {
    console.error('generateUserKeypair error:', error);
    throw new Error('Failed to generate user keypair');
  }
}
async function generateSessionKeyPair() {
  return window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    false,
    ['deriveKey', 'deriveBits']
  );
}
async function ensureSessionKeyPair() {
  if (!keyPair || !keyPair.publicKey) {
    keyPair = await generateSessionKeyPair();
  }
  return keyPair;
}
console.log('generateUserKeypair function loaded'); // Confirm it's defined
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}
function setCookie(name, value, days) {
  let expires = '';
  if (days) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    expires = '; expires=' + date.toUTCString();
  }
  document.cookie = name + '=' + (value || '') + expires + '; path=/; Secure; HttpOnly; SameSite=Strict';
}
function processSignalingQueue() {
  signalingQueue.forEach((queue, key) => {
    while (queue.length > 0) {
      const { type, additionalData } = queue.shift();
      if (type.startsWith('relay-')) {
        sendRelayMessage(type, additionalData);
      } else {
        sendSignalingMessage(type, additionalData);
      }
    }
  });
  signalingQueue.clear();
}
let reconnectAttempts = 0;
const imageRateLimits = new Map();
const voiceRateLimits = new Map();
let globalMessageRate = { count: 0, startTime: performance.now() };
function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const randomBytes = window.crypto.getRandomValues(new Uint8Array(16));
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars[randomBytes[i] % chars.length];
    if (i % 4 === 3 && i < 15) result += '-';
  }
  return result;
}
let code = generateCode();
function readInitialClientId() {
  if (typeof window !== 'undefined' && window.__CLIENT_ID__) return window.__CLIENT_ID__;
  try {
    const stored = sessionStorage.getItem('anonClientId');
    if (stored) return stored;
  } catch (e) {}
  return newClientId();
}
let clientId = readInitialClientId();
try { sessionStorage.setItem('anonClientId', clientId); } catch (e) {}
let username = '';
let isInitiator = false;
let isConnected = false;
let maxClients = 2;
let totalClients = 0;
let peerConnections = new Map();
let dataChannels = new Map();
let connectionTimeouts = new Map();
let retryCounts = new Map();
const maxRetries = 2;
let candidatesQueues = new Map();
let processedMessageIds = new Set();
let usernames = new Map();
let claimedClients = new Map();
let messageRateLimits = new Map();
let codeSentToRandom = false;
let useRelay = false;
let token = '';
let refreshToken = '';
let features = { enableService: true, enableImages: true, enableVoice: true, enableVoiceCalls: true, enableAudioToggle: true, enableGrokBot: true, enableP2P: true, enableRelay: true };
let keyPair;
let roomMaster;
let signingKey;
let signingSalt;
let messageSalt;
let remoteAudios = new Map();
let refreshingToken = false;
let signalingQueue = new Map();
let connectedClients = new Set();
let clientPublicKeys = new Map();
let clientEcdhKeys = new Map();
let clientIdentityKeys = new Map();
let identityKeyPair = null;
let identityPubB64 = null;
let attachSheetOpen = false;
let lastAttachAction = 'photos';
let voiceCancelled = false;
function closeAttachSheet() {
  attachSheetOpen = false;
  document.getElementById('attachSheet')?.classList.remove('open');
  updateAttachButton();
}
function updateAttachButton() {
  const btn = document.getElementById('imageButton');
  if (!btn) return;
  const recording = !!(typeof mediaRecorder !== 'undefined' && mediaRecorder && mediaRecorder.state === 'recording');
  btn.classList.toggle('open', attachSheetOpen);
  btn.classList.toggle('recording', recording);
  btn.classList.toggle('active', !!voiceCallActive && !recording);
  if (recording) {
    btn.textContent = '■';
    btn.title = 'Stop recording';
  } else if (attachSheetOpen) {
    btn.textContent = '+';
    btn.title = 'Close';
  } else if (voiceCallActive) {
    btn.textContent = '📞';
    btn.title = 'End call';
  } else {
    const icons = { photos: '📷', camera: '📸', file: '📄', voice: '🎤', call: '📞', grok: '🤖' };
    btn.textContent = icons[lastAttachAction] || '📷';
    btn.title = 'Attach photo, file, voice or call';
  }
  const callTile = document.getElementById('voiceCallButton');
  if (callTile) {
    callTile.classList.toggle('active', !!voiceCallActive);
    const label = callTile.querySelector('.attach-label');
    if (label) label.textContent = voiceCallActive ? 'Hang up' : 'Call';
  }
}
function updateComposerSend() {
  const send = document.getElementById('sendButton');
  if (!send) return;
  send.textContent = '➤';
  send.dataset.mode = 'send';
  send.title = 'Send';
  send.setAttribute('aria-label', 'Send message');
  send.classList.remove('mic-mode');
}
function setComposerRecording(on) {
  document.getElementById('composerRow')?.classList.toggle('hidden', on);
  document.getElementById('recordBar')?.classList.toggle('hidden', !on);
  attachSheetOpen = false;
  document.getElementById('attachSheet')?.classList.remove('open');
  updateAttachButton();
}
function toggleAttachSheet() {
  if (typeof mediaRecorder !== 'undefined' && mediaRecorder && mediaRecorder.state === 'recording') {
    stopVoiceRecording();
    return;
  }
  if (voiceCallActive) {
    toggleVoiceCall();
    updateAttachButton();
    return;
  }
  attachSheetOpen = !attachSheetOpen;
  document.getElementById('attachSheet')?.classList.toggle('open', attachSheetOpen);
  updateAttachButton();
}
function pickAttachFile(inputId) {
  closeAttachSheet();
  const el = document.getElementById(inputId);
  if (el) {
    el.value = '';
    el.click();
  }
}
function handleAttachAction(action) {
  lastAttachAction = action || lastAttachAction;
  if (action === 'photos') pickAttachFile('imageInput');
  else if (action === 'camera') pickAttachFile('cameraInput');
  else if (action === 'file') pickAttachFile('fileInput');
  else if (action === 'voice') {
    closeAttachSheet();
    startVoiceRecording();
  } else if (action === 'call') {
    closeAttachSheet();
    toggleVoiceCall();
  } else if (action === 'grok') {
    closeAttachSheet();
    toggleGrokBot();
  }
  updateAttachButton();
}
let initiatorPublic;
let persistentEcdhPrivate = null;
let userPublicKey;
let userPublicKeyIdentity = null;
let lastWsUrl = '';
let pinReconnect = false;
let connectedWaiters = [];
let socket, statusElement, codeDisplayElement, copyCodeButton, initialContainer, usernameContainer, connectContainer, chatContainer, newSessionButton, maxClientsContainer, inputContainer, messages, cornerLogo, button2, helpText, helpModal;
let lazyObserver;
let p2pOnly = false;
let roomForceRelay = false;
let suppressAutoBurnUntil = 0;
let hideLocalTimer = null;
let hideRoomTimer = null;
const serverUrls = [
  'wss://signaling-server-zc6m.onrender.com',
  'wss://signal.anonomoose.com'
];
let serverUrlIndex = 0;
let wsWatchTimer = null;
function watchSocketConnect(s) {
  clearTimeout(wsWatchTimer);
  wsWatchTimer = setTimeout(() => {
    if (s && s.readyState !== WebSocket.OPEN) {
      console.warn('WebSocket connect timeout, trying next server', s.url);
      try { s.close(); } catch (e) {}
    }
  }, 2500);
}
function serverForCode(roomCode) {
  return serverUrls[Math.min(serverUrlIndex, serverUrls.length - 1)];
}
if (typeof window !== 'undefined') {
function notifyConnected() {
  const waiters = connectedWaiters.slice();
  connectedWaiters = [];
  waiters.forEach(fn => fn());
}
function waitForToken(timeoutMs = 10000) {
  if (token && socket && socket.readyState === WebSocket.OPEN) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Signaling reconnect timed out')), timeoutMs);
    connectedWaiters.push(() => {
      clearTimeout(timer);
      resolve();
    });
  });
}
function bindSocketHandlers(s) {
  s.onopen = handleSocketOpen;
  s.onerror = handleSocketError;
  s.onclose = handleSocketClose;
  s.onmessage = handleSocketMessage;
}
async function ensureServerForCode(roomCode) {
  const want = serverForCode(roomCode);
  const wantHost = want.replace(/^wss:\/\//, '').split('/')[0];
  let haveHost = '';
  try { haveHost = socket && socket.url ? new URL(socket.url).host : ''; } catch (e) {}
  if (haveHost === wantHost && socket && socket.readyState === WebSocket.OPEN && token) {
    return;
  }
  pinReconnect = true;
  lastWsUrl = want;
  token = '';
  refreshToken = '';
  try {
    if (socket && socket.readyState === WebSocket.OPEN) socket.close();
  } catch (e) {}
  socket = new WebSocket(want);
  bindSocketHandlers(socket);
  watchSocketConnect(socket);
  await waitForToken();
  pinReconnect = false;
}
async function initIdentityKeys() {
  if (identityKeyPair && identityPubB64) return;
  const keys = await getSessionKeys();
  applyPersistentIdentity(keys);
}
function applyPersistentIdentity(keys) {
  persistentEcdhPrivate = keys.ecdhPrivate;
  identityKeyPair = { privateKey: keys.ecdsaPrivate, publicKey: keys.ecdsaPublic };
  identityPubB64 = keys.ecdsaPubB64;
}
async function sendJoin(extra) {
  extra = extra || {};
  await initIdentityKeys();
  await ensureServerForCode(code);
  socket.send(JSON.stringify(Object.assign({
    type: 'join',
    code,
    clientId,
    username,
    token,
    identityPublic: identityPubB64,
    sbAccess: (window.__sbSession && window.__sbSession.access_token) || undefined
  }, extra)));
}
function readP2pOnly() {
  return !!(
    document.getElementById('p2pOnlyCheckStart')?.checked ||
    document.getElementById('p2pOnlyCheck')?.checked ||
    document.getElementById('p2pOnlyCheckConnect')?.checked
  );
}
function syncLinkToggles(src) {
  if (!src) return;
  const p2pIds = ['p2pOnlyCheckStart', 'p2pOnlyCheck', 'p2pOnlyCheckConnect'];
  const lanIds = ['lanDropCheckStart', 'lanDropCheck', 'lanDropCheckConnect'];
  const ids = p2pIds.includes(src.id) ? p2pIds : lanIds.includes(src.id) ? lanIds : null;
  if (!ids) return;
  ids.forEach((id) => {
    const el = document.getElementById(id);
    if (el && el !== src) el.checked = src.checked;
  });
}
function enterHostedRoom() {
  p2pOnly = readP2pOnly();
  initialContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  if (codeDisplayElement) {
    codeDisplayElement.textContent = 'Your code: ' + code;
    codeDisplayElement.classList.remove('hidden');
  }
  copyCodeButton?.classList.remove('hidden');
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for them to join…';
  sendJoin().catch((err) => {
    console.error(err);
    showStatusMessage('Failed to start chat.');
  });
  document.getElementById('messageInput')?.focus();
}
window.enterHostedRoom = enterHostedRoom;
lastWsUrl = serverForCode((new URLSearchParams(window.location.search).get('code')) || code);
const bootCode = new URLSearchParams(window.location.search).get('code');
if (bootCode) {
  socket = new WebSocket(lastWsUrl);
  bindSocketHandlers(socket);
  watchSocketConnect(socket);
  console.log(`WebSocket created, connected to ${lastWsUrl}`);
} else {
  console.log('WebSocket deferred until a chat starts');
}
  username = (sessionStorage.getItem('username') || localStorage.getItem('username') || new URLSearchParams(window.location.search).get('name') || '').trim();
  if (username) rememberUsername(username);
  globalMessageRate.startTime = performance.now();
  statusElement = document.getElementById('status');
  codeDisplayElement = document.getElementById('codeDisplay');
  copyCodeButton = document.getElementById('copyCodeButton');
  initialContainer = document.getElementById('initialContainer');
  usernameContainer = document.getElementById('usernameContainer');
  connectContainer = document.getElementById('connectContainer');
  chatContainer = document.getElementById('chatContainer');
  newSessionButton = document.getElementById('newSessionButton');
  maxClientsContainer = document.getElementById('maxClientsContainer');
  inputContainer = document.querySelector('.input-container');
  messages = document.getElementById('messages');
  cornerLogo = document.getElementById('cornerLogo');
  button2 = document.getElementById('button2');
  helpText = document.getElementById('helpText');
  helpModal = document.getElementById('helpModal');
  window.sendJoin = sendJoin;
  window.ensureServerForCode = ensureServerForCode;
  window.initIdentityKeys = initIdentityKeys;
  window.notifyConnected = notifyConnected;
  window.serverForCode = serverForCode;
  window.bindSocketHandlers = bindSocketHandlers;
}
helpText.addEventListener('click', () => {
  helpModal.classList.add('active');
  helpModal.focus();
});
helpModal.addEventListener('click', () => {
  helpModal.classList.remove('active');
  helpText.focus();
});
helpModal.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    helpModal.classList.remove('active');
    helpText.focus();
  }
});
const addUserText = document.getElementById('addUserText');
const addUserModal = document.getElementById('addUserModal');
addUserText.addEventListener('click', (e) => {
  e.preventDefault();
  e.stopPropagation();
  inviteAnotherSeat();
});
addUserModal.addEventListener('click', (e) => {
  if (e.target === addUserModal) {
    addUserModal.classList.remove('active');
  }
});
addUserModal.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    addUserModal.classList.remove('active');
    addUserText.focus();
  }
});
document.addEventListener('click', () => {
  document.querySelectorAll('.user-dot.open').forEach((d) => d.classList.remove('open'));
});
let pendingCode = null;
let pendingJoin = null;
const maxReconnectAttempts = 5;
let refreshFailures = 0;
let refreshBackoff = 1000;
function updateLogoutButtonVisibility() {
  const logoutButton = document.getElementById('logoutButton');
  if (logoutButton) {
    logoutButton.classList.toggle('hidden', !(username && token));
  }
  const logged = !!(window.sbAuth && typeof window.sbAuth.isLoggedIn === 'function' && window.sbAuth.isLoggedIn());
  document.querySelectorAll('.logged-only-opt').forEach((el) => {
    el.classList.toggle('hidden', !logged);
  });
  if (typeof updateSealedNotesBadge === 'function') updateSealedNotesBadge();
  else if (typeof renderMooseInbox === 'function') renderMooseInbox();
}
function logout() {
  if (socket && socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({ type: 'logout', clientId, token }));
  }
  username = '';
  token = '';
  refreshToken = '';
  clientId = newClientId();
  try { sessionStorage.setItem('anonClientId', clientId); } catch (e) {}
  localStorage.removeItem('username');
  processedMessageIds.clear();
  connectedClients.clear();
  peerConnections.forEach((pc) => pc.close());
  peerConnections.clear();
  dataChannels.forEach((dc) => dc.close());
  dataChannels.clear();
  try { if (socket) socket.close(); } catch (e) {}
  initialContainer.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton?.classList.add('hidden');
  newSessionButton.classList.add('hidden');
  maxClientsContainer.classList.add('hidden');
  inputContainer.classList.add('hidden');
  messages.classList.remove('waiting');
  messages.innerHTML = '';
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  updateLogoutButtonVisibility();
  showStatusMessage('Logged out successfully.');
  document.getElementById('startChatToggleButton')?.focus();
}
function endChat() {
  burnTranscript();
  if (socket && socket.readyState === WebSocket.OPEN && code && token) {
    socket.send(JSON.stringify({ type: 'leave', code, clientId, token }));
  }
  processedMessageIds.clear();
  connectedClients.clear();
  peerConnections.forEach((pc) => pc.close());
  peerConnections.clear();
  dataChannels.forEach((dc) => dc.close());
  dataChannels.clear();
  initialContainer.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton?.classList.add('hidden');
  newSessionButton.classList.add('hidden');
  maxClientsContainer.classList.add('hidden');
  inputContainer.classList.add('hidden');
  messages.classList.remove('waiting');
  messages.innerHTML = '';
  code = '';
  pendingCode = null;
  const privacy = document.getElementById('privacyStatus');
  if (privacy) privacy.classList.add('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  updateLogoutButtonVisibility();
  showStatusMessage('Chat ended.');
  document.getElementById('startChatToggleButton')?.focus();
}
function handleSocketOpen() {
  clearTimeout(wsWatchTimer);
  try { sessionStorage.setItem('signalHost', socket.url); } catch (e) {}
  console.log('WebSocket opened');
  socket.send(JSON.stringify({ type: 'connect', clientId }));
  reconnectAttempts = 0;
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    console.log('Detected code in URL, setting pendingCode for autoConnect after token');
    if (code !== codeParam) pendingCode = codeParam;
  } else if (!code && !pendingJoin && !pinReconnect) {
    console.log('No valid code in URL, showing initial container');
    initialContainer.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton?.classList.add('hidden');
  }
  updateLogoutButtonVisibility();
}
function handleSocketError(error) {
  console.error('WebSocket error:', error);
}
function handleSocketClose() {
  console.log('WebSocket closed');
  stopKeepAlive();
  if (window.__lanLock) {
    console.log('LAN lock: not reconnecting');
    return;
  }
  if (pinReconnect) return;
  if (!code && !pendingCode && !pendingJoin) return;
  if (serverUrlIndex < serverUrls.length - 1 && reconnectAttempts === 0) {
    serverUrlIndex += 1;
    lastWsUrl = serverUrls[serverUrlIndex];
    socket = new WebSocket(lastWsUrl);
    bindSocketHandlers(socket);
    watchSocketConnect(socket);
    return;
  }
  if (reconnectAttempts >= maxReconnectAttempts) {
    showStatusMessage('Max reconnect attempts reached. Please refresh the page.', 10000);
    return;
  }
  const delay = Math.min(30000, 5000 * Math.pow(2, reconnectAttempts));
  reconnectAttempts++;
  setTimeout(() => {
    socket = new WebSocket(lastWsUrl || (window.serverForCode && window.serverForCode(code)) || 'wss://signaling-server-zc6m.onrender.com');
    if (window.bindSocketHandlers) window.bindSocketHandlers(socket);
    else bindSocketHandlers(socket);
    watchSocketConnect(socket);
  }, delay);
}
async function handleSocketMessage(event) {
  try {
    const message = JSON.parse(event.data);
    if (!message.type) {
      console.error('Invalid message: missing type');
      showStatusMessage('Invalid server message received.');
      return;
    }
    if (message.type === 'ping') {
      socket.send(JSON.stringify({ type: 'pong' }));
      console.log('Received ping, sent pong');
      return;
    }
    if (message.type === 'connected') {
      token = message.accessToken;
      refreshToken = message.refreshToken;
      if (message.turnUsername) turnUsername = message.turnUsername;
      if (message.turnCredential) turnCredential = message.turnCredential;
      if (message.clientId) {
        clientId = message.clientId;
        try { sessionStorage.setItem('anonClientId', clientId); } catch (e) {}
      }
      console.log('Received authentication tokens');
      startKeepAlive();
      setTimeout(refreshAccessToken, 5 * 60 * 1000);
      if (window.notifyConnected) window.notifyConnected();
      if (pendingCode && pendingCode !== code) {
        autoConnect(pendingCode);
        pendingCode = null;
      } else {
        pendingCode = null;
      }
      if (pendingJoin) {
        code = pendingJoin.code || code;
        username = pendingJoin.username || username;
        sendJoin(pendingJoin.totpCode ? { totpCode: pendingJoin.totpCode } : {}).catch(err => {
          console.error(err);
          showStatusMessage('Failed to join after reconnect.');
        });
        pendingJoin = null;
      }
      processSignalingQueue();
      updateLogoutButtonVisibility();
      return;
    }
    if (message.type === 'token-refreshed') {
      token = message.accessToken;
      refreshToken = message.refreshToken;
      console.log('Received new tokens:', { accessToken: token, refreshToken });
      refreshFailures = 0;
      refreshBackoff = 1000;
      setTimeout(refreshAccessToken, 5 * 60 * 1000);
      if (pendingJoin) {
        sendJoin(pendingJoin.totpCode ? { totpCode: pendingJoin.totpCode } : {}).catch(() => {});
        pendingJoin = null;
      }
      processSignalingQueue();
      refreshingToken = false;
      updateLogoutButtonVisibility();
      return;
    }
    if (message.type === 'error') {
      console.log('Server response:', message.message, 'Code:', message.code || 'N/A');
      if (message.message.includes('Username taken')) {
        const claimError = document.getElementById('claimError');
        claimError.textContent = 'Username already taken. Please try another.';
        setTimeout(() => {
          claimError.textContent = '';
        }, 5000);
        document.getElementById('claimUsernameInput').value = '';
        document.getElementById('claimPasswordInput').value = '';
        document.getElementById('claimUsernameInput')?.focus();
        return;
      }
      if (message.message.includes('Invalid login credentials')) {
        const loginError = document.getElementById('loginError');
        loginError.textContent = 'Invalid username or password. Please try again.';
        setTimeout(() => {
          loginError.textContent = '';
        }, 5000);
        document.getElementById('loginUsernameInput').value = '';
        document.getElementById('loginPasswordInput').value = '';
        document.getElementById('loginUsernameInput')?.focus();
        return;
      }
      if (message.message.includes('User already logged in')) {
        const loginError = document.getElementById('loginError');
        loginError.textContent = 'User is already logged in. Please log out from other sessions first.';
        setTimeout(() => {
          loginError.textContent = '';
        }, 5000);
        document.getElementById('loginUsernameInput').value = '';
        document.getElementById('loginPasswordInput').value = '';
        document.getElementById('loginUsernameInput')?.focus();
        return;
      }
      if (message.message.includes('Invalid or expired token') || message.message.includes('Missing authentication token')) {
        if (refreshToken && !refreshingToken) {
          refreshingToken = true;
          console.log('Attempting to refresh token');
          socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
        } else {
          console.error('No refresh token available or refresh in progress, forcing reconnect');
          socket.close();
        }
      } else if (message.message.includes('Token revoked') || message.message.includes('Invalid or expired refresh token')) {
        refreshFailures++;
        console.log(`Refresh failure count: ${refreshFailures}`);
        if (refreshFailures > 3) {
          console.log('Exceeded refresh failures, forcing full reconnect with new clientId');
          clientId = newClientId();
          try { sessionStorage.setItem('anonClientId', clientId); } catch (e) {}
          token = '';
          refreshToken = '';
          refreshFailures = 0;
          refreshBackoff = 1000;
          socket.close();
        } else {
          const jitter = Math.random() * 4000 + 1000;
          const delay = Math.min(refreshBackoff + jitter, 8000);
          setTimeout(() => {
            if (refreshToken && !refreshingToken) {
              refreshingToken = true;
              socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
            }
          }, delay);
          refreshBackoff = Math.min(refreshBackoff * 2, 8000);
        }
      } else if (message.message.includes('IP temporarily banned')) {
        showStatusMessage('Too many failed tries. Wait a minute and refresh.');
        return;
      } else if (message.message.includes('Rate limit exceeded')) {
        showStatusMessage('Rate limit exceeded. Waiting before retrying...');
        setTimeout(() => {
          if (reconnectAttempts < maxReconnectAttempts) {
            socket.send(JSON.stringify({ type: 'connect', clientId }));
          }
        }, 60000);
      } else if (message.message.includes('Chat is full') ||
        message.message.includes('Username already taken') ||
        message.message.includes('Initiator offline') ||
        message.message.includes('Invalid code format')) {
        console.log(`Join failed: ${message.message}`);
        showStatusMessage(`Failed to join chat: ${message.message}`);
        socket.send(JSON.stringify({ type: 'leave', code, clientId, token }));
        initialContainer.classList.remove('hidden');
        usernameContainer.classList.add('hidden');
        connectContainer.classList.add('hidden');
        codeDisplayElement.classList.add('hidden');
        copyCodeButton?.classList.add('hidden');
        chatContainer.classList.add('hidden');
        newSessionButton.classList.add('hidden');
        maxClientsContainer.classList.add('hidden');
        inputContainer.classList.add('hidden');
        messages.classList.remove('waiting');
        codeSentToRandom = false;
        button2.disabled = false;
        token = '';
        refreshToken = '';
        updateLogoutButtonVisibility();
        return;
      } else if (message.message.includes('Service has been disabled by admin.')) {
        showStatusMessage(message.message);
        initialContainer.classList.remove('hidden');
        usernameContainer.classList.add('hidden');
        connectContainer.classList.add('hidden');
        codeDisplayElement.classList.add('hidden');
        copyCodeButton?.classList.add('hidden');
        chatContainer.classList.add('hidden');
        newSessionButton.classList.add('hidden');
        maxClientsContainer.classList.add('hidden');
        inputContainer.classList.add('hidden');
        messages.classList.remove('waiting');
        socket.close();
        updateLogoutButtonVisibility();
        return;
      } else if (/Unknown message type/i.test(message.message || '')) {
        console.warn('Server:', message.message);
      } else {
        showStatusMessage(message.message);
      }
      return;
    }
    if (message.type === 'kick' || message.type === 'ban') {
      alert(message.message || `You have been ${message.type}ed from the room.`);
      endChat();
      return;
    }
    if (message.type === 'totp-required') {
      showTotpInputModal(message.code);
      return;
    }
    if (message.type === 'totp-not-required') {
      if (pendingTotpSecret) {
        showTotpSecretModal(pendingTotpSecret.display);
        pendingTotpSecret = null;
      }
      sendJoin();
      return;
    }
    if (message.type === 'init') {
      clientId = message.clientId;
      maxClients = Math.min(message.maxClients, 50);
      isInitiator = message.isInitiator;
      features = message.features || features;
      if (!features.enableP2P || message.forceRelay || maxClients > 4) {
        applyGroupRelay();
      }
      totalClients = 1;
      console.log(`Initialized client ${clientId}, username: ${username}, maxClients: ${maxClients}, isInitiator: ${isInitiator}, features: ${JSON.stringify(features)}`);
      usernames.set(clientId, username);
      claimedClients.set(clientId, !!(window.sbAuth && window.sbAuth.isLoggedIn()));
      if (Array.isArray(message.roster)) {
        message.roster.forEach((m) => {
          if (m.clientId && m.username) usernames.set(m.clientId, m.username);
          if (m.clientId) claimedClients.set(m.clientId, !!m.claimed);
        });
      }
      connectedClients.add(clientId);
      if (identityPubB64) clientIdentityKeys.set(clientId, identityPubB64);
      initialContainer.classList.add('hidden');
      usernameContainer.classList.add('hidden');
      connectContainer.classList.add('hidden');
      chatContainer.classList.remove('hidden');
      if (code) {
        codeDisplayElement.textContent = 'Your code: ' + code;
        codeDisplayElement.classList.remove('hidden');
        copyCodeButton?.classList.remove('hidden');
      }
      messages.classList.add('waiting');
      statusElement.textContent = isInitiator ? 'Waiting for connection...' : 'Connecting...';
      initializeMaxClientsUI();
      updateFeaturesUI();
      await ensureSessionKeyPair();
      if (isInitiator) {
        roomMaster = window.crypto.getRandomValues(new Uint8Array(32));
        signingSalt = window.crypto.getRandomValues(new Uint8Array(16));
        messageSalt = window.crypto.getRandomValues(new Uint8Array(16));
        signingKey = await deriveSigningKey();
        console.log('Generated initial roomMaster, signingSalt, messageSalt, and signingKey for initiator.');
        isConnected = true;
        if (pendingTotpSecret) {
          socket.send(JSON.stringify({ type: 'set-totp', secret: pendingTotpSecret.send, code, clientId, token }));
          showTotpSecretModal(pendingTotpSecret.display);
          pendingTotpSecret = null;
        }
        setInterval(triggerRatchet, 5 * 60 * 1000);
        if (useRelay) {
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Server backup · still encrypted';
            privacyStatus.classList.remove('hidden');
          }
          isConnected = true;
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      } else {
        try {
          const publicKey = await exportPublicKey(keyPair.publicKey);
          await initIdentityKeys();
          let identityEcdh = null;
          try {
            const me = await ensurePersistentKeys();
            identityEcdh = me && me.ecdhPubB64;
          } catch (e) {}
          if (socket && socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: 'public-key', publicKey, identityPublic: identityPubB64, identityEcdh, clientId, code, token }));
          }
        } catch (err) {
          console.error('Failed to send public-key:', err);
          showStatusMessage('Key setup failed. Rejoin the room.');
        }
      }
      updateMaxClientsUI();
      updateDots();
      if (message.turnUsername) turnUsername = message.turnUsername;
      if (message.turnCredential) turnCredential = message.turnCredential;
      updateRecentCodes(code);
      if (!isInitiator && Array.isArray(message.roster) && !groupRelayOn()) {
        message.roster.forEach((m) => {
          if (!m.clientId || m.clientId === clientId) return;
          setTimeout(() => {
            if (!peerConnections.has(m.clientId) && features.enableP2P) {
              startPeerConnection(m.clientId, true);
            }
          }, 2200);
        });
      }
      return;
    }
    if (message.type === 'initiator-changed') {
      console.log(`Initiator changed to ${message.newInitiator} for code: ${code}`);
      isInitiator = message.newInitiator === clientId;
      initializeMaxClientsUI();
      updateMaxClientsUI();
      return;
    }
    if (message.type === 'join-notify' && message.code === code) {
      totalClients = message.totalClients;
      console.log(`Join-notify received for code: ${code}, client: ${message.clientId}, total: ${totalClients}, username: ${message.username}`);
      if (message.username) {
        usernames.set(message.clientId, message.username);
      }
      claimedClients.set(message.clientId, !!message.claimed);
      if (message.identityPublic) {
        clientIdentityKeys.set(message.clientId, message.identityPublic);
      }
      connectedClients.add(message.clientId);
      updateMaxClientsUI();
      updateDots();
      if (isInitiator && message.clientId !== clientId && !peerConnections.has(message.clientId) && !groupRelayOn()) {
        console.log(`Initiating peer connection with client ${message.clientId}`);
        startPeerConnection(message.clientId, true);
      } else if (!isInitiator && message.clientId !== clientId && !groupRelayOn()) {
        const otherId = message.clientId;
        setTimeout(() => {
          if (!peerConnections.has(otherId) && features.enableP2P) {
            startPeerConnection(otherId, true);
          }
        }, 2200);
      }
      if (voiceCallActive) {
        renegotiate(message.clientId);
      }
      if (useRelay) {
        isConnected = true;
        inputContainer.classList.remove('hidden');
        messages.classList.remove('waiting');
        updateMaxClientsUI();
      }
      updateRecentCodes(code);
      return;
    }
    if (message.type === 'room-wipe') {
      if (message.clientId !== clientId) applyRemoteRoomWipe();
      return;
    }
    if (message.type === 'client-disconnected') {
      totalClients = message.totalClients;
      console.log(`Client ${message.clientId} disconnected from code: ${code}, total: ${totalClients}`);
      usernames.delete(message.clientId);
      connectedClients.delete(message.clientId);
      clientPublicKeys.delete(message.clientId);
      cleanupPeerConnection(message.clientId);
      if (remoteAudios.has(message.clientId)) {
        const audio = remoteAudios.get(message.clientId);
        audio.remove();
        remoteAudios.delete(message.clientId);
        if (remoteAudios.size === 0) {
          document.getElementById('remoteAudioContainer').classList.add('hidden');
        }
      }
      updateMaxClientsUI();
      updateDots();
      if (totalClients <= 1) {
        showStatusMessage('The other person left. Room is still open if they rejoin.');
        inputContainer.classList.add('hidden');
        messages.classList.add('waiting');
        statusElement.textContent = 'Waiting for connection...';
      }
      if (totalClients <= 1) {
        inputContainer.classList.add('hidden');
        messages.classList.add('waiting');
        endChat();
      }
      return;
    }
    if (message.type === 'max-clients') {
      maxClients = Math.min(message.maxClients, 50);
      console.log(`Max clients updated to ${maxClients} for code: ${code}`);
      if (message.forceRelay || maxClients > 4) applyGroupRelay();
      updateMaxClientsUI();
      updateDots();
      return;
    }
    if (message.type === 'offer' && message.clientId !== clientId) {
      console.log(`Received offer from ${message.clientId} for code: ${code}`);
      handleOffer(message.offer, message.clientId);
      return;
    }
    if (message.type === 'answer' && message.clientId !== clientId) {
      console.log(`Received answer from ${message.clientId} for code: ${code}`);
      handleAnswer(message.answer, message.clientId);
      return;
    }
    if (message.type === 'candidate' && message.clientId !== clientId) {
      console.log(`Received ICE candidate from ${message.clientId} for code: ${code}`);
      if (!peerConnections.has(message.clientId) && features.enableP2P) {
        startPeerConnection(message.clientId, !!isInitiator);
      }
      handleCandidate(message.candidate, message.clientId);
      return;
    }
    if (message.type === 'public-key') {
      try {
        clientPublicKeys.set(message.clientId, message.publicKey);
        if (message.identityPublic) {
          clientIdentityKeys.set(message.clientId, message.identityPublic);
        }
        if (message.identityEcdh) {
          clientEcdhKeys.set(message.clientId, message.identityEcdh);
        }
        if (!isInitiator) return;
        await ensureSessionKeyPair();
        const joinerPublic = await importPublicKey(message.publicKey);
        const sharedKey = await derivePakeWrapKey(keyPair.privateKey, joinerPublic, code);
        const payload = {
          roomMaster: arrayBufferToBase64(roomMaster),
          signingSalt: arrayBufferToBase64(signingSalt),
          messageSalt: arrayBufferToBase64(messageSalt)
        };
        const payloadStr = JSON.stringify(payload);
        const { encrypted, iv } = await encryptRaw(sharedKey, payloadStr, 'room-key|' + code);
        const myPublic = await exportPublicKey(keyPair.publicKey);
        await initIdentityKeys();
        let identityEcdh = null;
        try {
          const me = await ensurePersistentKeys();
          identityEcdh = me && me.ecdhPubB64;
        } catch (e) {}
        socket.send(JSON.stringify({
          type: 'encrypted-room-key',
          encryptedKey: encrypted,
          iv,
          publicKey: myPublic,
          identityPublic: identityPubB64,
          identityEcdh,
          targetId: message.clientId,
          code,
          clientId,
          token
        }));
      } catch (error) {
        console.error('Error handling public-key:', error);
        showStatusMessage('Key exchange failed.');
      }
      return;
    }
    if (message.type === 'encrypted-room-key') {
      try {
        initiatorPublic = message.publicKey;
        if (message.identityPublic) {
          clientIdentityKeys.set(message.clientId || 'initiator', message.identityPublic);
        }
        if (message.identityEcdh) {
          clientEcdhKeys.set(message.clientId || 'initiator', message.identityEcdh);
        }
        if (message.publicKey && message.clientId) {
          clientPublicKeys.set(message.clientId, message.publicKey);
        }
        const initiatorPublicImported = await importPublicKey(initiatorPublic);
        await ensureSessionKeyPair();
        const sharedKey = await derivePakeWrapKey(keyPair.privateKey, initiatorPublicImported, code);
        const decryptedStr = await decryptRaw(sharedKey, message.encryptedKey, message.iv, 'room-key|' + code);
        const payload = JSON.parse(decryptedStr);
        roomMaster = base64ToArrayBuffer(payload.roomMaster);
        signingSalt = base64ToArrayBuffer(payload.signingSalt);
        messageSalt = base64ToArrayBuffer(payload.messageSalt);
        signingKey = await deriveSigningKey();
        console.log('Room master, salts successfully imported.');
        if (useRelay) {
          isConnected = true;
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Server backup · still encrypted';
            privacyStatus.classList.remove('hidden');
          }
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      } catch (error) {
        console.error('Error handling encrypted-room-key:', error);
        showStatusMessage('Failed to receive encryption key.');
      }
      return;
    }
    if (message.type === 'new-room-key' && message.targetId === clientId) {
      if (!message.version || message.version <= keyVersion) {
        console.log(`Ignoring outdated key version ${message.version} (current: ${keyVersion})`);
        return;
      }
      try {
        const dhPubB64 = message.publicKey || initiatorPublic;
        if (!dhPubB64) {
          throw new Error('No initiator public key available for ratchet');
        }
        const importedInitiatorPublic = await importPublicKey(dhPubB64);
        const shared = await derivePakeWrapKey(keyPair.privateKey, importedInitiatorPublic, code);
        const decryptedStr = await decryptRaw(shared, message.encrypted, message.iv, 'new-room-key|' + code + '|' + message.version);
        const payload = JSON.parse(decryptedStr);
        roomMaster = base64ToArrayBuffer(payload.roomMaster);
        signingSalt = base64ToArrayBuffer(payload.signingSalt);
        messageSalt = base64ToArrayBuffer(payload.messageSalt);
        signingKey = await deriveSigningKey();
        keyVersion = message.version;
        if (typeof skResetLocal === 'function') skResetLocal();
        if (message.publicKey) {
          initiatorPublic = message.publicKey;
        }
        console.log(`New room master and salts received and set for PFS (version ${keyVersion}).`);
        keyPair = await generateSessionKeyPair();
        const rotatedPub = await exportPublicKey(keyPair.publicKey);
        if (socket && socket.readyState === WebSocket.OPEN && token) {
          socket.send(JSON.stringify({ type: 'public-key', publicKey: rotatedPub, identityPublic: identityPubB64, clientId, code, token }));
        }
      } catch (error) {
        console.error('Error handling new-room-key:', error);
        showStatusMessage('Failed to update encryption key for PFS.');
      }
      return;
    }
    if ((message.type === 'message' || message.type === 'image' || message.type === 'voice' || message.type === 'file') && (message.encryptedContent || message.encryptedData)) {
      if (processedMessageIds.has(message.messageId)) return;
      processedMessageIds.add(message.messageId);
      console.log('Received relay message:', message);
      const encrypted = message.encryptedContent || message.encryptedData; // Handle conditional
      if (!message.messageId || !message.timestamp || !message.nonce || !message.iv || !encrypted) {
        console.error('Invalid payload in relay message:', message);
        showStatusMessage('Invalid message received.');
        return;
      }
      if (!message.sk && !message.signature) {
        console.error('Invalid payload in relay message:', message);
        showStatusMessage('Invalid message received.');
        return;
      }
      const now = Date.now();
      if (Math.abs(now - message.timestamp) > 300000) {
        console.warn(`Rejecting relay message with timestamp ${message.timestamp} (now: ${now})`);
        return;
      }
      // Added rate limit check for relay messages
      let rateMap;
      let maxCount = 10;
      if (message.type === 'message') {
        rateMap = messageRateLimits;
      } else if (message.type === 'image') {
        rateMap = imageRateLimits;
        maxCount = 5;
      } else if (message.type === 'voice') {
        rateMap = voiceRateLimits;
        maxCount = 200; // Further increased limit for voice
      } else if (message.type === 'file') {
        rateMap = imageRateLimits;
        maxCount = 5;
      }
      const rateKey = 'relay';
      const rate = rateMap.get(rateKey) || { count: 0, startTime: performance.now() };
      const nowPerf = performance.now();
      if (nowPerf - rate.startTime > 1000) {
        rate.count = 1;
        rate.startTime = nowPerf;
      } else {
        rate.count++;
        if (rate.count > maxCount) {
          console.warn(`Rate limit exceeded for relay: ${rate.count} messages in 1s`);
          return;
        }
      }
      rateMap.set(rateKey, rate);
      try {
        let rawData;
        if (message.sk && typeof skDecrypt === 'function') {
          try {
            rawData = await skDecrypt(message.senderId || 'relay', message);
          } catch (e) {
            const messageKey = await deriveMessageKey();
            rawData = await decryptRaw(messageKey, encrypted, message.iv, String(message.messageId) + '|' + String(message.nonce));
          }
        } else {
        const messageKey = await deriveMessageKey();
        rawData = await decryptRaw(messageKey, encrypted, message.iv, String(message.messageId) + '|' + String(message.nonce));
        const toVerify = rawData + message.nonce;
        const valid = await verifyMessage(signingKey, message.signature, toVerify);
        if (!valid) {
          console.warn(`Invalid signature for relay message`);
          showStatusMessage('Invalid message signature detected.');
          return;
        }
        const encryptedBlob = message.encryptedContent || message.encryptedData;
        if (!message.identityPublic || !message.identitySig) {
          console.warn('Relay message missing identity signature');
          showStatusMessage('Unsigned message rejected.');
          return;
        }
        const senderId = message.senderId;
        if (senderId && clientIdentityKeys.has(senderId) && clientIdentityKeys.get(senderId) !== message.identityPublic) {
          console.warn('Relay identity key changed, accepting verified new key');
        }
        const identityOk = await verifyIdentitySignature(
          message.identityPublic,
          message.identitySig,
          String(message.messageId) + String(message.nonce) + String(encryptedBlob)
        );
        if (!identityOk) {
          console.warn('Relay identity signature invalid');
          showStatusMessage('Message identity check failed.');
          return;
        }
        if (senderId && message.identityPublic) {
          clientIdentityKeys.set(senderId, message.identityPublic);
        }
        }
        // Parse metadata (same as P2P)
        let metadataStr = '';
        let braceCount = 0;
        for (let i = 0; i < rawData.length; i++) {
          metadataStr += rawData[i];
          if (rawData[i] === '{') braceCount++;
          if (rawData[i] === '}') braceCount--;
          if (braceCount === 0 && metadataStr.startsWith('{')) break;
        }
        const metadata = JSON.parse(metadataStr);
        const senderUsername = (senderId && usernames.get(senderId)) || metadata.username;
        const claimed = !!(senderId && claimedClients.get(senderId));
        const timestamp = metadata.timestamp;
        const contentType = metadata.type;
        let base64Data = rawData.substring(metadataStr.length).trimEnd();
        let contentOrData;
        const messages = document.getElementById('messages');
        const isSelf = senderUsername === username;
        const messageDiv = document.createElement('div');
        messageDiv.className = `message-bubble ${isSelf ? 'self' : 'other'}`;
        const timeSpan = document.createElement('span');
        timeSpan.className = 'timestamp';
        timeSpan.textContent = new Date(timestamp).toLocaleTimeString();
        messageDiv.appendChild(timeSpan);
        const nameSpan = document.createElement('span');
        fillClaimedName(nameSpan, senderUsername, claimed);
        messageDiv.appendChild(nameSpan);
        let mime = message.mime;
        if (contentType === 'message') {
          contentOrData = base64Data;
        } else {
          let defaultMime = 'application/octet-stream';
          if (contentType === 'image') defaultMime = 'image/jpeg';
          if (contentType === 'voice') defaultMime = 'audio/webm';
          if (contentType === 'file' && !mime && message.filename) {
            const ext = message.filename.split('.').pop().toLowerCase();
            const mimeMap = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', pdf: 'application/pdf', txt: 'text/plain', mp3: 'audio/mpeg', webm: 'audio/webm' };
            mime = mimeMap[ext] || defaultMime;
          }
          if (base64Data.startsWith('data:')) {
            contentOrData = base64Data;
          } else {
            if (!mime && contentType === 'image') {
              mime = detectImageMime(base64Data) || defaultMime;
            }
            contentOrData = `data:${mime || defaultMime};base64,${base64Data}`;
          }
        }
        if (contentType === 'image') {
          const img = document.createElement('img');
          img.dataset.src = contentOrData;
          img.style.maxWidth = '100%';
          img.style.borderRadius = '0.5rem';
          img.style.cursor = 'pointer';
          img.setAttribute('alt', 'Received image');
          img.addEventListener('click', () => createImageModal(contentOrData, 'messageInput'));
          lazyObserver.observe(img);
          messageDiv.appendChild(img);
        } else if (contentType === 'voice') {
          messageDiv.appendChild(makeVoiceNotePlayer(contentOrData));
        } else if (contentType === 'file') {
          const link = document.createElement('a');
          link.href = contentOrData;
          link.download = message.filename || 'file';
          link.textContent = `Download ${message.filename || 'file'}`;
          link.setAttribute('alt', 'Received file');
          messageDiv.appendChild(link);
        } else {
          messageDiv.appendChild(document.createTextNode(sanitizeMessage(contentOrData)));
        }
        const burnMs = Number(metadata.burnMs) || 0;
        if (burnMs > 0) {
          const tag = document.createElement('span');
          tag.className = 'burn-tag';
          tag.textContent = Math.round(burnMs / 1000) + 's';
          messageDiv.appendChild(tag);
          setTimeout(() => {
            messageDiv.classList.add('burned-line');
            setTimeout(() => { try { messageDiv.remove(); } catch (e) {} }, 400);
          }, burnMs);
        }
        messages.prepend(messageDiv);
        messages.scrollTop = 0;
      } catch (error) {
        console.error('Decryption/verification failed for relay message:', error);
        showStatusMessage('Failed to decrypt/verify message.');
        return;
      }
      return;
    }
    if (message.type === 'features-update') {
      features = message;
      console.log('Received features update:', features);
      setTimeout(updateFeaturesUI, 0);
      if (!features.enableService) {
        showStatusMessage(`Service disabled by admin. Disconnecting...`);
        socket.close();
      }
      return;
    }
    if (message.type === 'turn-credentials') {
      if (message.turnUsername) turnUsername = message.turnUsername;
      if (message.turnCredential) turnCredential = message.turnCredential;
      return;
    }
    if (message.type === 'username-registered') {
      const claimSuccess = document.getElementById('claimSuccess');
      claimSuccess.textContent = `Username claimed successfully: ${message.username}`;
      setTimeout(() => {
        claimSuccess.textContent = '';
        document.getElementById('claimUsernameModal').classList.remove('active');
        initialContainer.classList.remove('hidden');
        usernameContainer.classList.add('hidden');
        connectContainer.classList.add('hidden');
        chatContainer.classList.add('hidden');
        codeDisplayElement.classList.add('hidden');
        copyCodeButton?.classList.add('hidden');
        statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'login-success') {
      username = message.username;
      rememberUsername(username);
      const loginSuccess = document.getElementById('loginSuccess');
      loginSuccess.textContent = `Logged in as ${username}`;
      if (message.offlineMessages && message.offlineMessages.length > 0) {
        deliverOfflineMessages(message.offlineMessages);
        showStatusMessage('Pending offline messages loaded.');
      }
      setTimeout(() => {
        loginSuccess.textContent = '';
        document.getElementById('loginModal').classList.remove('active');
        initialContainer.classList.remove('hidden');
        usernameContainer.classList.add('hidden');
        connectContainer.classList.add('hidden');
        chatContainer.classList.add('hidden');
        codeDisplayElement.classList.add('hidden');
        copyCodeButton?.classList.add('hidden');
        statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'user-found') {
      const searchedUsername = document.getElementById('searchUsernameInput').value.trim();
      showUserSearchResult(searchedUsername, message);
      return;
    }
    if (message.type === 'inbox-message' || message.type === 'incoming-connection') {
      if (message.encrypted && message.ephemeral_public) {
        openOfflinePayload(message).then(opened => {
          let parsed;
          try { parsed = JSON.parse(opened); } catch (e) { parsed = null; }
          if (parsed && parsed.type === 'connection-request' && parsed.code) {
            showIncomingInvite(parsed.from || 'Someone', parsed.code, message.id);
            return;
          }
          const fromName = (parsed && parsed.from) || 'Someone';
          const displayText = (parsed && parsed.text) || opened;
          const messageDiv = document.createElement('div');
          messageDiv.className = 'message-bubble other';
          messageDiv.textContent = `Message from ${fromName}: ${displayText}`;
          if (messages) messages.prepend(messageDiv);
          if (message.id) confirmOfflineMessage(message.id);
        }).catch(() => {
          showStatusMessage('Could not decrypt an incoming message.');
        });
        return;
      }
      if (message.code) {
        showIncomingInvite(message.from || 'Someone', message.code, null);
      }
      return;
    }
    if (message.type === 'connection-denied') {
      showStatusMessage(`Connection request denied by ${message.from}`);
      return;
    }
    if (message.type === 'user-not-found') {
      document.getElementById('searchError').textContent = 'User not found.';
      setTimeout(() => {
        document.getElementById('searchError').textContent = '';
      }, 5000);
      return;
    }
    if (message.type === 'offline-message-sent') {
      showStatusMessage('Encrypted offline message sent.');
      return;
    }
  } catch (error) {
    console.error('Error parsing message:', error, 'Raw data:', event.data);
  }
};
function refreshAccessToken() {
  if (socket && socket.readyState === WebSocket.OPEN && refreshToken && !refreshingToken) {
    refreshingToken = true;
    console.log('Proactively refreshing access token');
    socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
  } else {
    console.log('Cannot refresh token: WebSocket not open, no refresh token, or refresh in progress');
  }
}
async function triggerRatchet() {
  if (!isInitiator || connectedClients.size <= 1) return;
  keyVersion++;
  const newKeyPair = await generateSessionKeyPair();
  const newPub = await exportPublicKey(newKeyPair.publicKey);
  const newRoomMaster = window.crypto.getRandomValues(new Uint8Array(32));
  const newSigningSalt = window.crypto.getRandomValues(new Uint8Array(16));
  const newMessageSalt = window.crypto.getRandomValues(new Uint8Array(16));
  let success = 0;
  let failures = [];
  for (const cId of connectedClients) {
    if (cId === clientId) continue;
    const publicKey = clientPublicKeys.get(cId);
    if (!publicKey) {
      console.warn(`No public key for client ${cId}, skipping ratchet send`);
      failures.push(cId);
      continue;
    }
    try {
      const importedPublic = await importPublicKey(publicKey);
      const shared = await derivePakeWrapKey(newKeyPair.privateKey, importedPublic, code);
      const payload = {
        roomMaster: arrayBufferToBase64(newRoomMaster),
        signingSalt: arrayBufferToBase64(newSigningSalt),
        messageSalt: arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await encryptRaw(shared, payloadStr, 'new-room-key|' + code + '|' + keyVersion);
      socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token, version: keyVersion, publicKey: newPub }));
      success++;
    } catch (error) {
      console.error(`Error sending new room key to ${cId}:`, error);
      failures.push(cId);
    }
  }
  if (success > 0) {
    keyPair = newKeyPair;
    roomMaster = newRoomMaster;
    signingSalt = newSigningSalt;
    messageSalt = newMessageSalt;
    signingKey = await deriveSigningKey();
    if (typeof skResetLocal === 'function') skResetLocal();
    console.log(`PFS ratchet complete (version ${keyVersion}), new roomMaster, salts, and DH key set.`);
    if (failures.length > 0) {
      console.warn(`Partial ratchet failure for clients: ${failures.join(', ')}. Retrying...`);
      triggerRatchetPartial(failures, newKeyPair, newPub, newRoomMaster, newSigningSalt, newMessageSalt, keyVersion, 1);
    }
  } else {
    console.warn(`PFS ratchet failed (version ${keyVersion}): No keys available to send to any clients.`);
    keyVersion--;
  }
}
async function triggerRatchetPartial(failures, newKeyPair, newPub, newRoomMaster, newSigningSalt, newMessageSalt, version, retryCount) {
  if (retryCount > 3) {
    console.warn(`Max retries (3) reached for partial ratchet (version ${version}). Giving up.`);
    return;
  }
  const backoffTimes = [10000, 30000, 60000];
  const delay = backoffTimes[retryCount - 1];
  console.log(`Scheduling retry ${retryCount} in ${delay / 1000}s for version ${version}`);
  await new Promise(resolve => setTimeout(resolve, delay));
  let retrySuccess = 0;
  let newFailures = [];
  for (const cId of failures) {
    const publicKey = clientPublicKeys.get(cId);
    if (!publicKey) {
      newFailures.push(cId);
      continue;
    }
    try {
      const importedPublic = await importPublicKey(publicKey);
      const shared = await derivePakeWrapKey(newKeyPair.privateKey, importedPublic, code);
      const payload = {
        roomMaster: arrayBufferToBase64(newRoomMaster),
        signingSalt: arrayBufferToBase64(newSigningSalt),
        messageSalt: arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await encryptRaw(shared, payloadStr, 'new-room-key|' + code + '|' + version);
      socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token, version, publicKey: newPub }));
      retrySuccess++;
    } catch (error) {
      console.error(`Retry ${retryCount} failed for ${cId}:`, error);
      newFailures.push(cId);
    }
  }
  if (retrySuccess > 0) {
    console.log(`Partial ratchet retry ${retryCount} successful for ${retrySuccess} clients (version ${version}).`);
  }
  if (newFailures.length > 0) {
    console.warn(`Still failures after retry ${retryCount}: ${newFailures.join(', ')}. Trying again...`);
    triggerRatchetPartial(newFailures, newKeyPair, newPub, newRoomMaster, newSigningSalt, newMessageSalt, version, retryCount + 1);
  } else {
    console.log(`All partial ratchet retries complete for version ${version}.`);
  }
}
function updateDots() {
  if (typeof updateRoomHeadcount === 'function') updateRoomHeadcount();
  const userDots = document.getElementById('userDots');
  if (!userDots) return;
  userDots.innerHTML = '';
  const greenCount = totalClients;
  const redCount = maxClients - greenCount;
  const otherClientIds = Array.from(connectedClients).filter(id => id !== clientId);
  const selfDot = document.createElement('div');
  selfDot.className = 'user-dot online';
  userDots.appendChild(selfDot);
  otherClientIds.forEach((targetId, index) => {
    const dot = document.createElement('div');
    dot.className = 'user-dot online';
    dot.dataset.targetId = targetId;
    const name = usernames.get(targetId) || 'User';
    const claimed = !!claimedClients.get(targetId);
    dot.title = claimed ? name + ' (logged in)' : name;
    if (isInitiator) {
      const menu = document.createElement('div');
      menu.className = 'user-menu';
      const label = document.createElement('div');
      label.textContent = claimed ? name + ' · logged in' : name;
      label.style.cssText = 'padding:0.4rem 0.6rem;font-size:0.75rem;border-bottom:1px solid #eee;color:' + (claimed ? '#dc2626' : '#374151') + ';font-weight:' + (claimed ? '800' : '500') + ';display:flex;align-items:center;gap:4px;';
      if (claimed) {
        const b = document.createElement('img');
        b.className = 'moose-badge';
        b.src = '/192.png';
        b.alt = '';
        b.width = 14;
        b.height = 14;
        label.appendChild(b);
      }
      const kickButton = document.createElement('button');
      kickButton.textContent = 'Kick';
      kickButton.onclick = (e) => { e.stopPropagation(); kickUser(targetId); };
      const banButton = document.createElement('button');
      banButton.textContent = 'Ban';
      banButton.onclick = (e) => { e.stopPropagation(); banUser(targetId); };
      menu.appendChild(label);
      menu.appendChild(kickButton);
      menu.appendChild(banButton);
      dot.appendChild(menu);
      dot.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        userDots.querySelectorAll('.user-dot.open').forEach((d) => { if (d !== dot) d.classList.remove('open'); });
        dot.classList.toggle('open');
      });
    }
    userDots.appendChild(dot);
  });
  for (let i = 0; i < redCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'user-dot offline';
    userDots.appendChild(dot);
  }
}
async function kickUser(targetId) {
  if (!isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for kick:', targetId);
    showStatusMessage('Invalid target user for kick.');
    return;
  }
  console.log('Kicking user', targetId);
  const toSign = targetId + 'kick' + code;
  const signature = await signMessage(signingKey, toSign);
  const message = { type: 'kick', targetId, code, clientId, token, signature };
  console.log('Sending kick message:', message);
  socket.send(JSON.stringify(message));
  showStatusMessage('Kicked. That seat is closed until you tap Add User.');
}
async function banUser(targetId) {
  if (!isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for ban:', targetId);
    showStatusMessage('Invalid target user for ban.');
    return;
  }
  console.log('Banning user', targetId);
  const toSign = targetId + 'ban' + code;
  const signature = await signMessage(signingKey, toSign);
  const message = { type: 'ban', targetId, code, clientId, token, signature };
  console.log('Sending ban message:', message);
  socket.send(JSON.stringify(message));
  showStatusMessage('Banned. That seat is closed until you tap Add User.');
}
function setupLazyObserver() {
  lazyObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const elem = entry.target;
        if (elem.dataset.src) {
          elem.src = elem.dataset.src;
          delete elem.dataset.src;
          lazyObserver.unobserve(elem);
        }
        if (elem.dataset.fullSrc) {
          elem.src = elem.dataset.fullSrc;
          delete elem.dataset.fullSrc;
          lazyObserver.unobserve(elem);
        }
      }
    });
  }, { rootMargin: '100px' });
}
function loadRecentCodes() {
  try { localStorage.removeItem('recentCodes'); } catch (e) {}
  const recentCodesList = document.getElementById('recentCodesList');
  if (recentCodesList) recentCodesList.innerHTML = '';
  const recentChats = document.getElementById('recentChats');
  if (recentChats) recentChats.classList.add('hidden');
}
function updateRecentCodes(code) {
  // Live rooms are ephemeral — do not persist codes across refresh.
}
function setupWaitingForJoin(codeParam) {
  console.log('Setting up waiting state for URL code:', codeParam);
  initialContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton?.classList.add('hidden');
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for connection...';
  // Prompt for username if not set
  if (!username) {
    username = prompt('Enter your username (1-16 alphanumeric characters):')?.trim() || 'Guest';
    if (!validateUsername(username)) {
      showStatusMessage('Invalid username. Using "Guest".');
      username = 'Guest';
    }
    rememberUsername(username);
  }
  // Set pendingCode to trigger autoConnect after token
  pendingCode = codeParam;
  document.getElementById('messageInput')?.focus();
}
document.addEventListener('DOMContentLoaded', () => {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
  ['pointerdown', 'touchstart', 'click'].forEach((ev) => {
    document.addEventListener(ev, unlockCallAudio, { passive: true });
  });
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    setupWaitingForJoin(codeParam);
  }
  const codeInput = document.getElementById('codeInput');
  if (codeInput) {
    codeInput.addEventListener('input', (e) => {
      let val = e.target.value.replace(/[^a-zA-Z0-9]/gi, '');
      val = val.substring(0, 16);
      let formatted = '';
      for (let i = 0; i < val.length; i++) {
        if (i > 0 && i % 4 === 0) formatted += '-';
        formatted += val[i];
      }
      e.target.value = formatted;
    });
  }
  setupLazyObserver();
  loadRecentCodes();
  document.getElementById('userDots').addEventListener('click', (e) => {
    if (e.target.classList.contains('user-dot')) {
      e.target.classList.toggle('active');
    }
  });
  document.getElementById('loginButton').addEventListener('click', () => {
    if (username && token) {
      showStatusMessage('You are already logged in. Log out first to switch accounts.');
      return;
    }
    document.getElementById('loginModal').classList.add('active');
  });
  document.getElementById('loginSubmitButton').onclick = () => submitLegacyLogin();
  document.getElementById('loginCancelButton').onclick = () => {
    document.getElementById('loginModal').classList.remove('active');
  };
  document.getElementById('searchUserButton').addEventListener('click', async () => {
    if (window.loggedFeatures && window.loggedFeatures.requireUnlock) {
      const ok = await window.loggedFeatures.requireUnlock('Unlock search');
      if (!ok) return;
    }
    const modal = document.getElementById('searchUserModal');
    modal.classList.remove('hidden');
    modal.classList.add('active');
    const hint = document.getElementById('trustedSearchHint');
    if (hint && typeof getTrusted === 'function') {
      const t = getTrusted();
      hint.textContent = t.length ? ('Trusted first: ' + t.slice(0, 8).join(', ')) : '';
    }
  });
  document.getElementById('searchSubmitButton').onclick = async () => {
    const name = document.getElementById('searchUsernameInput').value.trim();
    if (!name) return;
    if (window.sbAuth && window.sbAuth.isLoggedIn()) {
      try {
        const found = await window.sbAuth.findUser(name);
        if (!found) {
          document.getElementById('searchError').textContent = 'User not found.';
          setTimeout(() => { document.getElementById('searchError').textContent = ''; }, 5000);
          return;
        }
        showUserSearchResult(name, found);
      } catch (err) {
        document.getElementById('searchError').textContent = 'Search failed.';
      }
      return;
    }
    socket.send(JSON.stringify({ type: 'find-user', username: name, from_username: username, clientId, token }));
  };
  document.getElementById('searchCancelButton').onclick = () => {
    const modal = document.getElementById('searchUserModal');
    modal.classList.remove('active');
    modal.classList.add('hidden');
  };
  document.getElementById('claimUsernameButton').addEventListener('click', () => {
    if (username && token) {
      showStatusMessage('You are already logged in. Log out first to claim a new username.');
      return;
    }
    document.getElementById('claimUsernameModal').classList.add('active');
  });
  document.getElementById('claimCancelButton').onclick = () => {
    document.getElementById('claimUsernameModal').classList.remove('active');
  };
  document.getElementById('claimSubmitButton').onclick = () => {
    if (username && token) {
      showStatusMessage('You are already logged in. Log out first to claim a new username.');
      return;
    }
    const name = document.getElementById('claimUsernameInput').value.trim();
    const pass = document.getElementById('claimPasswordInput').value;
    if (validateUsername(name) && pass.length >= 8) {
      generateUserKeypair().then(publicKey => {
        socket.send(JSON.stringify({
          type: 'register-username',
          username: name,
          password: pass,
          public_key: publicKey,
          identity_public_key: identityPubB64,
          clientId,
          token
        }));
      }).catch(error => {
        console.error('Key generation error:', error);
        showStatusMessage('Failed to generate keys for claim.');
      });
    } else {
      showStatusMessage('Invalid username or password (min 8 chars).');
    }
  };
  document.getElementById('loginSubmitButton').onclick = () => submitLegacyLogin();
  document.getElementById('logoutButton').onclick = () => {
    console.log('Logout button clicked');
    logout();
  };
  const copyRecoveryBtn = document.getElementById('copyRecoveryKitButton');
  if (copyRecoveryBtn) {
    copyRecoveryBtn.onclick = () => {
      const val = document.getElementById('recoveryKitValue').value;
      if (navigator.clipboard && val) navigator.clipboard.writeText(val);
      showStatusMessage('Recovery kit copied.');
    };
  }
  const closeRecoveryBtn = document.getElementById('closeRecoveryKitButton');
  if (closeRecoveryBtn) {
    closeRecoveryBtn.onclick = () => {
      document.getElementById('recoveryKitModal').classList.remove('active');
      document.getElementById('recoveryKitModal').classList.add('hidden');
    };
  }
  const restoreBtn = document.getElementById('restoreKeysButton');
  if (restoreBtn) {
    restoreBtn.onclick = () => {
      const kit = document.getElementById('recoverKitInput').value.trim();
      const modal = document.getElementById('recoverKeysModal');
      const name = modal.dataset.username;
      const pass = modal.dataset.password;
      restorePersistentKeys(kit).then(keys => {
        applyPersistentIdentity(keys);
        modal.classList.remove('active');
        modal.classList.add('hidden');
        socket.send(JSON.stringify({
          type: 'login-username',
          username: name,
          password: pass,
          public_key: keys.ecdhPubB64,
          identity_public_key: keys.ecdsaPubB64,
          clientId,
          token
        }));
        showStatusMessage('Keys restored.');
      }).catch(err => {
        console.error(err);
        showStatusMessage('Could not restore kit. Check it and try again.');
      });
    };
  }
  const genNewBtn = document.getElementById('generateNewKeysButton');
  if (genNewBtn) {
    genNewBtn.onclick = () => {
      const modal = document.getElementById('recoverKeysModal');
      const name = modal.dataset.username;
      const pass = modal.dataset.password;
      generateUserKeypair().then(publicKey => {
        modal.classList.remove('active');
        modal.classList.add('hidden');
        showStatusMessage('New keys generated. Old offline messages may be lost.');
        socket.send(JSON.stringify({
          type: 'login-username',
          username: name,
          password: pass,
          public_key: publicKey,
          identity_public_key: identityPubB64,
          clientId,
          token
        }));
      }).catch(err => {
        console.error(err);
        showStatusMessage('Failed to generate new keys.');
      });
    };
  }
  const cancelRecoverBtn = document.getElementById('cancelRecoverKeysButton');
  if (cancelRecoverBtn) {
    cancelRecoverBtn.onclick = () => {
      document.getElementById('recoverKeysModal').classList.remove('active');
      document.getElementById('recoverKeysModal').classList.add('hidden');
    };
  }
  updateLogoutButtonVisibility();
  ['p2pOnlyCheckStart', 'p2pOnlyCheck', 'p2pOnlyCheckConnect', 'lanDropCheckStart', 'lanDropCheck', 'lanDropCheckConnect'].forEach((id) => {
    document.getElementById(id)?.addEventListener('change', (e) => syncLinkToggles(e.target));
  });
  document.getElementById('startChatToggleButton').onclick = () => {
    console.log('Start chat toggle clicked');
    if (window.sbAuth && window.sbAuth.isLoggedIn() && validateUsername(username)) {
      document.getElementById('usernameInput').value = username;
      document.getElementById('joinWithUsernameButton').click();
      return;
    }
    initialContainer.classList.add('hidden');
    usernameContainer.classList.remove('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton?.classList.add('hidden');
    statusElement.textContent = 'Enter a username to start a chat';
    document.getElementById('usernameInput').value = username || '';
    document.getElementById('usernameInput')?.focus();
  };
  document.getElementById('connectToggleButton').onclick = () => {
    console.log('Connect toggle clicked');
    initialContainer.classList.add('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.remove('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton?.classList.add('hidden');
    statusElement.textContent = 'Enter a username and code to join a chat';
    document.getElementById('usernameConnectInput').value = username || '';
    document.getElementById('usernameConnectInput')?.focus();
  };
  document.getElementById('start2FAChatButton').onclick = () => {
    document.getElementById('totpOptionsModal').classList.add('active');
    document.getElementById('totpUsernameInput').value = username || '';
    document.getElementById('totpUsernameInput')?.focus();
    document.getElementById('customTotpSecretContainer').classList.add('hidden');
    document.querySelector('input[name="totpType"][value="server"]').checked = true;
  };
  const connect2FABtn = document.getElementById('connect2FAChatButton');
  if (connect2FABtn) connect2FABtn.onclick = () => {
    initialContainer.classList.add('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.remove('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton?.classList.add('hidden');
    statusElement.textContent = 'Enter a username and code to join a 2FA chat';
    document.getElementById('usernameConnectInput').value = username || '';
    document.getElementById('usernameConnectInput')?.focus();
    const connectButton = document.getElementById('connectButton');
    connectButton.onclick = () => {
      const usernameInput = document.getElementById('usernameConnectInput').value.trim();
      const inputCode = document.getElementById('codeInput').value.trim();
      if (!validateUsername(usernameInput)) {
        showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
        document.getElementById('usernameConnectInput')?.focus();
        return;
      }
      if (!validateCode(inputCode)) {
        showStatusMessage('Invalid code format: xxxx-xxxx-xxxx-xxxx.');
        document.getElementById('codeInput')?.focus();
        return;
      }
      username = usernameInput;
      rememberUsername(username);
      code = inputCode;
      showTotpInputModal(code);
    };
  };
  document.querySelectorAll('input[name="totpType"]').forEach(radio => {
    radio.addEventListener('change', () => {
      document.getElementById('customTotpSecretContainer').classList.toggle('hidden', radio.value !== 'custom');
    });
  });
  document.getElementById('createTotpRoomButton').onclick = () => {
    const serverGenerated = document.querySelector('input[name="totpType"]:checked').value === 'server';
    startTotpRoom(serverGenerated);
  };
  document.getElementById('cancelTotpButton').onclick = () => {
    document.getElementById('totpOptionsModal').classList.remove('active');
    initialContainer.classList.remove('hidden');
  };
  document.getElementById('closeTotpSecretButton').onclick = () => {
    document.getElementById('totpSecretModal').classList.remove('active');
  };
  document.getElementById('submitTotpCodeButton').onclick = () => {
    const totpCode = document.getElementById('totpCodeInput').value.trim();
    const codeParam = document.getElementById('totpInputModal').dataset.code;
    if (totpCode.length !== 6 || isNaN(totpCode)) {
      showStatusMessage('Invalid 2FA code: 6 digits required.');
      return;
    }
    joinWithTotp(codeParam, totpCode);
    document.getElementById('totpInputModal').classList.remove('active');
  };
  document.getElementById('cancelTotpInputButton').onclick = () => {
    document.getElementById('totpInputModal').classList.remove('active');
    initialContainer.classList.remove('hidden');
  };
  document.getElementById('joinWithUsernameButton').onclick = () => {
    const usernameInput = document.getElementById('usernameInput').value.trim();
    if (!validateUsername(usernameInput)) {
      showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
      document.getElementById('usernameInput')?.focus();
      return;
    }
    username = usernameInput;
    rememberUsername(username);
    const p2pBox = document.getElementById('p2pOnlyCheck');
    p2pOnly = readP2pOnly();
    if (window.pendingJoinCode && validateCode(window.pendingJoinCode)) {
      const joinCode = window.pendingJoinCode;
      window.pendingJoinCode = null;
      usernameContainer.classList.add('hidden');
      autoConnect(joinCode);
      return;
    }
    if (window.pendingStegoEncode) {
      window.pendingStegoEncode = false;
      usernameContainer.classList.add('hidden');
      initialContainer.classList.remove('hidden');
      document.getElementById('stegoEncodeBtn')?.click();
      return;
    }
    code = generateCode();
    codeDisplayElement.textContent = `Your code: ${code}`;
    codeDisplayElement.classList.remove('hidden');
    copyCodeButton?.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    initialContainer.classList.add('hidden');
    chatContainer.classList.remove('hidden');
    messages.classList.add('waiting');
    statusElement.textContent = 'Waiting for connection...';
    sendJoin().catch(err => {
      console.error(err);
      showStatusMessage('Failed to start chat.');
    });
    document.getElementById('messageInput')?.focus();
  };
  document.getElementById('connectButton').onclick = () => {
    const usernameInput = document.getElementById('usernameConnectInput').value.trim();
    const inputCode = document.getElementById('codeInput').value.trim();
    if (!validateUsername(usernameInput)) {
      showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
      document.getElementById('usernameConnectInput')?.focus();
      return;
    }
    if (!validateCode(inputCode)) {
      showStatusMessage('Invalid code format: xxxx-xxxx-xxxx-xxxx.');
      document.getElementById('codeInput')?.focus();
      return;
    }
    username = usernameInput;
    rememberUsername(username);
    const p2pBoxConnect = document.getElementById('p2pOnlyCheckConnect');
    p2pOnly = readP2pOnly();
    code = inputCode;
    codeDisplayElement.textContent = `Using code: ${code}`;
    codeDisplayElement.classList.remove('hidden');
    copyCodeButton?.classList.remove('hidden');
    initialContainer.classList.add('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.remove('hidden');
    messages.classList.add('waiting');
    statusElement.textContent = 'Waiting for connection...';
    sendJoin().catch(err => {
      console.error(err);
      showStatusMessage('Failed to join chat.');
    });
    document.getElementById('messageInput')?.focus();
  };
  document.getElementById('backButton').onclick = () => {
    console.log('Back button clicked from usernameContainer');
    window.pendingJoinCode = null;
    window.pendingStegoEncode = false;
    usernameContainer.classList.add('hidden');
    initialContainer.classList.remove('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton?.classList.add('hidden');
    statusElement.textContent = 'Start a new chat or connect to an existing one';
    messages.classList.remove('waiting');
    document.getElementById('startChatToggleButton')?.focus();
    updateLogoutButtonVisibility();
  };
  document.getElementById('backButtonConnect').onclick = () => {
    console.log('Back button clicked from connectContainer');
    connectContainer.classList.add('hidden');
    initialContainer.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton?.classList.add('hidden');
    statusElement.textContent = 'Start a new chat or connect to an existing one';
    messages.classList.remove('waiting');
    document.getElementById('connectToggleButton')?.focus();
    updateLogoutButtonVisibility();
  };
  document.getElementById('sendButton').onclick = () => {
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value.trim();
    if (message) {
      sendMessage(message);
      updateComposerSend();
    }
  };
  document.getElementById('messageInput').addEventListener('input', updateComposerSend);
  document.getElementById('messageInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      const messageInput = document.getElementById('messageInput');
      const message = messageInput.value.trim();
      if (message) {
        sendMessage(message);
        updateComposerSend();
      }
    }
  });
  document.getElementById('imageButton').onclick = (event) => {
    event.stopPropagation();
    toggleAttachSheet();
  };
  ['imageInput', 'cameraInput', 'fileInput'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.onchange = (event) => {
      const file = event.target.files && event.target.files[0];
      if (!file) return;
      const type = file.type && file.type.startsWith('image/') ? 'image' : 'file';
      sendMedia(file, type);
      event.target.value = '';
    };
  });
  document.querySelectorAll('#attachSheet .attach-tile').forEach(tile => {
    tile.onclick = (event) => {
      event.stopPropagation();
      handleAttachAction(tile.getAttribute('data-action'));
    };
  });
  const voiceSendBtn = document.getElementById('voiceSendButton');
  if (voiceSendBtn) {
    voiceSendBtn.onclick = () => {
      voiceCancelled = false;
      stopVoiceRecording();
    };
  }
  const voiceCancelBtn = document.getElementById('voiceCancelButton');
  if (voiceCancelBtn) {
    voiceCancelBtn.onclick = () => {
      voiceCancelled = true;
      stopVoiceRecording();
    };
  }
  document.getElementById('voiceButton').onclick = () => {
    if (!mediaRecorder || mediaRecorder.state !== 'recording') {
      startVoiceRecording();
    } else {
      stopVoiceRecording();
    }
  };
  document.addEventListener('click', (event) => {
    if (!attachSheetOpen) return;
    const box = document.querySelector('.input-container');
    if (box && !box.contains(event.target)) closeAttachSheet();
  });
  updateComposerSend();
  updateAttachButton();
  document.getElementById('audioOutputButton').onclick = () => {
    toggleAudioOutput();
  };
  document.getElementById('saveGrokKey').onclick = () => {
    saveGrokKey();
  };
  document.getElementById('newSessionButton').onclick = () => {
    burnChatSession();
    window.location.href = 'https://anonomoose.com';
  };
  document.getElementById('usernameInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      document.getElementById('joinWithUsernameButton')?.click();
    }
  });
  document.getElementById('usernameConnectInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      document.getElementById('codeInput')?.focus();
    }
  });
  document.getElementById('codeInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      document.getElementById('connectButton')?.click();
    }
  });
  function currentInviteCode() {
    if (code && validateCode(code)) return code;
    const shown = (codeDisplayElement && codeDisplayElement.textContent) || '';
    const extracted = shown.replace('Your code: ', '').replace('Using code: ', '').trim();
    return validateCode(extracted) ? extracted : '';
  }
  function inviteSmsBody(inviteCode) {
    return 'Join private chat: https://www.anonomoose.com/?code=' + inviteCode;
  }
  function openTextCodeModal() {
    const inviteCode = currentInviteCode();
    if (!inviteCode) {
      showStatusMessage('Start a chat first so there is a code to send.');
      return;
    }
    const preview = document.getElementById('textCodePreview');
    if (preview) preview.value = inviteSmsBody(inviteCode);
    const modal = document.getElementById('textCodeModal');
    modal.classList.remove('hidden');
    modal.classList.add('active');
  }
  function closeTextCodeModal() {
    const modal = document.getElementById('textCodeModal');
    modal.classList.remove('active');
    modal.classList.add('hidden');
  }
  document.getElementById('textCodeButton').onclick = () => openTextCodeModal();
  const roomQrBtn = document.getElementById('roomQrButton');
  if (roomQrBtn) roomQrBtn.onclick = () => {
    if (!code) {
      showStatusMessage('Start a chat first.');
      return;
    }
    const modal = document.getElementById('roomQrModal');
    const box = document.getElementById('roomQrBox');
    const lab = document.getElementById('roomQrCodeLabel');
    if (!modal || !box) return;
    box.innerHTML = '';
    const url = 'https://www.anonomoose.com/?code=' + encodeURIComponent(code);
    if (lab) lab.textContent = code;
    try { new QRCode(box, { text: url, width: 180, height: 180 }); }
    catch (e) { box.textContent = url; }
    modal.classList.remove('hidden');
    modal.classList.add('active');
  };
  const closeRoomQr = document.getElementById('closeRoomQr');
  if (closeRoomQr) closeRoomQr.onclick = () => {
    const modal = document.getElementById('roomQrModal');
    if (!modal) return;
    modal.classList.add('hidden');
    modal.classList.remove('active');
  };
  document.getElementById('textCodeCancelButton').onclick = () => closeTextCodeModal();
  document.getElementById('textCodeCopyButton').onclick = async () => {
    const inviteCode = currentInviteCode();
    if (!inviteCode) {
      showStatusMessage('No code to send.');
      return;
    }
    const text = inviteSmsBody(inviteCode);
    try {
      if (navigator.clipboard) await navigator.clipboard.writeText(text);
      else {
        const preview = document.getElementById('textCodePreview');
        if (preview) {
          preview.select();
          document.execCommand('copy');
        }
      }
      showStatusMessage('Invite copied. Paste it into Messages. Stay on this page.');
      closeTextCodeModal();
    } catch (e) {
      showStatusMessage('Copy failed. Select the text and copy it yourself.');
    }
  };
  document.getElementById('textCodeShareButton').onclick = async () => {
    suppressAutoBurnUntil = Date.now() + 120000;
    const inviteCode = currentInviteCode();
    if (!inviteCode) {
      showStatusMessage('No code to send.');
      return;
    }
    const text = inviteSmsBody(inviteCode);
    if (navigator.share) {
      try {
        await navigator.share({ title: 'Anonomoose', text, url: 'https://www.anonomoose.com/?code=' + inviteCode });
        closeTextCodeModal();
        showStatusMessage('Invite shared. Stay in this tab so they can join.');
        return;
      } catch (e) {
        if (e && e.name === 'AbortError') return;
      }
    }
    try {
      if (navigator.clipboard) await navigator.clipboard.writeText(text);
      showStatusMessage('Share not available. Invite copied — paste it into Messages.');
      closeTextCodeModal();
    } catch (e) {
      showStatusMessage('Select the invite text and copy it.');
    }
  };
  document.getElementById('button1').onclick = () => {
    if (!(isInitiator && socket && socket.readyState === WebSocket.OPEN && code && totalClients < maxClients && token)) {
      showStatusMessage('Start a chat first, then tap Send Code. Stay on this page.');
      document.getElementById('button1')?.focus();
      return;
    }
    if (!window.confirm('This puts your room on the public random board. Anyone can tap the code. Text Code stays private. Post it?')) {
      document.getElementById('button1')?.focus();
      return;
    }
    socket.send(JSON.stringify({ type: 'submit-random', code, clientId, token }));
    suppressAutoBurnUntil = Date.now() + 180000;
    showStatusMessage('Posted to the public board. Stay in this chat — others tap it to join you.');
    codeSentToRandom = true;
    document.getElementById('button1')?.focus();
  };
  document.getElementById('button2').onclick = () => {
    suppressAutoBurnUntil = Date.now() + 180000;
    window.open('https://www.anonomoose.com/random.html', '_blank', 'noopener');
    document.getElementById('button2')?.focus();
  };
  const cornerLogo = document.getElementById('cornerLogo');
  if (cornerLogo) {
    let mooseSingleTimer = null;
    const fullMooseBurn = () => {
      if (mooseSingleTimer) {
        clearTimeout(mooseSingleTimer);
        mooseSingleTimer = null;
      }
      requestRoomWipe();
      playBurnFlash().then(() => {
        burnChatSession();
        if (window.loggedFeatures && window.loggedFeatures.goCoverStory) {
          window.loggedFeatures.goCoverStory();
        }
      });
    };
    const onMoose = (e) => {
      if (e) e.preventDefault();
      if (mooseSingleTimer) {
        fullMooseBurn();
        return;
      }
      mooseSingleTimer = setTimeout(() => {
        mooseSingleTimer = null;
        playBurnFlash().then(() => {
          burnTranscript();
          showStatusMessage('Messages burned here. Tap the moose twice to wipe everyone and leave.');
        });
      }, 500);
    };
    cornerLogo.addEventListener('click', onMoose);
  } else {
    console.error('cornerLogo element not found—check ID in index.html');
  }
  window.addEventListener('pagehide', (event) => {
    if (event.persisted) return;
    if (Date.now() < suppressAutoBurnUntil) return;
    burnTranscript();
    try {
      if (socket && socket.readyState === WebSocket.OPEN && code && token) {
        socket.send(JSON.stringify({ type: 'leave', code, clientId, token }));
      }
    } catch (e) {}
  });
  window.addEventListener('beforeunload', () => {
    burnTranscript();
  });
  window.addEventListener('pageshow', (event) => {
    if (hideLocalTimer) { clearTimeout(hideLocalTimer); hideLocalTimer = null; }
    if (hideRoomTimer) { clearTimeout(hideRoomTimer); hideRoomTimer = null; }
  });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      if (hideLocalTimer) { clearTimeout(hideLocalTimer); hideLocalTimer = null; }
      if (hideRoomTimer) { clearTimeout(hideRoomTimer); hideRoomTimer = null; }
      return;
    }
    if (Date.now() < suppressAutoBurnUntil) return;
    hideLocalTimer = setTimeout(() => {
      if (!document.hidden) return;
      if (Date.now() < suppressAutoBurnUntil) return;
      const chat = document.getElementById('chatContainer');
      if (!chat || chat.classList.contains('hidden')) return;
      burnTranscript();
    }, 4000);
    hideRoomTimer = setTimeout(() => {
      if (!document.hidden) return;
      if (Date.now() < suppressAutoBurnUntil) return;
      const chat = document.getElementById('chatContainer');
      if (!chat || chat.classList.contains('hidden')) return;
      requestRoomWipe();
      setTimeout(() => burnChatSession(), 300);
    }, 20000);
  });
});
async function sendMessage(content) {
  if (!content) {
    return;
  }
  if (grokBotActive && content.startsWith('/grok ')) {
    console.log('Grok command detected');
    const query = content.slice(6).trim();
    if (query) await sendToGrok(query);
  } else if (content === '/ratchet' && isInitiator) {
    console.log('Ratchet command detected');
    await triggerRatchet();
    showStatusMessage('Key ratchet triggered manually.');
  } else {
    console.log('Preparing to send regular message');
    try {
      await prepareAndSendMessage({ content });
      console.log('Message sent successfully');
    } catch (error) {
      console.error('Error sending message:', error);
      showStatusMessage('Failed to send message.');
    }
  }
  const messageInput = document.getElementById('messageInput');
  messageInput.value = '';
  messageInput.style.height = '2.5rem';
  messageInput?.focus();
  if (typeof updateComposerSend === 'function') updateComposerSend();
}
function confirmOfflineMessage(id) {
  if (!id) return;
  if (window.sbAuth && window.sbAuth.isLoggedIn()) {
    window.sbAuth.confirmOffline(id).catch(() => {});
    return;
  }
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: 'confirm-offline-message', messageId: id, clientId, token }));
  }
}

function deliverOfflineMessages(list) {
  if (!list || !list.length) return;
  showStatusMessage('Pending offline messages loaded.');
  for (const msg of list) {
    if (msg.encrypted && msg.iv && msg.ephemeral_public) {
      (async () => {
        try {
          const opened = await openOfflinePayload(msg);
          let parsed;
          try { parsed = JSON.parse(opened); } catch (e) { parsed = null; }
          if (parsed && parsed.type === 'connection-request' && parsed.code) {
            showIncomingInvite(parsed.from || msg.from || 'Someone', parsed.code, msg.id);
            return;
          }
          const fromName = (parsed && parsed.from) || msg.from || 'Someone';
          const displayText = (parsed && parsed.text) || opened;
          const messageDiv = document.createElement('div');
          messageDiv.className = 'message-bubble other';
          messageDiv.textContent = `Offline message from ${fromName}: ${displayText}`;
          if (messages) messages.prepend(messageDiv);
          confirmOfflineMessage(msg.id);
        } catch (error) {
          console.error('Failed to decrypt offline message');
          showStatusMessage('Failed to decrypt an offline message.');
        }
      })();
    } else if (msg.id) {
      confirmOfflineMessage(msg.id);
    }
  }
}

function showUserSearchResult(searchedUsername, message) {
  const searchResult = document.getElementById('searchResult');
  searchResult.innerHTML = '';
  if (typeof isBlocked === 'function' && isBlocked(searchedUsername)) {
    searchResult.textContent = searchedUsername + ' is blocked. Unblock them from your moose book.';
    return;
  }
  const on = message.status === 'online';
  const seen = (typeof lastSeenLabel === 'function') ? lastSeenLabel(message.last_active, message.status) : message.status;
  const line = document.createElement('p');
  line.innerHTML = '<strong>' + searchedUsername + '</strong> · <span class="' + (on ? 'presence-on' : 'presence-off') + '">' + seen + '</span>';
  searchResult.appendChild(line);
  if (typeof saveBookEntry === 'function') {
    saveBookEntry({ name: searchedUsername, public_key: message.public_key, identity_public_key: message.identity_public_key, id: message.id });
  }
  if (message.identity_public_key && typeof rememberSafety === 'function') {
    rememberSafety(searchedUsername, message.identity_public_key).then((s) => {
      if (!s.num) return;
      const p = document.createElement('p');
      p.className = 'safety-num';
      p.textContent = (s.warn ? 'Safety number CHANGED: ' : 'Safety number: ') + s.num;
      if (s.warn) {
        p.style.color = '#dc2626';
        if (typeof setTrustedName === 'function') setTrustedName(searchedUsername, false);
      }
      searchResult.insertBefore(p, searchResult.children[1] || null);
    });
  }
  if (typeof isTrustedName === 'function' && isTrustedName(searchedUsername)) {
    const star = document.createElement('p');
    star.className = 'presence-on';
    star.textContent = 'Trusted moose';
    searchResult.appendChild(star);
  }
  if (message.public_key) {
    userPublicKey = message.public_key;
    if (message.identity_public_key) userPublicKeyIdentity = message.identity_public_key;
    const inviteBtn = document.createElement('button');
    inviteBtn.textContent = 'Send room invite';
    inviteBtn.onclick = async () => {
      if (inviteBtn.disabled) return;
      inviteBtn.disabled = true;
      const prev = inviteBtn.textContent;
      inviteBtn.textContent = 'Sending…';
      try {
        await inviteEncryptedChat(searchedUsername, message.public_key);
        document.getElementById('searchUserModal').classList.remove('active');
        document.getElementById('searchUserModal').classList.add('hidden');
      } finally {
        inviteBtn.disabled = false;
        inviteBtn.textContent = prev;
      }
    };
    searchResult.appendChild(inviteBtn);
    const callBtn = document.createElement('button');
    callBtn.textContent = on ? 'Call now' : 'Call (missed call if offline)';
    callBtn.onclick = async () => {
      if (callBtn.disabled) return;
      callBtn.disabled = true;
      const prev = callBtn.textContent;
      callBtn.textContent = 'Calling…';
      try {
        await inviteEncryptedChat(searchedUsername, message.public_key, { call: true });
        document.getElementById('searchUserModal').classList.remove('active');
        document.getElementById('searchUserModal').classList.add('hidden');
      } finally {
        callBtn.disabled = false;
        callBtn.textContent = prev;
      }
    };
    searchResult.appendChild(callBtn);
    const blockBtn = document.createElement('button');
    blockBtn.textContent = 'Block';
    blockBtn.className = 'block';
    blockBtn.onclick = () => {
      if (typeof blockName === 'function') blockName(searchedUsername);
      searchResult.textContent = searchedUsername + ' blocked.';
    };
    searchResult.appendChild(blockBtn);
    const trustBtn = document.createElement('button');
    trustBtn.textContent = (typeof isTrustedName === 'function' && isTrustedName(searchedUsername)) ? 'Untrust' : 'Trust';
    trustBtn.onclick = () => {
      const on = !(typeof isTrustedName === 'function' && isTrustedName(searchedUsername));
      if (typeof setTrustedName === 'function') setTrustedName(searchedUsername, on);
      if (message.id && typeof trustOnServer === 'function') trustOnServer(message.id, on);
      trustBtn.textContent = on ? 'Untrust' : 'Trust';
    };
    searchResult.appendChild(trustBtn);
    const ttl = document.createElement('select');
    ttl.className = 'border border-gray-300 p-2 w-full mt-2 rounded';
    ttl.innerHTML = '<option value="0">Keep until they open</option><option value="3600000">Burn in 1 hour if unopened</option><option value="86400000">Burn in 24 hours if unopened</option>';
    const photoLab = document.createElement('p');
    photoLab.className = 'text-xs text-gray-500 mt-2 mb-0';
    photoLab.textContent = 'Photo (read once)';
    const photoInput = document.createElement('input');
    photoInput.type = 'file';
    photoInput.accept = 'image/*';
    photoInput.setAttribute('aria-label', 'Photo');
    const voiceLab = document.createElement('p');
    voiceLab.className = 'text-xs text-gray-500 mt-2 mb-0';
    voiceLab.textContent = 'Voice file (or record below)';
    const voiceInput = document.createElement('input');
    voiceInput.type = 'file';
    voiceInput.accept = 'audio/*';
    voiceInput.setAttribute('aria-label', 'Voice');
    let pendingVoice = null;
    const recBtn = document.createElement('button');
    recBtn.textContent = 'Record voice (5s)';
    recBtn.onclick = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const rec = new MediaRecorder(stream);
        const chunks = [];
        rec.ondataavailable = (e) => { if (e.data.size) chunks.push(e.data); };
        rec.onstop = () => {
          stream.getTracks().forEach((t) => t.stop());
          pendingVoice = new Blob(chunks, { type: rec.mimeType || 'audio/webm' });
          recBtn.textContent = 'Voice ready';
        };
        rec.start();
        recBtn.textContent = 'Recording…';
        setTimeout(() => { try { rec.stop(); } catch (e) {} }, 5000);
      } catch (e) { alert('Mic blocked'); }
    };
    const meetAt = document.createElement('input');
    meetAt.type = 'datetime-local';
    meetAt.className = 'border border-gray-300 p-2 w-full mt-2 rounded';
    meetAt.title = 'Hide until this time';
    const meetHint = document.createElement('p');
    meetHint.className = 'text-xs text-gray-500 mt-1';
    meetHint.textContent = 'Optional: hide until this time, then burns 30 min later.';
    const meetAttach = document.createElement('label');
    meetAttach.className = 'text-xs block mt-1';
    meetAttach.innerHTML = '<input type="checkbox" id="meetAttachCode"> Attach this room’s code (must be in a chat)';
    const pokeBtn = document.createElement('button');
    pokeBtn.textContent = 'Poke (no text)';
    pokeBtn.onclick = async () => {
      try {
        await sendOfflineMessage(searchedUsername, '', { poke: true });
        pokeBtn.textContent = 'Poked';
        setTimeout(() => { pokeBtn.textContent = 'Poke (no text)'; }, 1500);
      } catch (e) { alert(e.message); }
    };
    const offlineMsgContainer = document.createElement('div');
    const textarea = document.createElement('textarea');
    textarea.placeholder = 'Sealed note (they open it later)';
    textarea.className = 'border border-gray-300 p-2 w-full mt-2 rounded';
    const sendBtn = document.createElement('button');
    sendBtn.textContent = 'Send note';
    sendBtn.onclick = async () => {
      const msgText = textarea.value.trim();
      if (sendBtn.disabled) return;
      if (!msgText && !(photoInput.files && photoInput.files[0]) && !meetAt.value && !(voiceInput.files && voiceInput.files[0]) && !pendingVoice) return;
      sendBtn.disabled = true;
      sendBtn.textContent = 'Sending…';
      try {
        const ttlMs = Number(ttl.value) || 0;
        const photo = (photoInput.files && photoInput.files[0] && typeof compressPhotoFile === 'function')
          ? await compressPhotoFile(photoInput.files[0])
          : null;
        let voice = null;
        if (pendingVoice && typeof compressVoiceBlob === 'function') voice = await compressVoiceBlob(pendingVoice);
        else if (voiceInput.files && voiceInput.files[0] && typeof compressVoiceBlob === 'function') voice = await compressVoiceBlob(voiceInput.files[0]);
        const meet = meetAt.value ? new Date(meetAt.value).getTime() : 0;
        const attachCode = !!(meetAttach.querySelector('input') && meetAttach.querySelector('input').checked);
        await sendOfflineMessage(searchedUsername, msgText, { ttlMs, photo, voice, unlockAt: meet, meetAt: attachCode ? meet : 0 });
        textarea.value = '';
        sendBtn.textContent = 'Sent';
        setTimeout(() => {
          sendBtn.textContent = 'Send note';
          sendBtn.disabled = false;
        }, 1200);
      } catch (error) {
        console.error('Offline send error:', error);
        showStatusMessage(error.message || 'Failed to send offline message.');
        sendBtn.textContent = 'Send note';
        sendBtn.disabled = false;
      }
    };
    offlineMsgContainer.appendChild(ttl);
    offlineMsgContainer.appendChild(photoLab);
    offlineMsgContainer.appendChild(photoInput);
    offlineMsgContainer.appendChild(voiceLab);
    offlineMsgContainer.appendChild(voiceInput);
    offlineMsgContainer.appendChild(recBtn);
    offlineMsgContainer.appendChild(meetHint);
    offlineMsgContainer.appendChild(meetAt);
    offlineMsgContainer.appendChild(meetAttach);
    offlineMsgContainer.appendChild(textarea);
    offlineMsgContainer.appendChild(sendBtn);
    offlineMsgContainer.appendChild(pokeBtn);
    searchResult.appendChild(offlineMsgContainer);
  } else {
    searchResult.appendChild(document.createTextNode('They have no encryption key on file, so mail cannot be sent.'));
  }
}

const offlineSendLock = new Set();

async function sendOfflineMessage(toUsername, messageText, extra) {
  extra = extra || {};
  if (!toUsername || !(messageText || extra.photo || extra.voice || extra.meetAt || extra.unlockAt || extra.poke)) throw new Error('Missing recipient or message');
  const lockKey = 'note:' + String(toUsername).toLowerCase() + ':' + (extra.poke ? 'poke' : '') + ':' + (messageText || '') + ':' + (extra.meetAt || extra.unlockAt || '') + ':' + (extra.photo ? 'p' : '');
  if (offlineSendLock.has(lockKey)) throw new Error('Already sending that note.');
  offlineSendLock.add(lockKey);
  try {
  if (typeof isBlocked === 'function' && isBlocked(toUsername)) throw new Error('That name is blocked');
  if (!userPublicKey) throw new Error('No public key for recipient');
  await ensurePersistentKeys();
  const messageId = generateMessageId();
  let kind = extra.photo ? 'photo' : (extra.voice ? 'voice' : (extra.poke ? 'poke' : 'note'));
  let payload = { type: extra.poke ? 'poke' : (extra.photo ? 'photo' : (extra.voice ? 'voice' : 'message')), from: username, text: extra.poke ? '' : (messageText || ''), timestamp: Date.now(), identity: identityPubB64 || '' };
  if (extra.photo) payload.photo = extra.photo;
  if (extra.voice) payload.voice = extra.voice;
  if (extra.unlockAt) {
    payload.unlock_at = extra.unlockAt;
    payload.burn_at = extra.unlockAt + 30 * 60 * 1000;
  }
  if (extra.meetAt) {
    if (!code) throw new Error('Start a chat first, then send a timed meet code.');
    kind = 'meet';
    payload.type = 'meet';
    payload.code = code;
    payload.unlock_at = extra.meetAt;
    payload.burn_at = extra.meetAt + 30 * 60 * 1000;
  }
  const plaintext = JSON.stringify(payload);
  const sealed = await sealOfflinePayload(userPublicKey, toUsername, plaintext, messageId);
  sealed.messageId = messageId;
  const expiresAt = extra.ttlMs ? (Date.now() + extra.ttlMs) : (payload.burn_at || extra.meetAt ? extra.meetAt + 30 * 60 * 1000 : null);
  if (window.sbAuth && window.sbAuth.isLoggedIn()) {
    await window.sbAuth.sendOffline(toUsername, sealed, { kind, expiresAt });
    showStatusMessage(extra.poke ? 'Poke sent.' : (kind === 'meet' ? 'Meet code sealed. Hidden until the time you set.' : (payload.unlock_at ? 'Timed note sealed.' : 'Encrypted offline message sent.')));
    return;
  }
  socket.send(JSON.stringify({
    type: 'send-offline-message',
    to_username: toUsername,
    encrypted: sealed.encrypted,
    iv: sealed.iv,
    ephemeral_public: sealed.ephemeral_public,
    messageId,
    clientId,
    token
  }));
  } finally {
    setTimeout(() => offlineSendLock.delete(lockKey), 2500);
  }
}

async function inviteEncryptedChat(toUsername, theirPub, opts) {
  opts = opts || {};
  const isCall = !!opts.call;
  if (!theirPub) {
    showStatusMessage('That user has no encryption key.');
    return;
  }
  const lockKey = (isCall ? 'call:' : 'invite:') + String(toUsername).toLowerCase();
  if (offlineSendLock.has(lockKey)) {
    showStatusMessage(isCall ? 'Call already ringing.' : 'Invite already sending.');
    return;
  }
  offlineSendLock.add(lockKey);
  userPublicKey = theirPub;
  if (!validateUsername(username)) {
    username = prompt('Enter your username (1-16 alphanumeric characters):')?.trim() || 'Guest';
    if (!validateUsername(username)) username = 'Guest';
    rememberUsername(username);
  }
  const alreadyInRoom = !!(code && chatContainer && !chatContainer.classList.contains('hidden'));
  if (!alreadyInRoom) code = generateCode();
  const messageId = generateMessageId();
  const plaintext = JSON.stringify({
    type: isCall ? 'call-invite' : 'connection-request',
    code,
    from: username,
    identity: identityPubB64 || ''
  });
  try {
    await ensurePersistentKeys();
    const sealed = await sealOfflinePayload(theirPub, toUsername, plaintext, messageId);
    sealed.messageId = messageId;
    const ttl = isCall ? 30 * 60 * 1000 : 10 * 60 * 1000;
    if (window.sbAuth && window.sbAuth.isLoggedIn()) {
      await window.sbAuth.sendOffline(toUsername, sealed, { kind: isCall ? 'call' : 'invite', expiresAt: Date.now() + ttl });
    } else {
      socket.send(JSON.stringify({
        type: 'send-offline-message',
        to_username: toUsername,
        encrypted: sealed.encrypted,
        iv: sealed.iv,
        ephemeral_public: sealed.ephemeral_public,
        messageId,
        clientId,
        token
      }));
    }
    if (isCall) window.__outgoingCall = true;
    if (!alreadyInRoom) await sendJoin();
    else if (isCall && typeof startVoiceCall === 'function') startVoiceCall();
    showStatusMessage(isCall
      ? 'Calling… they ring if the app is open, otherwise a missed call in Sealed Notes.'
      : 'Sealed invite sent. They tap Open in their inbox to join.');
  } catch (err) {
    console.error(err);
    showStatusMessage('Failed to send ' + (isCall ? 'call' : 'invite') + ': ' + (err.message || 'unknown error'));
    offlineSendLock.delete(lockKey);
    window.__outgoingCall = false;
  } finally {
    setTimeout(() => offlineSendLock.delete(lockKey), 2500);
  }
}

function stopCallRing() {
  window.__callRinging = false;
  if (window.__callRingTimer) {
    clearTimeout(window.__callRingTimer);
    window.__callRingTimer = null;
  }
  if (window.__callVibTimer) {
    clearTimeout(window.__callVibTimer);
    window.__callVibTimer = null;
  }
  try { navigator.vibrate(0); } catch (e) {}
  const audio = document.getElementById('callRingAudio');
  if (audio) {
    try { audio.pause(); audio.currentTime = 0; } catch (e) {}
  }
  try { if (window.__callNote) window.__callNote.close(); } catch (e) {}
  window.__callNote = null;
}

function mooseRingtoneSrc() {
  if (window.__mooseRingSrc) return window.__mooseRingSrc;
  const sr = 22050;
  const seconds = 2.4;
  const n = sr * seconds;
  const pcm = new Int16Array(n);
  for (let i = 0; i < n; i++) {
    const t = i / sr;
    const burst = (t % 2.4) < 1.15;
    if (!burst) continue;
    const env = Math.min(1, (t % 2.4) * 8) * Math.min(1, (1.15 - (t % 2.4)) * 8);
    const s = (Math.sin(2 * Math.PI * 440 * t) + Math.sin(2 * Math.PI * 480 * t)) * 0.4 * env;
    pcm[i] = Math.max(-32767, Math.min(32767, s * 32767));
  }
  const bytes = pcm.byteLength;
  const buf = new ArrayBuffer(44 + bytes);
  const v = new DataView(buf);
  const w = (o, s) => { for (let i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); };
  w(0, 'RIFF'); v.setUint32(4, 36 + bytes, true); w(8, 'WAVE'); w(12, 'fmt ');
  v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
  v.setUint32(24, sr, true); v.setUint32(28, sr * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true);
  w(36, 'data'); v.setUint32(40, bytes, true);
  new Uint8Array(buf, 44).set(new Uint8Array(pcm.buffer));
  window.__mooseRingSrc = URL.createObjectURL(new Blob([buf], { type: 'audio/wav' }));
  return window.__mooseRingSrc;
}

function unlockCallAudio() {
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!window.__mooseAudioCtx && Ctx) window.__mooseAudioCtx = new Ctx();
    if (window.__mooseAudioCtx && window.__mooseAudioCtx.state === 'suspended') window.__mooseAudioCtx.resume();
  } catch (e) {}
  const a = document.getElementById('callRingAudio');
  if (!a) return;
  if (!a.src) a.src = mooseRingtoneSrc();
  const wasMuted = a.muted;
  a.muted = true;
  const p = a.play();
  if (p && p.then) {
    p.then(() => { a.pause(); a.currentTime = 0; a.muted = wasMuted; }).catch(() => { a.muted = wasMuted; });
  }
}

function startOscRing() {
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    const ctx = window.__mooseAudioCtx || (Ctx ? new Ctx() : null);
    if (!ctx) return;
    window.__mooseAudioCtx = ctx;
    if (ctx.state === 'suspended') ctx.resume();
    const beep = () => {
      if (!window.__callRinging) return;
      [440, 480].forEach((freq) => {
        const o = ctx.createOscillator();
        const g = ctx.createGain();
        o.type = 'sine';
        o.frequency.value = freq;
        g.gain.setValueAtTime(0.0001, ctx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + 0.03);
        g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 1.1);
        o.connect(g);
        g.connect(ctx.destination);
        o.start();
        o.stop(ctx.currentTime + 1.15);
      });
      window.__callRingTimer = setTimeout(beep, 2000);
    };
    beep();
  } catch (e) {}
}

function startCallRing() {
  stopCallRing();
  window.__callRinging = true;
  unlockCallAudio();
  const audio = document.getElementById('callRingAudio');
  let usedAudio = false;
  if (audio) {
    audio.src = mooseRingtoneSrc();
    audio.loop = true;
    audio.volume = 1;
    audio.currentTime = 0;
    const play = audio.play();
    if (play && play.then) {
      play.then(() => { usedAudio = true; }).catch(() => startOscRing());
    } else {
      startOscRing();
    }
    setTimeout(() => { if (window.__callRinging && audio.paused) startOscRing(); }, 400);
  } else {
    startOscRing();
  }
  const buzz = () => {
    if (!window.__callRinging) return;
    try { navigator.vibrate([900, 250, 900, 500]); } catch (e) {}
    window.__callVibTimer = setTimeout(buzz, 2600);
  };
  buzz();
  try {
    if (window.Notification && Notification.permission === 'granted') {
      window.__callNote = new Notification('Incoming call', {
        body: 'Anonomoose',
        tag: 'moose-call',
        requireInteraction: true,
        silent: false,
        vibrate: [400, 200, 400, 200, 400]
      });
    } else if (window.Notification && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  } catch (e) {}
}

function showIncomingInvite(fromUser, inviteCode, dbId, isCall) {
  const modal = document.getElementById('incomingConnectionModal');
  const title = modal && modal.querySelector('h2');
  const label = document.getElementById('incomingMessage');
  const accept = document.getElementById('acceptButton');
  const deny = document.getElementById('denyButton');
  if (title) title.textContent = isCall ? 'Incoming call' : 'Incoming connection';
  if (label) label.textContent = isCall
    ? (fromUser + ' is calling. Answer?')
    : (fromUser + ' wants to connect. Accept?');
  if (accept) accept.textContent = isCall ? 'Answer' : 'Accept';
  if (deny) deny.textContent = isCall ? 'Decline' : 'Deny';
  if (isCall) startCallRing();
  const closeInvite = () => {
    stopCallRing();
    if (!modal) return;
    modal.classList.remove('active');
    modal.classList.add('hidden');
  };
  if (accept) {
    accept.onclick = () => {
      if (dbId) confirmOfflineMessage(dbId);
      if (isCall) window.__answerCall = true;
      autoConnect(inviteCode);
      closeInvite();
    };
  }
  if (deny) {
    deny.onclick = () => {
      if (dbId) confirmOfflineMessage(dbId);
      closeInvite();
    };
  }
  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('active');
  }
}

async function handleIncomingCallRow(row) {
  if (!row || window.__moosePanic) return;
  try {
    const opened = await openOfflinePayload(row);
    let parsed = null;
    try { parsed = JSON.parse(opened); } catch (e) {}
    if (parsed && parsed.type === 'call-invite' && parsed.code) {
      showIncomingInvite(parsed.from || 'Someone', parsed.code, row.id, true);
    }
  } catch (e) {}
}
window.handleIncomingCallRow = handleIncomingCallRow;

function showRecoveryKitModal(kit) {
  const modal = document.getElementById('recoveryKitModal');
  const field = document.getElementById('recoveryKitValue');
  if (!modal || !field) {
    window.prompt('Save this recovery kit. You need it on a new device:', kit);
    return;
  }
  field.value = kit;
  modal.classList.add('active');
  modal.classList.remove('hidden');
}

function submitLegacyLogin() {
  if (username && token) {
    showStatusMessage('You are already logged in. Log out first to switch accounts.');
    return;
  }
  const name = document.getElementById('loginUsernameInput').value.trim();
  const pass = document.getElementById('loginPasswordInput').value;
  if (!validateUsername(name) || pass.length < 8) {
    showStatusMessage('Invalid username or password (min 8 chars).');
    return;
  }
  loadPersistentKeys().then(existing => {
    if (existing) {
      applyPersistentIdentity(existing);
      socket.send(JSON.stringify({
        type: 'login-username',
        username: name,
        password: pass,
        public_key: existing.ecdhPubB64,
        identity_public_key: existing.ecdsaPubB64,
        clientId,
        token
      }));
      return;
    }
    const recoverModal = document.getElementById('recoverKeysModal');
    if (recoverModal) {
      recoverModal.dataset.username = name;
      recoverModal.dataset.password = pass;
      recoverModal.classList.add('active');
      recoverModal.classList.remove('hidden');
      return;
    }
    generateUserKeypair().then(publicKey => {
      showStatusMessage('New device: generated new keys. Old offline messages may be lost.');
      socket.send(JSON.stringify({
        type: 'login-username',
        username: name,
        password: pass,
        public_key: publicKey,
        identity_public_key: identityPubB64,
        clientId,
        token
      }));
    });
  }).catch(error => {
    console.error(error);
    showStatusMessage('Failed to load keys for login.');
  });
}
