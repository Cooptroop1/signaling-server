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
    const keys = await ensurePersistentKeys();
    if (keys.recoveryKit) {
      showRecoveryKitModal(keys.recoveryKit);
    }
    applyPersistentIdentity(keys);
    console.log('Generated/loaded persistent user keypair');
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
    const stored = localStorage.getItem('anonClientId');
    if (stored) return stored;
  } catch (e) {}
  return newClientId();
}
let clientId = readInitialClientId();
try { localStorage.setItem('anonClientId', clientId); } catch (e) {}
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
let clientIdentityKeys = new Map();
let identityKeyPair = null;
let identityPubB64 = null;
let initiatorPublic;
let persistentEcdhPrivate = null;
let userPublicKey;
let userPublicKeyIdentity = null;
let lastWsUrl = '';
let pinReconnect = false;
let connectedWaiters = [];
let socket, statusElement, codeDisplayElement, copyCodeButton, initialContainer, usernameContainer, connectContainer, chatContainer, newSessionButton, maxClientsContainer, inputContainer, messages, cornerLogo, button2, helpText, helpModal;
let lazyObserver;
if (typeof window !== 'undefined') {
const serverUrls = [
  'wss://signaling-server-zc6m.onrender.com',
  'wss://signaling-server-1.onrender.com'
];
function serverForCode(roomCode) {
  const s = String(roomCode || '').replace(/-/g, '').toLowerCase();
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return serverUrls[(h >>> 0) % serverUrls.length];
}
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
  const have = socket && socket.url ? socket.url : '';
  if (have.indexOf(want.replace('wss://', '')) !== -1 && socket.readyState === WebSocket.OPEN && token) {
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
  await waitForToken();
  pinReconnect = false;
}
async function initIdentityKeys() {
  if (identityKeyPair && identityPubB64) return;
  const persistent = await loadPersistentKeys();
  if (persistent) {
    applyPersistentIdentity(persistent);
    return;
  }
  identityKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify']
  );
  identityPubB64 = await exportIdentityPublic(identityKeyPair.publicKey);
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
    identityPublic: identityPubB64
  }, extra)));
}
lastWsUrl = serverForCode(code);
socket = new WebSocket(lastWsUrl);
bindSocketHandlers(socket);
console.log(`WebSocket created, connected to ${lastWsUrl}`);
  username = localStorage.getItem('username')?.trim() || '';
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
  (async () => {
    keyPair = await generateSessionKeyPair();
    try { await initIdentityKeys(); } catch (e) { console.error('Identity init failed', e); }
  })();
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
addUserText.addEventListener('click', () => {
  if (isInitiator) {
    addUserModal.classList.add('active');
    addUserModal.focus();
  }
});
addUserModal.addEventListener('click', () => {
  addUserModal.classList.remove('active');
  addUserText.focus();
});
addUserModal.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    addUserModal.classList.remove('active');
    addUserText.focus();
  }
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
}
function logout() {
  if (socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({ type: 'logout', clientId, token }));
  }
  username = '';
  token = '';
  refreshToken = '';
  clientId = newClientId();
  try { localStorage.setItem('anonClientId', clientId); } catch (e) {}
  localStorage.removeItem('username');
  processedMessageIds.clear();
  connectedClients.clear();
  peerConnections.forEach((pc) => pc.close());
  peerConnections.clear();
  dataChannels.forEach((dc) => dc.close());
  dataChannels.clear();
  socket.close();
  initialContainer.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
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
  if (socket.readyState === WebSocket.OPEN && code && token) {
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
  copyCodeButton.classList.add('hidden');
  newSessionButton.classList.add('hidden');
  maxClientsContainer.classList.add('hidden');
  inputContainer.classList.add('hidden');
  messages.classList.remove('waiting');
  messages.innerHTML = '';
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  updateLogoutButtonVisibility();
  showStatusMessage('Chat ended.');
  document.getElementById('startChatToggleButton')?.focus();
}
function handleSocketOpen() {
  console.log('WebSocket opened');
  socket.send(JSON.stringify({ type: 'connect', clientId }));
  reconnectAttempts = 0;
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    console.log('Detected code in URL, setting pendingCode for autoConnect after token');
    pendingCode = codeParam;
  } else {
    console.log('No valid code in URL, showing initial container');
    initialContainer.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton.classList.add('hidden');
  }
  updateLogoutButtonVisibility();
}
function handleSocketError(error) {
  console.error('WebSocket error:', error);
  showStatusMessage('Connection error, please try again later.');
  connectionTimeouts.forEach((timeout) => clearTimeout(timeout));
}
function handleSocketClose() {
  console.log('WebSocket closed');
  stopKeepAlive();
  if (pinReconnect) return;
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
  }, delay);
}
async function handleSocketMessage(event) {
  console.log('Received WebSocket message:', event.data);
  try {
    const message = JSON.parse(event.data);
    console.log('Parsed message:', message);
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
      if (message.clientId) {
        clientId = message.clientId;
        try { localStorage.setItem('anonClientId', clientId); } catch (e) {}
      }
      console.log('Received authentication tokens');
      startKeepAlive();
      setTimeout(refreshAccessToken, 5 * 60 * 1000);
      if (window.notifyConnected) window.notifyConnected();
      if (pendingCode) {
        autoConnect(pendingCode);
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
          try { localStorage.setItem('anonClientId', clientId); } catch (e) {}
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
        copyCodeButton.classList.add('hidden');
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
        copyCodeButton.classList.add('hidden');
        chatContainer.classList.add('hidden');
        newSessionButton.classList.add('hidden');
        maxClientsContainer.classList.add('hidden');
        inputContainer.classList.add('hidden');
        messages.classList.remove('waiting');
        socket.close();
        updateLogoutButtonVisibility();
        return;
      } else if (message.message.includes('Target client not found or offline')) {
        showStatusMessage('The other user is offline or not found.');
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
      maxClients = Math.min(message.maxClients, 10);
      isInitiator = message.isInitiator;
      features = message.features || features;
      if (!features.enableP2P) {
        useRelay = true;
      }
      totalClients = 1;
      console.log(`Initialized client ${clientId}, username: ${username}, maxClients: ${maxClients}, isInitiator: ${isInitiator}, features: ${JSON.stringify(features)}`);
      usernames.set(clientId, username);
      connectedClients.add(clientId);
      if (identityPubB64) clientIdentityKeys.set(clientId, identityPubB64);
      initializeMaxClientsUI();
      updateFeaturesUI();
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
            privacyStatus.textContent = 'Relay Mode (E2EE)';
            privacyStatus.classList.remove('hidden');
          }
          isConnected = true;
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      } else {
        const publicKey = await exportPublicKey(keyPair.publicKey);
        await initIdentityKeys();
        socket.send(JSON.stringify({ type: 'public-key', publicKey, identityPublic: identityPubB64, clientId, code, token }));
      }
      updateMaxClientsUI();
      updateDots();
      turnUsername = message.turnUsername;
      turnCredential = message.turnCredential;
      updateRecentCodes(code);
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
      if (message.identityPublic) {
        clientIdentityKeys.set(message.clientId, message.identityPublic);
      }
      connectedClients.add(message.clientId);
      updateMaxClientsUI();
      updateDots();
      if (isInitiator && message.clientId !== clientId && !peerConnections.has(message.clientId)) {
        console.log(`Initiating peer connection with client ${message.clientId}`);
        startPeerConnection(message.clientId, true);
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
        alert('The chat room is now empty. Returning to start page.');
        endChat();
      }
      if (totalClients <= 1) {
        inputContainer.classList.add('hidden');
        messages.classList.add('waiting');
        endChat();
      }
      return;
    }
    if (message.type === 'max-clients') {
      maxClients = Math.min(message.maxClients, 10);
      console.log(`Max clients updated to ${maxClients} for code: ${code}`);
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
      handleCandidate(message.candidate, message.clientId);
      return;
    }
    if (message.type === 'public-key' && isInitiator) {
      try {
        clientPublicKeys.set(message.clientId, message.publicKey);
        if (message.identityPublic) {
          clientIdentityKeys.set(message.clientId, message.identityPublic);
        }
        const joinerPublic = await importPublicKey(message.publicKey);
        const sharedKey = await deriveSharedKey(keyPair.privateKey, joinerPublic);
        const payload = {
          roomMaster: arrayBufferToBase64(roomMaster),
          signingSalt: arrayBufferToBase64(signingSalt),
          messageSalt: arrayBufferToBase64(messageSalt)
        };
        const payloadStr = JSON.stringify(payload);
        const { encrypted, iv } = await encryptRaw(sharedKey, payloadStr);
        const myPublic = await exportPublicKey(keyPair.publicKey);
        await initIdentityKeys();
        socket.send(JSON.stringify({
          type: 'encrypted-room-key',
          encryptedKey: encrypted,
          iv,
          publicKey: myPublic,
          identityPublic: identityPubB64,
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
        const initiatorPublicImported = await importPublicKey(initiatorPublic);
        const sharedKey = await deriveSharedKey(keyPair.privateKey, initiatorPublicImported);
        const decryptedStr = await decryptRaw(sharedKey, message.encryptedKey, message.iv);
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
            privacyStatus.textContent = 'Relay Mode (E2EE)';
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
        const shared = await deriveSharedKey(keyPair.privateKey, importedInitiatorPublic);
        const decryptedStr = await decryptRaw(shared, message.encrypted, message.iv);
        const payload = JSON.parse(decryptedStr);
        roomMaster = base64ToArrayBuffer(payload.roomMaster);
        signingSalt = base64ToArrayBuffer(payload.signingSalt);
        messageSalt = base64ToArrayBuffer(payload.messageSalt);
        signingKey = await deriveSigningKey();
        keyVersion = message.version;
        if (message.publicKey) {
          initiatorPublic = message.publicKey;
        }
        console.log(`New room master and salts received and set for PFS (version ${keyVersion}).`);
        keyPair = await generateSessionKeyPair();
        const rotatedPub = await exportPublicKey(keyPair.publicKey);
        if (socket.readyState === WebSocket.OPEN && token) {
          socket.send(JSON.stringify({ type: 'public-key', publicKey: rotatedPub, identityPublic: identityPubB64, clientId, code, token }));
        }
      } catch (error) {
        console.error('Error handling new-room-key:', error);
        showStatusMessage('Failed to update encryption key for PFS.');
      }
      return;
    }
    if ((message.type === 'message' || message.type === 'image' || message.type === 'voice' || message.type === 'file') && useRelay) {
      if (processedMessageIds.has(message.messageId)) return;
      processedMessageIds.add(message.messageId);
      console.log('Received relay message:', message);
      const encrypted = message.encryptedContent || message.encryptedData; // Handle conditional
      if (!message.messageId || !message.timestamp || !message.nonce || !message.iv || !message.signature || !encrypted) {
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
        const messageKey = await deriveMessageKey();
        let rawData = await decryptRaw(messageKey, encrypted, message.iv);
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
          console.warn('Relay identity key mismatch');
          showStatusMessage('Message identity mismatch.');
          return;
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
        messageDiv.appendChild(document.createTextNode(`${senderUsername}: `));
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
          const audio = document.createElement('audio');
          audio.dataset.src = contentOrData;
          audio.controls = true;
          audio.setAttribute('alt', 'Received voice message');
          audio.addEventListener('click', () => createAudioModal(contentOrData, 'messageInput'));
          lazyObserver.observe(audio);
          messageDiv.appendChild(audio);
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
        copyCodeButton.classList.add('hidden');
        statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'login-success') {
      username = message.username;
      localStorage.setItem('username', username);
      const loginSuccess = document.getElementById('loginSuccess');
      loginSuccess.textContent = `Logged in as ${username}`;
      if (message.offlineMessages && message.offlineMessages.length > 0) {
        for (const msg of message.offlineMessages) {
          if (msg.type === 'message' && msg.encrypted && msg.iv && msg.ephemeral_public) {
            (async () => {
              try {
                const keys = await loadPersistentKeys();
                if (!keys) throw new Error('No identity keys on this device');
                const ephemeralPublicImported = await importPublicKey(msg.ephemeral_public);
                const shared = await deriveSharedKey(keys.ecdhPrivate, ephemeralPublicImported);
                const decrypted = await decryptRaw(shared, msg.encrypted, msg.iv);
                let displayText = decrypted;
                let fromName = msg.from;
                try {
                  const parsed = JSON.parse(decrypted);
                  if (parsed.inner && parsed.identitySig && parsed.identityPublic) {
                    const ok = await verifyIdentitySignature(parsed.identityPublic, parsed.identitySig, parsed.inner);
                    if (!ok) throw new Error('identity');
                    if (msg.identity_public && msg.identity_public !== parsed.identityPublic) throw new Error('identity mismatch');
                    const inner = JSON.parse(parsed.inner);
                    fromName = inner.from || msg.from;
                    displayText = inner.text || decrypted;
                  }
                } catch (parseErr) {
                  if (String(parseErr.message).indexOf('identity') !== -1) throw parseErr;
                }
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message-bubble other';
                messageDiv.textContent = `Offline message from ${fromName}: ${displayText}`;
                messages.prepend(messageDiv);
              } catch (error) {
                console.error('Failed to decrypt offline message:', error);
                showStatusMessage('Failed to decrypt an offline message.');
              }
            })();
          } else if (msg.type === 'connection-request') {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message-bubble other';
            messageDiv.textContent = `Offline request from ${msg.from}: code ${msg.code}`;
            messages.prepend(messageDiv);
          }
        }
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
        copyCodeButton.classList.add('hidden');
        statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'user-found') {
      const searchedUsername = document.getElementById('searchUsernameInput').value.trim();
      const searchResult = document.getElementById('searchResult');
      searchResult.innerHTML = `User ${searchedUsername} is ${message.status}. Code: `;
      const codeLink = document.createElement('a');
      codeLink.href = '#';
      codeLink.textContent = message.code;
      codeLink.onclick = (e) => {
        e.preventDefault();
        autoConnect(message.code);
        document.getElementById('searchUserModal').classList.remove('active');
      };
      searchResult.appendChild(codeLink);
      if (message.status === 'offline' && message.public_key) {
        userPublicKey = message.public_key;
        if (message.identity_public_key) {
          userPublicKeyIdentity = message.identity_public_key;
        }
        const offlineMsgContainer = document.createElement('div');
        const textarea = document.createElement('textarea');
        textarea.placeholder = 'Send offline message...';
        const sendBtn = document.createElement('button');
        sendBtn.textContent = 'Send';
        sendBtn.onclick = () => {
          const msgText = textarea.value.trim();
          if (msgText) {
            sendOfflineMessage(searchedUsername, msgText).then(() => {
              textarea.value = '';
            }).catch(error => {
              console.error('Offline send error:', error);
              showStatusMessage('Failed to send offline message.');
            });
          }
        };
        offlineMsgContainer.appendChild(textarea);
        offlineMsgContainer.appendChild(sendBtn);
        searchResult.appendChild(offlineMsgContainer);
      }
      return;
    }
    if (message.type === 'incoming-connection') {
      const fromUser = message.from === username ? 'Someone' : message.from;
      document.getElementById('incomingMessage').textContent = `${fromUser} wants to connect. Accept?`;
      document.getElementById('acceptButton').onclick = () => {
        socket.send(JSON.stringify({ type: 'connection-accepted', code: message.code, clientId, token }));
        autoConnect(message.code);
        document.getElementById('incomingConnectionModal').classList.remove('active');
      };
      document.getElementById('denyButton').onclick = () => {
        socket.send(JSON.stringify({ type: 'connection-denied', code: message.code, clientId, token }));
        document.getElementById('incomingConnectionModal').classList.remove('active');
      };
      document.getElementById('incomingConnectionModal').classList.add('active');
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
      showStatusMessage('Offline message sent successfully.');
      return;
    }
  } catch (error) {
    console.error('Error parsing message:', error, 'Raw data:', event.data);
  }
};
function refreshAccessToken() {
  if (socket.readyState === WebSocket.OPEN && refreshToken && !refreshingToken) {
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
      const shared = await deriveSharedKey(newKeyPair.privateKey, importedPublic);
      const payload = {
        roomMaster: arrayBufferToBase64(newRoomMaster),
        signingSalt: arrayBufferToBase64(newSigningSalt),
        messageSalt: arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await encryptRaw(shared, payloadStr);
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
      const shared = await deriveSharedKey(newKeyPair.privateKey, importedPublic);
      const payload = {
        roomMaster: arrayBufferToBase64(newRoomMaster),
        signingSalt: arrayBufferToBase64(newSigningSalt),
        messageSalt: arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await encryptRaw(shared, payloadStr);
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
    if (isInitiator) {
      const menu = document.createElement('div');
      menu.className = 'user-menu';
      const kickButton = document.createElement('button');
      kickButton.textContent = 'Kick';
      kickButton.onclick = () => kickUser(targetId);
      const banButton = document.createElement('button');
      banButton.textContent = 'Ban';
      banButton.onclick = () => banUser(targetId);
      menu.appendChild(kickButton);
      menu.appendChild(banButton);
      dot.appendChild(menu);
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
  showStatusMessage(`Kicked user ${usernames.get(targetId) || targetId}`);
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
  showStatusMessage(`Banned user ${usernames.get(targetId) || targetId}`);
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
  const recentCodes = JSON.parse(localStorage.getItem('recentCodes')) || [];
  const recentCodesList = document.getElementById('recentCodesList');
  recentCodesList.innerHTML = '';
  if (recentCodes.length > 0) {
    document.getElementById('recentChats').classList.remove('hidden');
    recentCodes.forEach(recentCode => {
      const button = document.createElement('button');
      button.textContent = recentCode;
      button.onclick = () => autoConnect(recentCode);
      recentCodesList.appendChild(button);
    });
  } else {
    document.getElementById('recentChats').classList.add('hidden');
  }
}
function updateRecentCodes(code) {
  let recentCodes = JSON.parse(localStorage.getItem('recentCodes')) || [];
  if (recentCodes.includes(code)) {
    recentCodes = recentCodes.filter(c => c !== code);
  }
  recentCodes.unshift(code);
  if (recentCodes.length > 5) {
    recentCodes = recentCodes.slice(0, 5);
  }
  localStorage.setItem('recentCodes', JSON.stringify(recentCodes));
  loadRecentCodes();
}
function setupWaitingForJoin(codeParam) {
  console.log('Setting up waiting state for URL code:', codeParam);
  initialContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for connection...';
  // Prompt for username if not set
  if (!username) {
    username = prompt('Enter your username (1-16 alphanumeric characters):')?.trim() || 'Guest';
    if (!validateUsername(username)) {
      showStatusMessage('Invalid username. Using "Guest".');
      username = 'Guest';
    }
    localStorage.setItem('username', username);
  }
  // Set pendingCode to trigger autoConnect after token
  pendingCode = codeParam;
  document.getElementById('messageInput')?.focus();
}
document.addEventListener('DOMContentLoaded', () => {
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
  const toggleRecent = document.getElementById('toggleRecent');
  const recentCodesList = document.getElementById('recentCodesList');
  toggleRecent.addEventListener('click', () => {
    const isHidden = recentCodesList.classList.toggle('hidden');
    toggleRecent.textContent = isHidden ? 'Show' : 'Hide';
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
  document.getElementById('searchUserButton').addEventListener('click', () => {
    document.getElementById('searchUserModal').classList.add('active');
  });
  document.getElementById('searchSubmitButton').onclick = () => {
    const name = document.getElementById('searchUsernameInput').value.trim();
    if (name) {
      socket.send(JSON.stringify({ type: 'find-user', username: name, from_username: username, clientId, token }));
    }
  };
  document.getElementById('searchCancelButton').onclick = () => {
    document.getElementById('searchUserModal').classList.remove('active');
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
  document.getElementById('startChatToggleButton').onclick = () => {
    console.log('Start chat toggle clicked');
    initialContainer.classList.add('hidden');
    usernameContainer.classList.remove('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton.classList.add('hidden');
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
    copyCodeButton.classList.add('hidden');
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
  document.getElementById('connect2FAChatButton').onclick = () => {
    initialContainer.classList.add('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.remove('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton.classList.add('hidden');
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
      localStorage.setItem('username', username);
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
    localStorage.setItem('username', username);
    console.log('Username set in localStorage:', username);
    code = generateCode();
    codeDisplayElement.textContent = `Your code: ${code}`;
    codeDisplayElement.classList.remove('hidden');
    copyCodeButton.classList.remove('hidden');
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
    localStorage.setItem('username', username);
    console.log('Username set in localStorage:', username);
    code = inputCode;
    codeDisplayElement.textContent = `Using code: ${code}`;
    codeDisplayElement.classList.remove('hidden');
    copyCodeButton.classList.remove('hidden');
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
    usernameContainer.classList.add('hidden');
    initialContainer.classList.remove('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton.classList.add('hidden');
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
    copyCodeButton.classList.add('hidden');
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
    }
  };
  document.getElementById('messageInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      const messageInput = document.getElementById('messageInput');
      const message = messageInput.value.trim();
      if (message) {
        sendMessage(message);
      }
    }
  });
  document.getElementById('imageButton').onclick = () => {
    document.getElementById('imageInput')?.click();
  };
  document.getElementById('imageInput').onchange = (event) => {
    const file = event.target.files[0];
    if (file) {
      const type = file.type.startsWith('image/') ? 'image' : 'file';
      sendMedia(file, type);
      event.target.value = '';
    }
  };
  document.getElementById('voiceButton').onclick = () => {
    if (!mediaRecorder || mediaRecorder.state !== 'recording') {
      startVoiceRecording();
    } else {
      stopVoiceRecording();
    }
  };
  document.getElementById('voiceCallButton').onclick = () => {
    toggleVoiceCall();
  };
  document.getElementById('audioOutputButton').onclick = () => {
    toggleAudioOutput();
  };
  document.getElementById('grokButton').onclick = () => {
    toggleGrokBot();
  };
  document.getElementById('saveGrokKey').onclick = () => {
    saveGrokKey();
  };
  document.getElementById('newSessionButton').onclick = () => {
    console.log('New session button clicked');
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
  document.getElementById('copyCodeButton').onclick = () => {
    const codeText = codeDisplayElement.textContent.replace('Your code: ', '').replace('Using code: ', '');
    navigator.clipboard.writeText(codeText).then(() => {
      copyCodeButton.textContent = 'Copied!';
      setTimeout(() => {
        copyCodeButton.textContent = 'Copy Code';
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy text: ', err);
      showStatusMessage('Failed to copy code.');
    });
    copyCodeButton?.focus();
  };
  document.getElementById('button1').onclick = () => {
    if (isInitiator && socket.readyState === WebSocket.OPEN && code && totalClients < maxClients && token) {
      socket.send(JSON.stringify({ type: 'submit-random', code, clientId, token }));
      showStatusMessage(`Sent code ${code} to random board.`);
      codeSentToRandom = true;
      button2.disabled = true;
    } else {
      showStatusMessage('Cannot send: Not initiator, no code, no token, or room is full.');
    }
    document.getElementById('button1')?.focus();
  };
  document.getElementById('button2').onclick = () => {
    if (!button2.disabled) {
      window.location.href = 'https://anonomoose.com/random.html';
    }
    document.getElementById('button2')?.focus();
  };
  const cornerLogo = document.getElementById('cornerLogo');
  if (cornerLogo) {
    cornerLogo.addEventListener('click', () => {
      document.getElementById('messages').innerHTML = '';
      processedMessageIds.clear();
      showStatusMessage('Chat history cleared locally.');
    });
  } else {
    console.error('cornerLogo element not found—check ID in index.html');
  }
});
async function sendMessage(content) {
  console.log('sendMessage called with content:', content);
  if (!content) {
    console.log('No content, returning');
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
}
async function sendOfflineMessage(toUsername, messageText) {
  if (!toUsername || !messageText) throw new Error('Missing recipient or message');
  if (!userPublicKey) throw new Error('No public key for recipient');
  const keys = await ensurePersistentKeys();
  if (keys.recoveryKit) showRecoveryKitModal(keys.recoveryKit);
  applyPersistentIdentity(keys);
  const recipientPub = await importPublicKey(userPublicKey);
  const eph = await generateSessionKeyPair();
  const shared = await deriveSharedKey(eph.privateKey, recipientPub);
  const inner = JSON.stringify({ from: username, text: messageText, timestamp: Date.now() });
  const identitySig = await signIdentitySignature(keys.ecdsaPrivate, inner);
  const envelope = JSON.stringify({ inner, identitySig, identityPublic: keys.ecdsaPubB64 });
  const { encrypted, iv } = await encryptRaw(shared, envelope);
  const ephemeral_public = await exportPublicKey(eph.publicKey);
  const messageId = generateMessageId();
  socket.send(JSON.stringify({
    type: 'send-offline-message',
    to_username: toUsername,
    encrypted,
    iv,
    ephemeral_public,
    identity_public: keys.ecdsaPubB64,
    messageId,
    clientId,
    token
  }));
}

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
