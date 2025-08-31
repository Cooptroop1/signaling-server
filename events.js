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
let globalMessageRate = { count: 0, startTime: Date.now() };
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
let clientId = getCookie('clientId') || Math.random().toString(36).substr(2, 9);
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
let initiatorPublic;
let userPrivateKey = localStorage.getItem('userPrivateKey') || null;
let userPublicKey = null;
let socket, statusElement, codeDisplayElement, copyCodeButton, initialContainer, usernameContainer, connectContainer, chatContainer, newSessionButton, maxClientsContainer, inputContainer, messages, cornerLogo, button2, helpText, helpModal, addUserText, addUserModal;
let pendingTotpSecret = null;
let keyVersion = 0;
let turnUsername, turnCredential;
if (typeof window !== 'undefined') {
  socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
  console.log('WebSocket created');
  if (getCookie('clientId')) {
    clientId = getCookie('clientId');
  } else {
    setCookie('clientId', clientId, 365);
  }
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
  addUserText = document.getElementById('addUserText');
  addUserModal = document.getElementById('addUserModal');
  (async () => {
    try {
      keyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-384' },
        false, // Non-extractable
        ['deriveKey', 'deriveBits']
      );
    } catch (error) {
      console.error('Key pair generation failed:', error);
    }
  })();
}

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

function showStatusMessage(message, duration = 5000) {
  if (statusElement) {
    statusElement.textContent = message;
    setTimeout(() => {
      if (statusElement.textContent === message) {
        statusElement.textContent = isConnected ? 'Connected' : 'Start a new chat or connect to an existing one';
      }
    }, duration);
  }
}

function validateUsername(username) {
  return /^[a-zA-Z0-9]{1,16}$/.test(username);
}

function validateCode(code) {
  return /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/.test(code);
}

function startKeepAlive() {
  // Implementation depends on your server
}

function stopKeepAlive() {
  // Implementation depends on your server
}

function initializeMaxClientsUI() {
  // Placeholder for UI initialization
}

function updateMaxClientsUI() {
  // Placeholder for UI update
}

function updateFeaturesUI() {
  // Placeholder for feature UI update
}

function updateRecentCodes(code) {
  // Placeholder for updating recent codes
}

function setupLazyObserver() {
  // Placeholder for lazy loading observer
}

function startPeerConnection(clientId, initiate) {
  // Placeholder for WebRTC peer connection
}

function cleanupPeerConnection(clientId) {
  // Placeholder for cleaning up peer connection
}

function handleOffer(offer, clientId) {
  // Placeholder for handling WebRTC offer
}

function handleAnswer(answer, clientId) {
  // Placeholder for handling WebRTC answer
}

function handleCandidate(candidate, clientId) {
  // Placeholder for handling ICE candidate
}

function sendMessage(message) {
  // Placeholder for sending messages
}

function sendMedia(file, type) {
  // Placeholder for sending media
}

function startVoiceRecording() {
  // Placeholder for voice recording
}

function stopVoiceRecording() {
  // Placeholder for stopping voice recording
}

function toggleVoiceCall() {
  // Placeholder for toggling voice call
}

function toggleAudioOutput() {
  // Placeholder for toggling audio output
}

function toggleGrokBot() {
  // Placeholder for toggling Grok bot
}

function saveGrokKey() {
  // Placeholder for saving Grok key
}

function createImageModal(src, focusId) {
  // Placeholder for image modal
}

function createAudioModal(src, focusId) {
  // Placeholder for audio modal
}

function renegotiate(clientId) {
  // Placeholder for renegotiation
}

function autoConnect(code) {
  // Placeholder for auto-connect
}

function showTotpInputModal(code) {
  // Placeholder for TOTP input modal
}

function joinWithTotp(code, totpCode) {
  // Placeholder for joining with TOTP
}

function startTotpRoom(serverGenerated) {
  // Placeholder for starting TOTP room
}

function showTotpSecretModal(secret) {
  // Placeholder for showing TOTP secret
}

async function deriveSigningKey() {
  // Placeholder for deriving signing key
  return null;
}

async function signMessage(key, data) {
  // Placeholder for signing message
  return '';
}

async function verifyMessage(key, signature, data) {
  // Placeholder for verifying message
  return true;
}

async function deriveMessageKey() {
  // Placeholder for deriving message key
  return null;
}

async function encryptRaw(key, data) {
  // Placeholder for encryption
  return { encrypted: '', iv: '' };
}

async function decryptRaw(key, encrypted, iv) {
  // Placeholder for decryption
  return '';
}

async function exportPublicKey(publicKey) {
  // Placeholder for exporting public key
  return '';
}

async function importPublicKey(publicKey) {
  // Placeholder for importing public key
  return null;
}

async function deriveSharedKey(privateKey, publicKey) {
  // Placeholder for deriving shared key
  return null;
}

function arrayBufferToBase64(buffer) {
  // Placeholder for array buffer to base64
  return '';
}

function base64ToArrayBuffer(base64) {
  // Placeholder for base64 to array buffer
  return new Uint8Array();
}

function sanitizeMessage(message) {
  // Placeholder for sanitizing message
  return message;
}

function sendRelayMessage(type, data) {
  // Placeholder for sending relay message
}

function sendSignalingMessage(type, data) {
  // Placeholder for sending signaling message
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

socket.onopen = () => {
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
    if (initialContainer) initialContainer.classList.remove('hidden');
    if (usernameContainer) usernameContainer.classList.add('hidden');
    if (connectContainer) connectContainer.classList.add('hidden');
    if (chatContainer) chatContainer.classList.add('hidden');
    if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
    if (copyCodeButton) copyCodeButton.classList.add('hidden');
  }
};

socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  showStatusMessage('Connection error, please try again later.');
  connectionTimeouts.forEach((timeout) => clearTimeout(timeout));
};

socket.onclose = () => {
  console.log('WebSocket closed');
  stopKeepAlive();
  if (reconnectAttempts >= maxReconnectAttempts) {
    showStatusMessage('Max reconnect attempts reached. Please refresh the page.', 10000);
    return;
  }
  const delay = Math.min(30000, 5000 * Math.pow(2, reconnectAttempts));
  reconnectAttempts++;
  setTimeout(() => {
    socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
    socket.onopen = socket.onopen;
    socket.onerror = socket.onerror;
    socket.onclose = socket.onclose;
    socket.onmessage = socket.onmessage;
  }, delay);
};

socket.onmessage = async (event) => {
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
      console.log('Received authentication tokens:', { accessToken: token, refreshToken });
      startKeepAlive();
      setTimeout(refreshAccessToken, 5 * 60 * 1000);
      if (pendingCode) {
        autoConnect(pendingCode);
        pendingCode = null;
      }
      processSignalingQueue();
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
        socket.send(JSON.stringify({ type: 'join', ...pendingJoin, token }));
        pendingJoin = null;
      }
      processSignalingQueue();
      refreshingToken = false;
      return;
    }
    if (message.type === 'error') {
      console.log('Server response:', message.message, 'Code:', message.code || 'N/A');
      if (message.message.includes('Username taken')) {
        const claimError = document.getElementById('claimError');
        if (claimError) {
          claimError.textContent = 'Username already taken. Please try another.';
          setTimeout(() => {
            claimError.textContent = '';
          }, 5000);
          document.getElementById('claimUsernameInput').value = '';
          document.getElementById('claimPasswordInput').value = '';
          document.getElementById('claimUsernameInput')?.focus();
        }
        return;
      }
      if (message.message.includes('Invalid login credentials')) {
        const loginError = document.getElementById('loginError');
        if (loginError) {
          loginError.textContent = 'Invalid username or password. Please try again.';
          setTimeout(() => {
            loginError.textContent = '';
          }, 5000);
          document.getElementById('loginUsernameInput').value = '';
          document.getElementById('loginPasswordInput').value = '';
          document.getElementById('loginUsernameInput')?.focus();
        }
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
          clientId = Math.random().toString(36).substr(2, 9);
          setCookie('clientId', clientId, 365);
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
      } else if (
        message.message.includes('Chat is full') ||
        message.message.includes('Username already taken') ||
        message.message.includes('Initiator offline') ||
        message.message.includes('Invalid code format')
      ) {
        console.log(`Join failed: ${message.message}`);
        showStatusMessage(`Failed to join chat: ${message.message}`);
        socket.send(JSON.stringify({ type: 'leave', code, clientId, token }));
        if (initialContainer) initialContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.add('hidden');
        if (connectContainer) connectContainer.classList.add('hidden');
        if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
        if (copyCodeButton) copyCodeButton.classList.add('hidden');
        if (chatContainer) chatContainer.classList.add('hidden');
        if (newSessionButton) newSessionButton.classList.add('hidden');
        if (maxClientsContainer) maxClientsContainer.classList.add('hidden');
        if (inputContainer) inputContainer.classList.add('hidden');
        if (messages) messages.classList.remove('waiting');
        codeSentToRandom = false;
        if (button2) button2.disabled = false;
        token = '';
        refreshToken = '';
      } else if (message.message.includes('Service has been disabled by admin.')) {
        showStatusMessage(message.message);
        if (initialContainer) initialContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.add('hidden');
        if (connectContainer) connectContainer.classList.add('hidden');
        if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
        if (copyCodeButton) copyCodeButton.classList.add('hidden');
        if (chatContainer) chatContainer.classList.add('hidden');
        if (newSessionButton) newSessionButton.classList.add('hidden');
        if (maxClientsContainer) maxClientsContainer.classList.add('hidden');
        if (inputContainer) inputContainer.classList.add('hidden');
        if (messages) messages.classList.remove('waiting');
        socket.close();
      } else {
        showStatusMessage(message.message);
      }
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
      socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
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
          if (inputContainer) inputContainer.classList.remove('hidden');
          if (messages) messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      } else {
        const publicKey = await exportPublicKey(keyPair.publicKey);
        socket.send(JSON.stringify({ type: 'public-key', publicKey, clientId, code, token }));
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
        if (inputContainer) inputContainer.classList.remove('hidden');
        if (messages) messages.classList.remove('waiting');
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
          const remoteAudioContainer = document.getElementById('remoteAudioContainer');
          if (remoteAudioContainer) remoteAudioContainer.classList.add('hidden');
        }
      }
      updateMaxClientsUI();
      updateDots();
      if (totalClients <= 1) {
        if (inputContainer) inputContainer.classList.add('hidden');
        if (messages) messages.classList.add('waiting');
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
        socket.send(JSON.stringify({
          type: 'encrypted-room-key',
          encryptedKey: encrypted,
          iv,
          publicKey: myPublic,
          targetId: message.clientId,
          code,
          clientId,
          token
        }));
        await triggerRatchet();
      } catch (error) {
        console.error('Error handling public-key:', error);
        showStatusMessage('Key exchange failed.');
      }
      return;
    }
    if (message.type === 'encrypted-room-key') {
      try {
        initiatorPublic = message.publicKey;
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
          if (inputContainer) inputContainer.classList.remove('hidden');
          if (messages) messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      } catch (error) {
        console.error('Error handling encrypted-room-key:', error);
        showStatusMessage('Failed to receive encryption key.');
      }
      return;
    }
    if (message.type === 'new-room-key' && message.targetId === clientId) {
      if (message.version <= keyVersion) {
        console.log(`Ignoring outdated key version ${message.version} (current: ${keyVersion})`);
        return;
      }
      try {
        const importedInitiatorPublic = await importPublicKey(initiatorPublic);
        const shared = await deriveSharedKey(keyPair.privateKey, importedInitiatorPublic);
        const decryptedStr = await decryptRaw(shared, message.encrypted, message.iv);
        const payload = JSON.parse(decryptedStr);
        roomMaster = base64ToArrayBuffer(payload.roomMaster);
        signingSalt = base64ToArrayBuffer(payload.signingSalt);
        messageSalt = base64ToArrayBuffer(payload.messageSalt);
        signingKey = await deriveSigningKey();
        keyVersion = message.version;
        console.log(`New room master and salts received and set for PFS (version ${keyVersion}).`);
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
      const payload = {
        messageId: message.messageId,
        username: message.username,
        content: message.content,
        encryptedContent: message.encryptedContent,
        data: message.data,
        encryptedData: message.encryptedData,
        filename: message.filename,
        timestamp: Number(message.timestamp) || Date.now(),
        iv: message.iv,
        signature: message.signature
      };
      if (!payload.username || ((!payload.content && !payload.encryptedContent) && (!payload.data && !payload.encryptedData)) || isNaN(payload.timestamp)) {
        console.error('Invalid payload in relay message:', payload);
        showStatusMessage('Invalid message received.');
        return;
      }
      const senderUsername = payload.username;
      const isSelf = senderUsername === username;
      const messageDiv = document.createElement('div');
      messageDiv.className = `message-bubble ${isSelf ? 'self' : 'other'}`;
      const timeSpan = document.createElement('span');
      timeSpan.className = 'timestamp';
      timeSpan.textContent = new Date(payload.timestamp).toLocaleTimeString();
      messageDiv.appendChild(timeSpan);
      messageDiv.appendChild(document.createTextNode(`${senderUsername}: `));
      let contentOrData = payload.content || payload.data;
      if (payload.encryptedContent || payload.encryptedData) {
        try {
          const messageKey = await deriveMessageKey();
          const encrypted = payload.encryptedContent || payload.encryptedData;
          const iv = payload.iv;
          contentOrData = await decryptRaw(messageKey, encrypted, iv);
          const toVerify = contentOrData + payload.timestamp;
          const valid = await verifyMessage(signingKey, payload.signature, toVerify);
          if (!valid) {
            console.warn(`Invalid signature for relay message`);
            showStatusMessage('Invalid message signature detected.');
            return;
          }
        } catch (error) {
          console.error(`Decryption/verification failed for relay message:`, error);
          showStatusMessage('Failed to decrypt/verify message.');
          return;
        }
      }
      if (message.type === 'image') {
        const img = document.createElement('img');
        img.src = contentOrData;
        img.style.maxWidth = '100%';
        img.style.borderRadius = '0.5rem';
        img.style.cursor = 'pointer';
        img.setAttribute('alt', 'Received image');
        img.addEventListener('click', () => createImageModal(contentOrData, 'messageInput'));
        messageDiv.appendChild(img);
      } else if (message.type === 'voice') {
        const audio = document.createElement('audio');
        audio.src = contentOrData;
        audio.controls = true;
        audio.setAttribute('alt', 'Received voice message');
        audio.addEventListener('click', () => createAudioModal(contentOrData, 'messageInput'));
        messageDiv.appendChild(audio);
      } else if (message.type === 'file') {
        const link = document.createElement('a');
        link.href = contentOrData;
        link.download = payload.filename || 'file';
        link.textContent = `Download ${payload.filename || 'file'}`;
        link.setAttribute('alt', 'Received file');
        messageDiv.appendChild(link);
      } else {
        messageDiv.appendChild(document.createTextNode(sanitizeMessage(contentOrData)));
      }
      if (messages) {
        messages.prepend(messageDiv);
        messages.scrollTop = 0;
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
      if (claimSuccess) {
        claimSuccess.textContent = `Username claimed successfully: ${message.username}`;
        setTimeout(() => {
          claimSuccess.textContent = '';
          const claimUsernameModal = document.getElementById('claimUsernameModal');
          if (claimUsernameModal) claimUsernameModal.classList.remove('active');
          if (initialContainer) initialContainer.classList.remove('hidden');
          if (usernameContainer) usernameContainer.classList.add('hidden');
          if (connectContainer) connectContainer.classList.add('hidden');
          if (chatContainer) chatContainer.classList.add('hidden');
          if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
          if (copyCodeButton) copyCodeButton.classList.add('hidden');
          if (statusElement) statusElement.textContent = 'Start a new chat or connect to an existing one';
        }, 5000);
      }
      return;
    }
    if (message.type === 'login-success') {
      username = message.username;
      localStorage.setItem('username', username);
      const loginSuccess = document.getElementById('loginSuccess');
      if (loginSuccess) {
        loginSuccess.textContent = `Logged in as ${username}`;
      }
      if (message.offlineMessages && message.offlineMessages.length > 0) {
        for (const msg of message.offlineMessages) {
          if (msg.type === 'message' && msg.encrypted && msg.iv && msg.ephemeral_public) {
            (async () => {
              try {
                const privateKey = await window.crypto.subtle.importKey('jwk', JSON.parse(userPrivateKey), { name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveKey', 'deriveBits']);
                const ephemeralPublicImported = await importPublicKey(msg.ephemeral_public);
                const shared = await deriveSharedKey(privateKey, ephemeralPublicImported);
                const decrypted = await decryptRaw(shared, msg.encrypted, msg.iv);
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message-bubble other';
                messageDiv.textContent = `Offline message from ${msg.from}: ${decrypted}`;
                if (messages) messages.prepend(messageDiv);
              } catch (error) {
                console.error('Failed to decrypt offline message:', error);
                showStatusMessage('Failed to decrypt an offline message.');
              }
            })();
          } else if (msg.type === 'connection-request') {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message-bubble other';
            messageDiv.textContent = `Offline request from ${msg.from}: code ${msg.code}`;
            if (messages) messages.prepend(messageDiv);
          }
        }
        showStatusMessage('Pending offline messages loaded.');
      }
      setTimeout(() => {
        if (loginSuccess) loginSuccess.textContent = '';
        const loginModal = document.getElementById('loginModal');
        if (loginModal) loginModal.classList.remove('active');
        if (initialContainer) initialContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.add('hidden');
        if (connectContainer) connectContainer.classList.add('hidden');
        if (chatContainer) chatContainer.classList.add('hidden');
        if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
        if (copyCodeButton) copyCodeButton.classList.add('hidden');
        if (statusElement) statusElement.textContent = 'Start a new chat or connect to an existing one';
      }, 5000);
      return;
    }
    if (message.type === 'user-found') {
      const searchedUsername = document.getElementById('searchUsernameInput')?.value.trim() || '';
      const searchResult = document.getElementById('searchResult');
      if (searchResult) {
        searchResult.innerHTML = `User ${searchedUsername} is ${message.status}. Code: `;
        const codeLink = document.createElement('a');
        codeLink.href = '#';
        codeLink.textContent = message.code;
        codeLink.onclick = (e) => {
          e.preventDefault();
          autoConnect(message.code);
          const searchUserModal = document.getElementById('searchUserModal');
          if (searchUserModal) searchUserModal.classList.remove('active');
        };
        searchResult.appendChild(codeLink);
        if (message.status === 'offline' && message.public_key) {
          userPublicKey = message.public_key;
          const offlineMsgContainer = document.createElement('div');
          const textarea = document.createElement('textarea');
          textarea.placeholder = 'Send offline message...';
          const sendBtn = document.createElement('button');
          sendBtn.textContent = 'Send';
          sendBtn.onclick = () => {
            const msgText = textarea.value.trim();
            if (msgText) {
              sendOfflineMessage(message.username, msgText).then(() => {
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
      }
      return;
    }
    if (message.type === 'incoming-connection') {
      const incomingMessage = document.getElementById('incomingMessage');
      if (incomingMessage) {
        incomingMessage.textContent = `${message.from} wants to connect. Accept?`;
      }
      const acceptButton = document.getElementById('acceptButton');
      if (acceptButton) {
        acceptButton.onclick = () => {
          socket.send(JSON.stringify({ type: 'connection-accepted', code: message.code, clientId, token }));
          autoConnect(message.code);
          const incomingConnectionModal = document.getElementById('incomingConnectionModal');
          if (incomingConnectionModal) incomingConnectionModal.classList.remove('active');
        };
      }
      const denyButton = document.getElementById('denyButton');
      if (denyButton) {
        denyButton.onclick = () => {
          socket.send(JSON.stringify({ type: 'connection-denied', code: message.code, clientId, token }));
          const incomingConnectionModal = document.getElementById('incomingConnectionModal');
          if (incomingConnectionModal) incomingConnectionModal.classList.remove('active');
        };
      }
      const incomingConnectionModal = document.getElementById('incomingConnectionModal');
      if (incomingConnectionModal) incomingConnectionModal.classList.add('active');
      return;
    }
    if (message.type === 'connection-denied') {
      showStatusMessage(`Connection request denied by ${message.from}`);
      return;
    }
    if (message.type === 'user-not-found') {
      const searchError = document.getElementById('searchError');
      if (searchError) {
        searchError.textContent = 'User not found.';
        setTimeout(() => {
          searchError.textContent = '';
        }, 5000);
      }
      return;
    }
    if (message.type === 'offline-message-sent') {
      showStatusMessage('Offline message sent successfully.');
      return;
    }
  } catch (error) {
    console.error('Error parsing message:', error, 'Raw data:', event.data);
    showStatusMessage('Error processing server message.');
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
      const shared = await deriveSharedKey(keyPair.privateKey, importedPublic);
      const payload = {
        roomMaster: arrayBufferToBase64(newRoomMaster),
        signingSalt: arrayBufferToBase64(newSigningSalt),
        messageSalt: arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await encryptRaw(shared, payloadStr);
      socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token, version: keyVersion }));
      success++;
    } catch (error) {
      console.error(`Error sending new room key to ${cId}:`, error);
      failures.push(cId);
    }
  }
  if (success > 0) {
    roomMaster = newRoomMaster;
    signingSalt = newSigningSalt;
    messageSalt = newMessageSalt;
    signingKey = await deriveSigningKey();
    console.log(`PFS ratchet complete (version ${keyVersion}), new roomMaster and salts set.`);
    if (failures.length > 0) {
      console.warn(`Partial ratchet failure for clients: ${failures.join(', ')}. Retrying...`);
      triggerRatchetPartial(failures, newRoomMaster, newSigningSalt, newMessageSalt, keyVersion, 1);
    }
  } else {
    console.warn(`PFS ratchet failed (version ${keyVersion}): No keys available to send to any clients.`);
    keyVersion--;
  }
}

async function triggerRatchetPartial(failures, newRoomMaster, newSigningSalt, newMessageSalt, version, retryCount) {
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
      const shared = await deriveSharedKey(keyPair.privateKey, importedPublic);
      const payload = {
        roomMaster: arrayBufferToBase64(newRoomMaster),
        signingSalt: arrayBufferToBase64(newSigningSalt),
        messageSalt: arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await encryptRaw(shared, payloadStr);
      socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token, version }));
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
    triggerRatchetPartial(newFailures, newRoomMaster, newSigningSalt, newMessageSalt, version, retryCount + 1);
  } else {
    console.log(`All partial ratchet retries complete for version ${version}.`);
  }
}

async function generateUserKeypair() {
  try {
    const keypair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey', 'deriveBits']
    );
    const privateJwk = await window.crypto.subtle.exportKey('jwk', keypair.privateKey);
    const publicBase64 = await exportPublicKey(keypair.publicKey);
    localStorage.setItem('userPrivateKey', JSON.stringify(privateJwk));
    userPrivateKey = privateJwk;
    userPublicKey = publicBase64;
    return publicBase64;
  } catch (error) {
    console.error('Key generation error:', error);
    showStatusMessage('Failed to generate keys.');
    throw error;
  }
}

async function sendOfflineMessage(toUsername, messageText) {
  if (!userPrivateKey) {
    showStatusMessage('No private key. Please re-claim username on this device.');
    return;
  }
  try {
    const ephemeralKeypair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      false,
      ['deriveKey', 'deriveBits']
    );
    const recipientPublic = await importPublicKey(userPublicKey);
    const shared = await deriveSharedKey(ephemeralKeypair.privateKey, recipientPublic);
    const { encrypted, iv } = await encryptRaw(shared, messageText);
    const ephemeralPublic = await exportPublicKey(ephemeralKeypair.publicKey);
    socket.send(JSON.stringify({
      type: 'send-offline-message',
      to_username: toUsername,
      encrypted,
      iv,
      ephemeral_public: ephemeralPublic,
      clientId,
      token
    }));
    showStatusMessage('Offline message sent.');
  } catch (error) {
    console.error('Offline send error:', error);
    showStatusMessage('Failed to send offline message.');
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
  otherClientIds.forEach((targetId) => {
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
  try {
    const toSign = targetId + 'kick' + code;
    const signature = await signMessage(signingKey, toSign);
    const message = { type: 'kick', targetId, code, clientId, token, signature };
    console.log('Sending kick message:', message);
    socket.send(JSON.stringify(message));
    showStatusMessage(`Kicked user ${usernames.get(targetId) || targetId}`);
  } catch (error) {
    console.error('Error kicking user:', error);
    showStatusMessage('Failed to kick user.');
  }
}

async function banUser(targetId) {
  if (!isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for ban:', targetId);
    showStatusMessage('Invalid target user for ban.');
    return;
  }
  console.log('Banning user', targetId);
  try {
    const toSign = targetId + 'ban' + code;
    const signature = await signMessage(signingKey, toSign);
    const message = { type: 'ban', targetId, code, clientId, token, signature };
    console.log('Sending ban message:', message);
    socket.send(JSON.stringify(message));
    showStatusMessage(`Banned user ${usernames.get(targetId) || targetId}`);
  } catch (error) {
    console.error('Error banning user:', error);
    showStatusMessage('Failed to ban user.');
  }
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
  const userDots = document.getElementById('userDots');
  if (userDots) {
    userDots.addEventListener('click', (e) => {
      if (e.target.classList.contains('user-dot')) {
        e.target.classList.toggle('active');
      }
    });
  }
  const toggleRecent = document.getElementById('toggleRecent');
  const recentCodesList = document.getElementById('recentCodesList');
  if (toggleRecent && recentCodesList) {
    toggleRecent.addEventListener('click', () => {
      const isHidden = recentCodesList.classList.toggle('hidden');
      toggleRecent.textContent = isHidden ? 'Show' : 'Hide';
    });
  }
  const loginButton = document.getElementById('loginButton');
  if (loginButton) {
    loginButton.addEventListener('click', () => {
      const loginModal = document.getElementById('loginModal');
      if (loginModal) loginModal.classList.add('active');
    });
  }
  const loginSubmitButton = document.getElementById('loginSubmitButton');
  if (loginSubmitButton) {
    loginSubmitButton.onclick = () => {
      const name = document.getElementById('loginUsernameInput')?.value.trim() || '';
      const pass = document.getElementById('loginPasswordInput')?.value || '';
      if (validateUsername(name) && pass.length >= 8) {
        if (!userPrivateKey) {
          generateUserKeypair().then(() => {
            showStatusMessage('New device detected. Generated new keys (old offline messages may be lost).');
            socket.send(JSON.stringify({ type: 'login-username', username: name, password: pass, clientId, token }));
          }).catch(error => {
            console.error('Key generation error:', error);
            showStatusMessage('Failed to generate keys for login.');
          });
        } else {
          socket.send(JSON.stringify({ type: 'login-username', username: name, password: pass, clientId, token }));
        }
      } else {
        showStatusMessage('Invalid username or password (min 8 chars).');
      }
    };
  }
  const loginCancelButton = document.getElementById('loginCancelButton');
  if (loginCancelButton) {
    loginCancelButton.onclick = () => {
      const loginModal = document.getElementById('loginModal');
      if (loginModal) loginModal.classList.remove('active');
    };
  }
  const searchUserButton = document.getElementById('searchUserButton');
  if (searchUserButton) {
    searchUserButton.addEventListener('click', () => {
      const searchUserModal = document.getElementById('searchUserModal');
      if (searchUserModal) searchUserModal.classList.add('active');
    });
  }
  const searchSubmitButton = document.getElementById('searchSubmitButton');
  if (searchSubmitButton) {
    searchSubmitButton.onclick = () => {
      const name = document.getElementById('searchUsernameInput')?.value.trim() || '';
      if (name) {
        socket.send(JSON.stringify({ type: 'find-user', username: name, clientId, token }));
      }
    };
  }
  const searchCancelButton = document.getElementById('searchCancelButton');
  if (searchCancelButton) {
    searchCancelButton.onclick = () => {
      const searchUserModal = document.getElementById('searchUserModal');
      if (searchUserModal) searchUserModal.classList.remove('active');
    };
  }
  const claimUsernameButton = document.getElementById('claimUsernameButton');
  if (claimUsernameButton) {
    claimUsernameButton.addEventListener('click', () => {
      const claimUsernameModal = document.getElementById('claimUsernameModal');
      if (claimUsernameModal) claimUsernameModal.classList.add('active');
    });
  }
  const claimSubmitButton = document.getElementById('claimSubmitButton');
  if (claimSubmitButton) {
    claimSubmitButton.onclick = () => {
      const name = document.getElementById('claimUsernameInput')?.value.trim() || '';
      const pass = document.getElementById('claimPasswordInput')?.value || '';
      if (validateUsername(name) && pass.length >= 8) {
        generateUserKeypair().then(publicKey => {
          socket.send(JSON.stringify({ type: 'register-username', username: name, password: pass, public_key: publicKey, clientId, token }));
        }).catch(error => {
          console.error('Key generation error:', error);
          showStatusMessage('Failed to generate keys for claim.');
        });
      } else {
        showStatusMessage('Invalid username or password (min 8 chars).');
      }
    };
  }
  const claimCancelButton = document.getElementById('claimCancelButton');
  if (claimCancelButton) {
    claimCancelButton.onclick = () => {
      const claimUsernameModal = document.getElementById('claimUsernameModal');
      if (claimUsernameModal) claimUsernameModal.classList.remove('active');
    };
  }
  if (helpText) {
    helpText.addEventListener('click', () => {
      if (helpModal) {
        helpModal.classList.add('active');
        helpModal.focus();
      }
    });
  }
  if (helpModal) {
    helpModal.addEventListener('click', () => {
      helpModal.classList.remove('active');
      if (helpText) helpText.focus();
    });
    helpModal.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        helpModal.classList.remove('active');
        if (helpText) helpText.focus();
      }
    });
  }
  if (addUserText) {
    addUserText.addEventListener('click', () => {
      if (isInitiator && addUserModal) {
        addUserModal.classList.add('active');
        addUserModal.focus();
      }
    });
  }
  if (addUserModal) {
    addUserModal.addEventListener('click', () => {
      addUserModal.classList.remove('active');
      if (addUserText) addUserText.focus();
    });
    addUserModal.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        addUserModal.classList.remove('active');
        if (addUserText) addUserText.focus();
      }
    });
  }
  const totpTypeRadios = document.querySelectorAll('input[name="totpType"]');
  if (totpTypeRadios) {
    totpTypeRadios.forEach(radio => {
      radio.addEventListener('change', () => {
        const customTotpSecretContainer = document.getElementById('customTotpSecretContainer');
        if (customTotpSecretContainer) {
          customTotpSecretContainer.classList.toggle('hidden', radio.value !== 'custom');
        }
      });
    });
  }
  const createTotpRoomButton = document.getElementById('createTotpRoomButton');
  if (createTotpRoomButton) {
    createTotpRoomButton.onclick = () => {
      const serverGenerated = document.querySelector('input[name="totpType"]:checked')?.value === 'server';
      startTotpRoom(serverGenerated);
    };
  }
  const cancelTotpButton = document.getElementById('cancelTotpButton');
  if (cancelTotpButton) {
    cancelTotpButton.onclick = () => {
      const totpOptionsModal = document.getElementById('totpOptionsModal');
      if (totpOptionsModal) totpOptionsModal.classList.remove('active');
      if (initialContainer) initialContainer.classList.remove('hidden');
    };
  }
  const closeTotpSecretButton = document.getElementById('closeTotpSecretButton');
  if (closeTotpSecretButton) {
    closeTotpSecretButton.onclick = () => {
      const totpSecretModal = document.getElementById('totpSecretModal');
      if (totpSecretModal) totpSecretModal.classList.remove('active');
    };
  }
  const submitTotpCodeButton = document.getElementById('submitTotpCodeButton');
  if (submitTotpCodeButton) {
    submitTotpCodeButton.onclick = () => {
      const totpCode = document.getElementById('totpCodeInput')?.value.trim() || '';
      const codeParam = document.getElementById('totpInputModal')?.dataset.code || '';
      if (totpCode.length !== 6 || isNaN(totpCode)) {
        showStatusMessage('Invalid 2FA code: 6 digits required.');
        return;
      }
      joinWithTotp(codeParam, totpCode);
      const totpInputModal = document.getElementById('totpInputModal');
      if (totpInputModal) totpInputModal.classList.remove('active');
    };
  }
  const cancelTotpInputButton = document.getElementById('cancelTotpInputButton');
  if (cancelTotpInputButton) {
    cancelTotpInputButton.onclick = () => {
      const totpInputModal = document.getElementById('totpInputModal');
      if (totpInputModal) totpInputModal.classList.remove('active');
      if (initialContainer) initialContainer.classList.remove('hidden');
    };
  }
  const startChatToggleButton = document.getElementById('startChatToggleButton');
  if (startChatToggleButton) {
    startChatToggleButton.onclick = () => {
      console.log('Start chat toggle clicked');
      if (initialContainer) initialContainer.classList.add('hidden');
      if (usernameContainer) usernameContainer.classList.remove('hidden');
      if (connectContainer) connectContainer.classList.add('hidden');
      if (chatContainer) chatContainer.classList.add('hidden');
      if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
      if (copyCodeButton) copyCodeButton.classList.add('hidden');
      if (statusElement) statusElement.textContent = 'Enter a username to start a chat';
      const usernameInput = document.getElementById('usernameInput');
      if (usernameInput) {
        usernameInput.value = username || '';
        usernameInput.focus();
      }
    };
  }
  const connectToggleButton = document.getElementById('connectToggleButton');
  if (connectToggleButton) {
    connectToggleButton.onclick = () => {
      console.log('Connect toggle clicked');
      if (initialContainer) initialContainer.classList.add('hidden');
      if (usernameContainer) usernameContainer.classList.add('hidden');
      if (connectContainer) connectContainer.classList.remove('hidden');
      if (chatContainer) chatContainer.classList.add('hidden');
      if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
      if (copyCodeButton) copyCodeButton.classList.add('hidden');
      if (statusElement) statusElement.textContent = 'Enter a username and code to join a chat';
      const usernameConnectInput = document.getElementById('usernameConnectInput');
      if (usernameConnectInput) {
        usernameConnectInput.value = username || '';
        usernameConnectInput.focus();
      }
    };
  }
  const start2FAChatButton = document.getElementById('start2FAChatButton');
  if (start2FAChatButton) {
    start2FAChatButton.onclick = () => {
      const totpOptionsModal = document.getElementById('totpOptionsModal');
      if (totpOptionsModal) {
        totpOptionsModal.classList.add('active');
        const totpUsernameInput = document.getElementById('totpUsernameInput');
        if (totpUsernameInput) {
          totpUsernameInput.value = username || '';
          totpUsernameInput.focus();
        }
        const customTotpSecretContainer = document.getElementById('customTotpSecretContainer');
        if (customTotpSecretContainer) customTotpSecretContainer.classList.add('hidden');
        const serverRadio = document.querySelector('input[name="totpType"][value="server"]');
        if (serverRadio) serverRadio.checked = true;
      }
    };
  }
  const connect2FAChatButton = document.getElementById('connect2FAChatButton');
  if (connect2FAChatButton) {
    connect2FAChatButton.onclick = () => {
      if (initialContainer) initialContainer.classList.add('hidden');
      if (usernameContainer) usernameContainer.classList.add('hidden');
      if (connectContainer) connectContainer.classList.remove('hidden');
      if (chatContainer) chatContainer.classList.add('hidden');
      if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
      if (copyCodeButton) copyCodeButton.classList.add('hidden');
      if (statusElement) statusElement.textContent = 'Enter a username and code to join a 2FA chat';
      const usernameConnectInput = document.getElementById('usernameConnectInput');
      if (usernameConnectInput) {
        usernameConnectInput.value = username || '';
        usernameConnectInput.focus();
      }
      const connectButton = document.getElementById('connectButton');
      if (connectButton) {
        connectButton.onclick = () => {
          const usernameInput = document.getElementById('usernameConnectInput')?.value.trim() || '';
          const inputCode = document.getElementById('codeInput')?.value.trim() || '';
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
      }
    };
  }
  const joinWithUsernameButton = document.getElementById('joinWithUsernameButton');
  if (joinWithUsernameButton) {
    joinWithUsernameButton.onclick = () => {
      const usernameInput = document.getElementById('usernameInput')?.value.trim() || '';
      if (!validateUsername(usernameInput)) {
        showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
        document.getElementById('usernameInput')?.focus();
        return;
      }
      username = usernameInput;
      localStorage.setItem('username', username);
      console.log('Username set in localStorage:', username);
      code = generateCode();
      if (codeDisplayElement) codeDisplayElement.textContent = `Your code: ${code}`;
      if (codeDisplayElement) codeDisplayElement.classList.remove('hidden');
      if (copyCodeButton) copyCodeButton.classList.remove('hidden');
      if (usernameContainer) usernameContainer.classList.add('hidden');
      if (connectContainer) connectContainer.classList.add('hidden');
      if (initialContainer) initialContainer.classList.add('hidden');
      if (chatContainer) chatContainer.classList.remove('hidden');
      if (messages) messages.classList.add('waiting');
      if (statusElement) statusElement.textContent = 'Waiting for connection...';
      if (socket.readyState === WebSocket.OPEN && token) {
        console.log('Sending join message for new chat');
        socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
      } else {
        pendingJoin = { code, clientId, username };
        if (socket.readyState !== WebSocket.OPEN) {
          socket.addEventListener('open', () => {
            console.log('WebSocket opened, sending join for new chat');
            if (token) {
              socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
              pendingJoin = null;
            }
          }, { once: true });
        }
      }
      document.getElementById('messageInput')?.focus();
    };
  }
  const connectButton = document.getElementById('connectButton');
  if (connectButton) {
    connectButton.onclick = () => {
      const usernameInput = document.getElementById('usernameConnectInput')?.value.trim() || '';
      const inputCode = document.getElementById('codeInput')?.value.trim() || '';
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
      if (codeDisplayElement) codeDisplayElement.textContent = `Using code: ${code}`;
      if (codeDisplayElement) codeDisplayElement.classList.remove('hidden');
      if (copyCodeButton) copyCodeButton.classList.remove('hidden');
      if (initialContainer) initialContainer.classList.add('hidden');
      if (usernameContainer) usernameContainer.classList.add('hidden');
      if (connectContainer) connectContainer.classList.add('hidden');
      if (chatContainer) chatContainer.classList.remove('hidden');
      if (messages) messages.classList.add('waiting');
      if (statusElement) statusElement.textContent = 'Waiting for connection...';
      if (socket.readyState === WebSocket.OPEN && token) {
        console.log('Sending join message for existing chat');
        socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
      } else {
        pendingJoin = { code, clientId, username };
        if (socket.readyState !== WebSocket.OPEN) {
          socket.addEventListener('open', () => {
            console.log('WebSocket opened, sending join for existing chat');
            if (token) {
              socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
              pendingJoin = null;
            }
          }, { once: true });
        }
      }
      document.getElementById('messageInput')?.focus();
    };
  }
  const backButton = document.getElementById('backButton');
  if (backButton) {
    backButton.onclick = () => {
      console.log('Back button clicked from usernameContainer');
      if (usernameContainer) usernameContainer.classList.add('hidden');
      if (initialContainer) initialContainer.classList.remove('hidden');
      if (connectContainer) connectContainer.classList.add('hidden');
      if (chatContainer) chatContainer.classList.add('hidden');
      if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
      if (copyCodeButton) copyCodeButton.classList.add('hidden');
      if (statusElement) statusElement.textContent = 'Start a new chat or connect to an existing one';
      if (messages) messages.classList.remove('waiting');
      document.getElementById('startChatToggleButton')?.focus();
    };
  }
  const backButtonConnect = document.getElementById('backButtonConnect');
  if (backButtonConnect) {
    backButtonConnect.onclick = () => {
      console.log('Back button clicked from connectContainer');
      if (connectContainer) connectContainer.classList.add('hidden');
      if (initialContainer) initialContainer.classList.remove('hidden');
      if (usernameContainer) usernameContainer.classList.add('hidden');
      if (chatContainer) chatContainer.classList.add('hidden');
      if (codeDisplayElement) codeDisplayElement.classList.add('hidden');
      if (copyCodeButton) copyCodeButton.classList.add('hidden');
      if (statusElement) statusElement.textContent = 'Start a new chat or connect to an existing one';
      if (messages) messages.classList.remove('waiting');
      document.getElementById('connectToggleButton')?.focus();
    };
  }
  const sendButton = document.getElementById('sendButton');
  if (sendButton) {
    sendButton.onclick = () => {
      const messageInput = document.getElementById('messageInput');
      const message = messageInput?.value.trim() || '';
      if (message) {
        sendMessage(message);
      }
    };
  }
  const messageInput = document.getElementById('messageInput');
  if (messageInput) {
    messageInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        const message = messageInput.value.trim();
        if (message) {
          sendMessage(message);
        }
      }
    });
  }
  const imageButton = document.getElementById('imageButton');
  if (imageButton) {
    imageButton.onclick = () => {
      document.getElementById('imageInput')?.click();
    };
  }
  const imageInput = document.getElementById('imageInput');
  if (imageInput) {
    imageInput.onchange = (event) => {
      const file = event.target.files[0];
      if (file) {
        const type = file.type.startsWith('image/') ? 'image' : 'file';
        sendMedia(file, type);
        event.target.value = '';
      }
    };
  }
  const voiceButton = document.getElementById('voiceButton');
  if (voiceButton) {
    voiceButton.onclick = () => {
      if (!mediaRecorder || mediaRecorder.state !== 'recording') {
        startVoiceRecording();
      } else {
        stopVoiceRecording();
      }
    };
  }
  const voiceCallButton = document.getElementById('voiceCallButton');
  if (voiceCallButton) {
    voiceCallButton.onclick = () => {
      toggleVoiceCall();
    };
  }
  const audioOutputButton = document.getElementById('audioOutputButton');
  if (audioOutputButton) {
    audioOutputButton.onclick = () => {
      toggleAudioOutput();
    };
  }
  const grokButton = document.getElementById('grokButton');
  if (grokButton) {
    grokButton.onclick = () => {
      toggleGrokBot();
    };
  }
  const saveGrokKeyButton = document.getElementById('saveGrokKey');
  if (saveGrokKeyButton) {
    saveGrokKeyButton.onclick = () => {
      saveGrokKey();
    };
  }
  const newSessionButtonLocal = document.getElementById('newSessionButton');
  if (newSessionButtonLocal) {
    newSessionButtonLocal.onclick = () => {
      console.log('New session button clicked');
      window.location.href = 'https://anonomoose.com';
    };
  }
  const usernameInput = document.getElementById('usernameInput');
  if (usernameInput) {
    usernameInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        document.getElementById('joinWithUsernameButton')?.click();
      }
    });
  }
  const usernameConnectInput = document.getElementById('usernameConnectInput');
  if (usernameConnectInput) {
    usernameConnectInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        document.getElementById('codeInput')?.focus();
      }
    });
  }
  const codeInputKeydown = document.getElementById('codeInput');
  if (code
