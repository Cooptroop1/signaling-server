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
let clientId = getCookie('clientId') || Math.random().toString(36).substr(2, 9); // Prefer cookie
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
const messageRateLimits = new Map();
let codeSentToRandom = false;
let useRelay = false;
let token = '';
let refreshToken = '';
let features = { enableService: true, enableImages: true, enableVoice: true, enableVoiceCalls: true, enableAudioToggle: true, enableGrokBot: true, enableP2P: true, enableRelay: true }; // Global features state
let keyPair;
let roomMaster;
let signingKey; // New: Cached signing key for HMAC
let remoteAudios = new Map();
let refreshingToken = false;
let signalingQueue = new Map();
let connectedClients = new Set(); // New: Track connected client IDs for ratchet
let clientPublicKeys = new Map(); // New: Initiator stores public keys of clients
let initiatorPublic; // New: Non-initiators store initiator's public key
// Declare UI variables globally
let socket, statusElement, codeDisplayElement, copyCodeButton, initialContainer, usernameContainer, connectContainer, chatContainer, newSessionButton, maxClientsContainer, inputContainer, messages, cornerLogo, button2, helpText, helpModal;
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
  (async () => {
    keyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveKey', 'deriveBits']
    );
  })();
  let cycleTimeout;
  function triggerCycle() {
    if (cycleTimeout) clearTimeout(cycleTimeout);
    cornerLogo.classList.add('wink');
    cycleTimeout = setTimeout(() => {
      cornerLogo.classList.remove('wink');
    }, 500);
    setTimeout(triggerCycle, 60000);
  }
  setTimeout(triggerCycle, 60000);
}
// Event handlers and listeners
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
const maxReconnectAttempts = 5; // Limit reconnect attempts
let refreshFailures = 0;
let refreshBackoff = 1000; // Initial backoff 1s
socket.onopen = () => {
  console.log('WebSocket opened');
  socket.send(JSON.stringify({ type: 'connect', clientId }));
  reconnectAttempts = 0; // Reset on successful connection
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
  }
};
socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  showStatusMessage('Connection error, please try again later.');
  connectionTimeouts.forEach((timeout) => clearTimeout(timeout));
};
socket.onclose = () => {
  console.log('WebSocket closed');
  showStatusMessage('Lost connection, reconnecting...');
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
      // Start token refresh timer (5 minutes for 10-minute expiry)
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
      refreshToken = message.refreshToken; // Update with new rotated refresh token
      console.log('Received new tokens:', { accessToken: token, refreshToken });
      showStatusMessage('Authentication tokens refreshed.');
      refreshFailures = 0;
      refreshBackoff = 1000;
      // Restart token refresh timer
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
      console.error('Server error:', message.message, 'Code:', message.code || 'N/A');
      if (message.message.includes('Invalid or expired token') || message.message.includes('Missing authentication token')) {
        // Silently handle token refresh without showing message
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
          socket.close(); // Trigger reconnect
        } else {
          // Exponential backoff for retry
          setTimeout(() => {
            if (refreshToken && !refreshingToken) {
              refreshingToken = true;
              socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
            }
          }, refreshBackoff);
          refreshBackoff = Math.min(refreshBackoff * 2, 8000); // Cap at 8s
        }
        showStatusMessage('Session expired. Reconnecting...');
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
        token = ''; // Clear token
        refreshToken = ''; // Clear refresh token
      } else if (message.message.includes('Service has been disabled by admin.')) {
        showStatusMessage(message.message);
        // Reset UI to initial state
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
    if (message.type === 'totp-enabled') {
      totpEnabled = true;
    }
    if (message.type === 'init') {
      clientId = message.clientId;
      maxClients = Math.min(message.maxClients, 10);
      isInitiator = message.isInitiator;
      features = message.features || features;
      totalClients = 1;
      console.log(`Initialized client ${clientId}, username: ${username}, maxClients: ${maxClients}, isInitiator: ${isInitiator}, features: ${JSON.stringify(features)}`);
      usernames.set(clientId, username);
      connectedClients.add(clientId); // Add self
      initializeMaxClientsUI();
      updateFeaturesUI();
      if (isInitiator) {
        roomMaster = window.crypto.getRandomValues(new Uint8Array(32));
        signingKey = await deriveSigningKey(roomMaster);
        if (pendingTotpSecret) {
          socket.send(JSON.stringify({ type: 'set-totp', secret: pendingTotpSecret.send, code, clientId, token }));
          showTotpSecretModal(pendingTotpSecret.display);
          pendingTotpSecret = null;
        }
        // New: Periodic ratchet timer (every 5 minutes)
        setInterval(triggerRatchet, 5 * 60 * 1000);
        // New: Enable UI for initiator in relay mode after key setup
        if (!features.enableP2P && features.enableRelay) {
          useRelay = true;
          isConnected = true;
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode: E2E Encrypted';
            privacyStatus.classList.remove('hidden');
          }
        }
      } else {
        const publicKey = await exportPublicKey(keyPair.publicKey);
        socket.send(JSON.stringify({ type: 'public-key', publicKey, clientId, code, token }));
      }
      updateMaxClientsUI();
      updateDots();
      turnUsername = message.turnUsername;
      turnCredential = message.turnCredential;
    }
    if (message.type === 'initiator-changed') {
      console.log(`Initiator changed to ${message.newInitiator} for code: ${code}`);
      isInitiator = message.newInitiator === clientId;
      initializeMaxClientsUI();
      updateMaxClientsUI();
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
      // New: Enable UI for non-initiator in relay mode after join and key exchange
      if (!features.enableP2P && features.enableRelay && totalClients > 1 && roomMaster) {
        useRelay = true;
        isConnected = true;
        inputContainer.classList.remove('hidden');
        messages.classList.remove('waiting');
        const privacyStatus = document.getElementById('privacyStatus');
        if (privacyStatus) {
          privacyStatus.textContent = 'Relay Mode: E2E Encrypted';
          privacyStatus.classList.remove('hidden');
        }
      }
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
        inputContainer.classList.add('hidden');
        messages.classList.add('waiting');
      }
    }
    if (message.type === 'max-clients') {
      maxClients = Math.min(message.maxClients, 10);
      console.log(`Max clients updated to ${maxClients} for code: ${code}`);
      updateMaxClientsUI();
      updateDots();
    }
    if (message.type === 'offer' && message.clientId !== clientId) {
      console.log(`Received offer from ${message.clientId} for code: ${code}`);
      handleOffer(message.offer, message.clientId);
    }
    if (message.type === 'answer' && message.clientId !== clientId) {
      console.log(`Received answer from ${message.clientId} for code: ${code}`);
      handleAnswer(message.answer, message.clientId);
    }
    if (message.type === 'candidate' && message.clientId !== clientId) {
      console.log(`Received ICE candidate from ${message.clientId} for code: ${code}`);
      handleCandidate(message.candidate, message.clientId);
    }
    if (message.type === 'public-key' && isInitiator) {
      try {
        clientPublicKeys.set(message.clientId, message.publicKey); // Store joiner's public key
        const joinerPublic = await importPublicKey(message.publicKey);
        const sharedKey = await deriveSharedKey(keyPair.privateKey, joinerPublic);
        const { encrypted, iv } = await encryptBytes(sharedKey, roomMaster);
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
        // Trigger PFS ratchet after receiving and storing the public key
        await triggerRatchet();
      } catch (error) {
        console.error('Error handling public-key:', error);
        showStatusMessage('Key exchange failed.');
      }
    }
    if (message.type === 'encrypted-room-key') {
      try {
        initiatorPublic = message.publicKey; // Store initiator's public key
        const initiatorPublicImported = await importPublicKey(initiatorPublic);
        const sharedKey = await deriveSharedKey(keyPair.privateKey, initiatorPublicImported);
        const roomMasterBuffer = await decryptBytes(sharedKey, message.encryptedKey, message.iv);
        roomMaster = new Uint8Array(roomMasterBuffer);
        signingKey = await deriveSigningKey(roomMaster);
        console.log('Room master successfully imported.');
        // New: Enable UI for non-initiator in relay mode after successful key exchange
        if (!features.enableP2P && features.enableRelay && totalClients > 1) {
          useRelay = true;
          isConnected = true;
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode: E2E Encrypted';
            privacyStatus.classList.remove('hidden');
          }
        }
      } catch (error) {
        console.error('Error handling encrypted-room-key:', error);
        showStatusMessage('Failed to receive encryption key.');
      }
    }
    if (message.type === 'new-room-key' && message.targetId === clientId) {
      try {
        const importedInitiatorPublic = await importPublicKey(initiatorPublic);
        const shared = await deriveSharedKey(keyPair.privateKey, importedInitiatorPublic);
        const newRoomMasterBuffer = await decryptBytes(shared, message.encrypted, message.iv);
        roomMaster = new Uint8Array(newRoomMasterBuffer);
        signingKey = await deriveSigningKey(roomMaster);
        console.log('New room master received and set for PFS.');
        // New: Ensure UI is enabled after successful PFS update in relay mode
        if (!features.enableP2P && features.enableRelay && totalClients > 1) {
          useRelay = true;
          isConnected = true;
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode: E2E Encrypted';
            privacyStatus.classList.remove('hidden');
          }
        }
      } catch (error) {
        console.error('PFS update error:', error.message); // New: Log specific error message for debugging
        showStatusMessage('Failed to update encryption key for PFS.');
        // New: Fallback to generate a new key and retry
        roomMaster = window.crypto.getRandomValues(new Uint8Array(32));
        signingKey = await deriveSigningKey(roomMaster);
        console.log('Generated fallback roomMaster due to PFS failure.');
      }
    }
    if ((message.type === 'message' || message.type === 'image' || message.type === 'voice' || message.type === 'file') && useRelay) {
      if (processedMessageIds.has(message.messageId)) return;
      processedMessageIds.add(message.messageId);
      const encrypted = message.type === 'message' ? message.encryptedContent : message.encryptedData;
      const valid = await verifyMessage(signingKey, message.signature, encrypted); // Verify signature before decrypt
      if (!valid) {
        console.error('Tampered message detected');
        showStatusMessage('Tampered message detected. Ignoring.');
        return;
      }
      let payload;
      try {
        const jsonString = await decrypt(encrypted, message.iv, message.salt, roomMaster);
        payload = JSON.parse(jsonString);
      } catch (error) {
        console.error('Decryption failed:', error);
        showStatusMessage('Failed to decrypt message.');
        return;
      }
      const senderUsername = payload.username;
      const messages = document.getElementById('messages');
      const isSelf = senderUsername === username;
      const messageDiv = document.createElement('div');
      messageDiv.className = `message-bubble ${isSelf ? 'self' : 'other'}`;
      const timeSpan = document.createElement('span');
      timeSpan.className = 'timestamp';
      timeSpan.textContent = new Date(payload.timestamp).toLocaleTimeString();
      messageDiv.appendChild(timeSpan);
      messageDiv.appendChild(document.createTextNode(`${senderUsername}: `));
      if (payload.type === 'image') {
        const img = document.createElement('img');
        img.src = payload.data;
        img.style.maxWidth = '100%';
        img.style.borderRadius = '0.5rem';
        img.style.cursor = 'pointer';
        img.setAttribute('alt', 'Received image');
        img.addEventListener('click', () => createImageModal(payload.data, 'messageInput'));
        messageDiv.appendChild(img);
      } else if (payload.type === 'voice') {
        const audio = document.createElement('audio');
        audio.src = payload.data;
        audio.controls = true;
        audio.setAttribute('alt', 'Received voice message');
        audio.addEventListener('click', () => createAudioModal(payload.data, 'messageInput'));
        messageDiv.appendChild(audio);
      } else if (payload.type === 'file') {
        const link = document.createElement('a');
        link.href = payload.data;
        link.download = payload.filename || 'file';
        link.textContent = `Download ${payload.filename || 'file'}`;
        link.setAttribute('alt', 'Received file');
        messageDiv.appendChild(link);
      } else {
        messageDiv.appendChild(document.createTextNode(sanitizeMessage(payload.content)));
      }
      messages.prepend(messageDiv);
      messages.scrollTop = 0;
    }
    if (message.type === 'features-update') {
      features = message;
      console.log('Received features update:', features);
      setTimeout(updateFeaturesUI, 0);
      if (!features.enableService) {
        showStatusMessage(`Service disabled by admin. Disconnecting...`);
        socket.close();
      }
    }
  } catch (error) {
    console.error('Error parsing message:', error, 'Raw data:', event.data);
  }
};

// New: Function to refresh access token proactively
function refreshAccessToken() {
  if (socket.readyState === WebSocket.OPEN && refreshToken && !refreshingToken) {
    refreshingToken = true;
    console.log('Proactively refreshing access token');
    socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
  } else {
    console.log('Cannot refresh token: WebSocket not open, no refresh token, or refresh in progress');
  }
}

// New: Function to trigger PFS key rotation (called by initiator on new join)
async function triggerRatchet() {
  if (!isInitiator) return;
  const newRoomMaster = window.crypto.getRandomValues(new Uint8Array(32));
  let success = 0;
  for (const cId of connectedClients) {
    if (cId === clientId) continue;
    const publicKey = clientPublicKeys.get(cId);
    if (!publicKey) {
      console.warn(`No public key for client ${cId}, skipping ratchet send`);
      continue;
    }
    try {
      const importedPublic = await importPublicKey(publicKey);
      const shared = await deriveSharedKey(keyPair.privateKey, importedPublic);
      const { encrypted, iv } = await encryptBytes(shared, newRoomMaster);
      socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token }));
      success++;
    } catch (error) {
      console.error(`Error sending new room key to ${cId}:`, error);
    }
  }
  if (success > 0) {
    roomMaster = newRoomMaster;
    signingKey = await deriveSigningKey(roomMaster);
    console.log('PFS ratchet complete, new roomMaster set.');
  } else {
    console.warn('PFS ratchet failed: No keys available to send to any clients.');
  }
}
document.getElementById('startChatToggleButton').onclick = () => {
  console.log('Start chat toggle clicked');
  initialContainer.classList.add('hidden');
  usernameContainer.classList.remove('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  inputContainer.classList.add('hidden');
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
  inputContainer.classList.add('hidden');
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
  inputContainer.classList.add('hidden');
  statusElement.textContent = 'Enter a username and code to join a 2FA chat';
  document.getElementById('usernameConnectInput').value = username || '';
  document.getElementById('usernameConnectInput')?.focus();
  // Override connectButton for 2FA prompt
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
  code = generateCode();
  codeDisplayElement.textContent = `Your code: ${code}`;
  codeDisplayElement.classList.remove('hidden');
  copyCodeButton.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  initialContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  messages.classList.add('waiting');
  inputContainer.classList.add('hidden');
  statusElement.textContent = 'Waiting for connection...';
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
document.getElementById('connectButton').onclick = () => {
  const usernameInput = document.getElementById('usernameConnectInput').value.trim();
  const inputCode = document.getElementById('codeInput').value.trim();
  if (!validateUsername(usernameInput)) {
    showStatusMessage('Invalid username: 1-16 alphanumeric chars.');
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
  codeDisplayElement.textContent = `Using code: ${code}`;
  codeDisplayElement.classList.remove('hidden');
  copyCodeButton.classList.remove('hidden');
  initialContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  messages.classList.add('waiting');
  inputContainer.classList.add('hidden');
  statusElement.textContent = 'Waiting for connection...';
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
document.getElementById('backButton').onclick = () => {
  console.log('Back button clicked from usernameContainer');
  usernameContainer.classList.add('hidden');
  initialContainer.classList.remove('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  inputContainer.classList.add('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  messages.classList.remove('waiting');
  document.getElementById('startChatToggleButton')?.focus();
};
document.getElementById('backButtonConnect').onclick = () => {
  console.log('Back button clicked from connectContainer');
  connectContainer.classList.add('hidden');
  initialContainer.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  inputContainer.classList.add('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  messages.classList.remove('waiting');
  document.getElementById('connectToggleButton')?.focus();
};
document.getElementById('sendButton').onclick = () => {
  const messageInput = document.getElementById('messageInput');
  const message = messageInput.value.trim();
  if (message) {
    sendMessage(message);
  }
};
// Add Enter key listener for sending messages
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
  // Redirect to the domain root to refresh and start fresh
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
cornerLogo.addEventListener('click', () => {
  document.getElementById('messages').innerHTML = '';
  processedMessageIds.clear();
  showStatusMessage('Chat history cleared locally.');
});

// Function to update user dots
function updateDots() {
  const userDots = document.getElementById('userDots');
  if (!userDots) return;
  userDots.innerHTML = '';
  const greenCount = Math.min(totalClients, maxClients);
  const redCount = maxClients - greenCount;
  for (let i = 0; i < greenCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'user-dot online';
    userDots.appendChild(dot);
  }
  for (let i = 0; i < redCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'user-dot offline';
    userDots.appendChild(dot);
  }
}

// Cookie helpers
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
document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    setupWaitingForJoin(codeParam);
  }
});
function setupWaitingForJoin(codeParam) {
  code = codeParam;
  initialContainer.style.display = 'none';
  connectContainer.style.display = 'none';
  usernameContainer.style.display = 'none';
  chatContainer.style.display = 'flex';
  codeDisplayElement.style.display = 'none';
  copyCodeButton.style.display = 'none';
  inputContainer.style.display = 'none';
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for connection...';
  if (!username || !validateUsername(username)) {
    usernameContainer.style.display = 'block';
    chatContainer.style.display = 'none';
    statusElement.textContent = 'Please enter a username to join the chat';
    document.getElementById('usernameInput').value = username || '';
    document.getElementById('usernameInput')?.focus();
    const joinButton = document.getElementById('joinWithUsernameButton');
    const originalOnclick = joinButton.onclick;
    joinButton.onclick = () => {
      const usernameInput = document.getElementById('usernameInput').value.trim();
      if (!validateUsername(usernameInput)) {
        showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
        document.getElementById('usernameInput')?.focus();
        return;
      }
      username = usernameInput;
      localStorage.setItem('username', username);
      usernameContainer.style.display = 'none';
      chatContainer.style.display = 'flex';
      codeDisplayElement.textContent = `Using code: ${code}`;
      codeDisplayElement.style.display = 'block';
      copyCodeButton.style.display = 'block';
      inputContainer.style.display = 'none';
      messages.classList.add('waiting');
      statusElement.textContent = 'Waiting for connection...';
      if (socket.readyState === WebSocket.OPEN && token) {
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
      // Restore original onclick if needed
      joinButton.onclick = originalOnclick;
    };
  } else {
    codeDisplayElement.textContent = `Using code: ${code}`;
    codeDisplayElement.style.display = 'block';
    copyCodeButton.style.display = 'block';
    inputContainer.style.display = 'none';
    if (socket.readyState === WebSocket.OPEN && token) {
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
  }
}
