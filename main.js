// main.js
let turnUsername = '';
let turnCredential = '';
let localStream = null;
let voiceCallActive = false;
let grokBotActive = false;
let grokApiKey = localStorage.getItem('grokApiKey') || '';
let renegotiating = new Map();
let audioOutputMode = 'earpiece';
let totpEnabled = false;
let totpSecret = '';
let pendingTotpSecret = null;
let mediaRecorder = null;
let voiceChunks = [];
let voiceTimerInterval = null;
let messageCount = 0;
const CHUNK_SIZE = 8192; // Reduced to 8KB for better mobile compatibility
const chunkBuffers = new Map(); // {chunkId: {chunks: [], total: m}}
const negotiationQueues = new Map(); // Queue pending negotiations per peer
let relaySendingChainKey;
let relaySendIndex = 0;
let relayReceiveStates = new Map(); // senderId: {chainKey, receiveIndex}
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
if (getCookie('clientId')) {
  clientId = getCookie('clientId');
} else {
  setCookie('clientId', clientId, 365);
}
username = localStorage.getItem('username')?.trim() || '';
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
let features = { enableService: true, enableImages: true, enableVoice: true, enableVoiceCalls: true, enableGrokBot: true };
let keyPair;
let roomMaster;
let signingKey;
let remoteAudios = new Map();
let refreshingToken = false;
let signalingQueue = new Map();
let connectedClients = new Set();
let clientPublicKeys = new Map();
let initiatorPublic;
let socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
console.log('WebSocket created');
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
    initialContainer.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    codeDisplayElement.classList.add('hidden');
    copyCodeButton.classList.add('hidden');
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
      showStatusMessage('Authentication tokens refreshed.');
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
      console.error('Server error:', message.message, 'Code:', message.code || 'N/A');
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
          setTimeout(() => {
            if (refreshToken && !refreshingToken) {
              refreshingToken = true;
              socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
            }
          }, refreshBackoff);
          refreshBackoff = Math.min(refreshBackoff * 2, 8000);
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
        token = '';
        refreshToken = '';
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
        signingKey = await deriveSigningKey(roomMaster);
        console.log('Generated initial roomMaster and signingKey for initiator.');
        isConnected = true;
        if (pendingTotpSecret) {
          socket.send(JSON.stringify({ type: 'set-totp', secret: pendingTotpSecret.send, code, clientId, token }));
          showTotpSecretModal(pendingTotpSecret.display);
          pendingTotpSecret = null;
        }
        setInterval(triggerRatchet, 5 * 60 * 1000);
        if (useRelay) {
          relaySendingChainKey = await deriveChainKey(roomMaster, 'relay-chain-' + clientId);
          relaySendIndex = 0;
          relayReceiveStates.clear();
          connectedClients.forEach(id => {
            if (id !== clientId) {
              deriveChainKey(roomMaster, 'relay-chain-' + id).then(key => {
                relayReceiveStates.set(id, { chainKey: key, receiveIndex: 0 });
              });
            }
          });
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode';
            privacyStatus.classList.remove('hidden');
          }
          isConnected = true;
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      } else {
        const publicKey = await exportPublicKey(keyPair.publicKey);
        socket.send(JSON.stringify({ type: 'public-key', publicKey, clientId, code, token }));
        if (useRelay) {
          relaySendingChainKey = await deriveChainKey(roomMaster, 'relay-chain-' + clientId);
          relaySendIndex = 0;
          relayReceiveStates.clear();
          connectedClients.forEach(id => {
            if (id !== clientId) {
              deriveChainKey(roomMaster, 'relay-chain-' + id).then(key => {
                relayReceiveStates.set(id, { chainKey: key, receiveIndex: 0 });
              });
            }
          });
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode';
            privacyStatus.classList.remove('hidden');
          }
          isConnected = true;
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      }
      updateMaxClientsUI();
      updateDots();
      turnUsername = message.turnUsername;
      turnCredential = message.turnCredential;
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
      if (useRelay && roomMaster) {
        deriveChainKey(roomMaster, 'relay-chain-' + message.clientId).then(key => {
          relayReceiveStates.set(message.clientId, { chainKey: key, receiveIndex: 0 });
          console.log(`Initialized receive ratchet for sender ${message.clientId}`);
        });
        isConnected = true;
        inputContainer.classList.remove('hidden');
        messages.classList.remove('waiting');
        updateMaxClientsUI();
      }
      if (voiceCallActive) {
        renegotiate(message.clientId);
      }
      return;
    }
    if (message.type === 'client-disconnected') {
      totalClients = message.totalClients;
      console.log(`Client ${message.clientId} disconnected from code: ${code}, total: ${totalClients}`);
      usernames.delete(message.clientId);
      connectedClients.delete(message.clientId);
      clientPublicKeys.delete(message.clientId);
      relayReceiveStates.delete(message.clientId);
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
      saveRelayStates();
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
        const roomMasterBuffer = await decryptBytes(sharedKey, message.encryptedKey, message.iv);
        roomMaster = new Uint8Array(roomMasterBuffer);
        signingKey = await deriveSigningKey(roomMaster);
        console.log('Room master successfully imported.');
        if (useRelay) {
          relaySendingChainKey = await deriveChainKey(roomMaster, 'relay-chain-' + clientId);
          relaySendIndex = 0;
          relayReceiveStates.clear();
          connectedClients.forEach(id => {
            if (id !== clientId) {
              deriveChainKey(roomMaster, 'relay-chain-' + id).then(key => {
                relayReceiveStates.set(id, { chainKey: key, receiveIndex: 0 });
              });
            }
          });
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode';
            privacyStatus.classList.remove('hidden');
          }
          isConnected = true;
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
      try {
        const importedInitiatorPublic = await importPublicKey(initiatorPublic);
        const shared = await deriveSharedKey(keyPair.privateKey, importedInitiatorPublic);
        const newRoomMasterBuffer = await decryptBytes(shared, message.encrypted, message.iv);
        roomMaster = new Uint8Array(newRoomMasterBuffer);
        signingKey = await deriveSigningKey(roomMaster);
        console.log('New room master received and set for PFS.');
        if (useRelay) {
          relaySendingChainKey = await deriveChainKey(roomMaster, 'relay-chain-' + clientId);
          relaySendIndex = 0;
          relayReceiveStates.clear();
          connectedClients.forEach(id => {
            if (id !== clientId) {
              deriveChainKey(roomMaster, 'relay-chain-' + id).then(key => {
                relayReceiveStates.set(id, { chainKey: key, receiveIndex: 0 });
              });
            }
          });
          saveRelayStates();
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
      console.log('Received plain relay message:', message); // Debug
      const payload = {
        messageId: message.messageId,
        username: message.username,
        content: message.content,
        encryptedContent: message.encryptedContent,
        data: message.data,
        encryptedData: message.encryptedData,
        filename: message.filename,
        timestamp: Number(message.timestamp) || Date.now(), // Ensure valid timestamp
        iv: message.iv,
        index: message.index,
        clientId: message.clientId
      };
      if (!payload.username || (!payload.content && !payload.data && !payload.encryptedContent && !payload.encryptedData) || isNaN(payload.timestamp)) {
        console.error('Invalid payload in relay message:', payload);
        showStatusMessage('Invalid message received.');
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
      let contentOrData = payload.content || payload.data;
      if (payload.encryptedContent || payload.encryptedData) {
        const senderId = payload.clientId;
        if (!relayReceiveStates.has(senderId)) {
          console.warn(`No receive state for sender ${senderId}, initializing`);
          relayReceiveStates.set(senderId, { chainKey: await deriveChainKey(roomMaster, 'relay-chain-' + senderId), receiveIndex: 0 });
        }
        const state = relayReceiveStates.get(senderId);
        const skip = payload.index - state.receiveIndex;
        if (skip < 0) {
          console.warn(`Replay message from ${senderId} with index ${payload.index}`);
          return;
        }
        if (skip > 100) {
          console.warn(`Too many skipped messages from ${senderId}, possible DoS`);
          return;
        }
        for (let i = 0; i < skip; i++) {
          await ratchetDeriveMK(state.chainKey); // derive and discard
          state.chainKey = await ratchetAdvance(state.chainKey);
        }
        const mk = await ratchetDeriveMK(state.chainKey);
        contentOrData = await decryptRaw(mk, payload.encryptedContent || payload.encryptedData, payload.iv);
        state.chainKey = await ratchetAdvance(state.chainKey);
        state.receiveIndex = payload.index + 1;
        saveRelayStates();
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
      messages.prepend(messageDiv);
      messages.scrollTop = 0;
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
