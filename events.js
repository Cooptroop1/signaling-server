import { UI } from './init.js';
import { getCookie, setCookie, processSignalingQueue } from './utils.js';

function showTotpInputModal(code) {
  UI.totpInputModal.classList.add('active');
  UI.totpInputModal.dataset.code = code;
  UI.totpCodeInput.value = '';
  UI.totpCodeInput?.focus();
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
let pendingCode = null;
let pendingJoin = null;
const maxReconnectAttempts = 5;
let refreshFailures = 0;
let refreshBackoff = 1000;
function updateLogoutButtonVisibility() {
  UI.logoutButton.classList.toggle('hidden', !(username && token));
}
function logout() {
  if (UI.socket.readyState === WebSocket.OPEN && token) {
    UI.socket.send(JSON.stringify({ type: 'logout', clientId, token }));
  }
  username = '';
  token = '';
  refreshToken = '';
  clientId = Math.random().toString(36).substr(2, 9);
  setCookie('clientId', clientId, 365);
  localStorage.removeItem('username');
  localStorage.removeItem('userPrivateKey');
  userPrivateKey = null;
  userPublicKey = null;
  processedMessageIds.clear();
  connectedClients.clear();
  peerConnections.forEach((pc) => pc.close());
  peerConnections.clear();
  dataChannels.forEach((dc) => dc.close());
  dataChannels.clear();
  UI.socket.close();
  UI.initialContainer.classList.remove('hidden');
  UI.usernameContainer.classList.add('hidden');
  UI.connectContainer.classList.add('hidden');
  UI.chatContainer.classList.add('hidden');
  UI.codeDisplayElement.classList.add('hidden');
  UI.copyCodeButton.classList.add('hidden');
  UI.newSessionButton.classList.add('hidden');
  UI.maxClientsContainer.classList.add('hidden');
  UI.inputContainer.classList.add('hidden');
  UI.messages.classList.remove('waiting');
  UI.messages.innerHTML = '';
  UI.statusElement.textContent = 'Start a new chat or connect to an existing one';
  updateLogoutButtonVisibility();
  showStatusMessage('Logged out successfully.');
  UI.startChatToggleButton?.focus();
}
UI.socket.onopen = () => {
  console.log('WebSocket opened');
  UI.socket.send(JSON.stringify({ type: 'connect', clientId }));
  reconnectAttempts = 0;
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    console.log('Detected code in URL, setting pendingCode for autoConnect after token');
    pendingCode = codeParam;
  } else {
    console.log('No valid code in URL, showing initial container');
    UI.initialContainer.classList.remove('hidden');
    UI.usernameContainer.classList.add('hidden');
    UI.connectContainer.classList.add('hidden');
    UI.chatContainer.classList.add('hidden');
    UI.codeDisplayElement.classList.add('hidden');
    UI.copyCodeButton.classList.add('hidden');
  }
  updateLogoutButtonVisibility();
};
UI.socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  showStatusMessage('Connection error, please try again later.');
  connectionTimeouts.forEach((timeout) => clearTimeout(timeout));
};
UI.socket.onclose = () => {
  console.log('WebSocket closed');
  stopKeepAlive();
  if (reconnectAttempts >= maxReconnectAttempts) {
    showStatusMessage('Max reconnect attempts reached. Please refresh the page.', 10000);
    return;
  }
  const delay = Math.min(30000, 5000 * Math.pow(2, reconnectAttempts));
  reconnectAttempts++;
  setTimeout(() => {
    UI.socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
    UI.socket.onopen = UI.socket.onopen;
    UI.socket.onerror = UI.socket.onerror;
    UI.socket.onclose = UI.socket.onclose;
    UI.socket.onmessage = UI.socket.onmessage;
  }, delay);
};
UI.socket.onmessage = async (event) => {
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
      UI.socket.send(JSON.stringify({ type: 'pong' }));
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
        UI.socket.send(JSON.stringify({ type: 'join', ...pendingJoin, token }));
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
        UI.claimError.textContent = 'Username already taken. Please try another.';
        setTimeout(() => {
          UI.claimError.textContent = '';
        }, 5000);
        UI.claimUsernameInput.value = '';
        UI.claimPasswordInput.value = '';
        UI.claimUsernameInput?.focus();
        return;
      }
      if (message.message.includes('Invalid login credentials')) {
        UI.loginError.textContent = 'Invalid username or password. Please try again.';
        setTimeout(() => {
          UI.loginError.textContent = '';
        }, 5000);
        UI.loginUsernameInput.value = '';
        UI.loginPasswordInput.value = '';
        UI.loginUsernameInput?.focus();
        return;
      }
      if (message.message.includes('User already logged in')) {
        UI.loginError.textContent = 'User is already logged in. Please log out from other sessions first.';
        setTimeout(() => {
          UI.loginError.textContent = '';
        }, 5000);
        UI.loginUsernameInput.value = '';
        UI.loginPasswordInput.value = '';
        UI.loginUsernameInput?.focus();
        return;
      }
      if (message.message.includes('Invalid or expired token') || message.message.includes('Missing authentication token')) {
        if (refreshToken && !refreshingToken) {
          refreshingToken = true;
          console.log('Attempting to refresh token');
          UI.socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
        } else {
          console.error('No refresh token available or refresh in progress, forcing reconnect');
          UI.socket.close();
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
          UI.socket.close();
        } else {
          const jitter = Math.random() * 4000 + 1000;
          const delay = Math.min(refreshBackoff + jitter, 8000);
          setTimeout(() => {
            if (refreshToken && !refreshingToken) {
              refreshingToken = true;
              UI.socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
            }
          }, delay);
          refreshBackoff = Math.min(refreshBackoff * 2, 8000);
        }
      } else if (message.message.includes('Rate limit exceeded')) {
        showStatusMessage('Rate limit exceeded. Waiting before retrying...');
        setTimeout(() => {
          if (reconnectAttempts < maxReconnectAttempts) {
            UI.socket.send(JSON.stringify({ type: 'connect', clientId }));
          }
        }, 60000);
      } else if (message.message.includes('Chat is full') ||
        message.message.includes('Username already taken') ||
        message.message.includes('Initiator offline') ||
        message.message.includes('Invalid code format')) {
        console.log(`Join failed: ${message.message}`);
        showStatusMessage(`Failed to join chat: ${message.message}`);
        UI.socket.send(JSON.stringify({ type: 'leave', code, clientId, token }));
        UI.initialContainer.classList.remove('hidden');
        UI.usernameContainer.classList.add('hidden');
        UI.connectContainer.classList.add('hidden');
        UI.codeDisplayElement.classList.add('hidden');
        UI.copyCodeButton.classList.add('hidden');
        UI.chatContainer.classList.add('hidden');
        UI.newSessionButton.classList.add('hidden');
        UI.maxClientsContainer.classList.add('hidden');
        UI.inputContainer.classList.add('hidden');
        UI.messages.classList.remove('waiting');
        codeSentToRandom = false;
        UI.button2.disabled = false;
        token = '';
        refreshToken = '';
        updateLogoutButtonVisibility();
        return;
      } else if (message.message.includes('Service has been disabled by admin.')) {
        showStatusMessage(message.message);
        UI.initialContainer.classList.remove('hidden');
        UI.usernameContainer.classList.add('hidden');
        UI.connectContainer.classList.add('hidden');
        UI.codeDisplayElement.classList.add('hidden');
        UI.copyCodeButton.classList.add('hidden');
        UI.chatContainer.classList.add('hidden');
        UI.newSessionButton.classList.add('hidden');
        UI.maxClientsContainer.classList.add('hidden');
        UI.inputContainer.classList.add('hidden');
        UI.messages.classList.remove('waiting');
        UI.socket.close();
        updateLogoutButtonVisibility();
        return;
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
      UI.socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
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
          UI.socket.send(JSON.stringify({ type: 'set-totp', secret: pendingTotpSecret.send, code, clientId, token }));
          showTotpSecretModal(pendingTotpSecret.display);
          pendingTotpSecret = null;
        }
        setInterval(triggerRatchet, 5 * 60 * 1000);
        if (useRelay) {
          UI.privacyStatus.textContent = 'Relay Mode (E2EE)';
          UI.privacyStatus.classList.remove('hidden');
          isConnected = true;
          UI.inputContainer.classList.remove('hidden');
          UI.messages.classList.remove('waiting');
          updateMaxClientsUI();
        }
      } else {
        const publicKey = await exportPublicKey(keyPair.publicKey);
        UI.socket.send(JSON.stringify({ type: 'public-key', publicKey, clientId, code, token }));
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
        UI.inputContainer.classList.remove('hidden');
        UI.messages.classList.remove('waiting');
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
          UI.remoteAudioContainer.classList.add('hidden');
        }
      }
      updateMaxClientsUI();
      updateDots();
      if (totalClients <= 1) {
        UI.inputContainer.classList.add('hidden');
        UI.messages.classList.add('waiting');
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
        UI.socket.send(JSON.stringify({
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
          UI.privacyStatus.textContent = 'Relay Mode (E2EE)';
          UI.privacyStatus.classList.remove('hidden');
          UI.inputContainer.classList.remove('hidden');
          UI.messages.classList.remove('waiting');
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
      UI.messages.prepend(messageDiv);
      UI.messages.scrollTop = 0;
      return;
    }
    if (message.type === 'features-update') {
      features = message;
      console.log('Received features update:', features);
      setTimeout(updateFeaturesUI, 0);
      if (!features.enableService) {
        showStatusMessage(`Service disabled by admin. Disconnecting...`);
        UI.socket.close();
      }
      return;
    }
    if (message.type === 'username-registered') {
      UI.claimSuccess.textContent = `Username claimed successfully: ${message.username}`;
      setTimeout(() => {
        UI.claimSuccess.textContent = '';
        UI.claimUsernameModal.classList.remove('active');
        UI.initialContainer.classList.remove('hidden');
        UI.usernameContainer.classList.add('hidden');
        UI.connectContainer.classList.add('hidden');
        UI.chatContainer.classList.add('hidden');
        UI.codeDisplayElement.classList.add('hidden');
        UI.copyCodeButton.classList.add('hidden');
        UI.statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'login-success') {
      username = message.username;
      localStorage.setItem('username', username);
      UI.loginSuccess.textContent = `Logged in as ${username}`;
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
                UI.messages.prepend(messageDiv);
              } catch (error) {
                console.error('Failed to decrypt offline message:', error);
                showStatusMessage('Failed to decrypt an offline message.');
              }
            })();
          } else if (msg.type === 'connection-request') {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message-bubble other';
            messageDiv.textContent = `Offline request from ${msg.from}: code ${msg.code}`;
            UI.messages.prepend(messageDiv);
          }
        }
        showStatusMessage('Pending offline messages loaded.');
      }
      setTimeout(() => {
        UI.loginSuccess.textContent = '';
        UI.loginModal.classList.remove('active');
        UI.initialContainer.classList.remove('hidden');
        UI.usernameContainer.classList.add('hidden');
        UI.connectContainer.classList.add('hidden');
        UI.chatContainer.classList.add('hidden');
        UI.codeDisplayElement.classList.add('hidden');
        UI.copyCodeButton.classList.add('hidden');
        UI.statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'user-found') {
      const searchedUsername = UI.searchUsernameInput.value.trim();
      UI.searchResult.innerHTML = `User ${searchedUsername} is ${message.status}. Code: `;
      const codeLink = document.createElement('a');
      codeLink.href = '#';
      codeLink.textContent = message.code;
      codeLink.onclick = (e) => {
        e.preventDefault();
        autoConnect(message.code);
        UI.searchUserModal.classList.remove('active');
      };
      UI.searchResult.appendChild(codeLink);
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
        UI.searchResult.appendChild(offlineMsgContainer);
      }
      return;
    }
    if (message.type === 'incoming-connection') {
      const fromUser = message.from === username ? 'Someone' : message.from;
      UI.incomingMessage.textContent = `${fromUser} wants to connect. Accept?`;
      UI.acceptButton.onclick = () => {
        UI.socket.send(JSON.stringify({ type: 'connection-accepted', code: message.code, clientId, token }));
        autoConnect(message.code);
        UI.incomingConnectionModal.classList.remove('active');
      };
      UI.denyButton.onclick = () => {
        UI.socket.send(JSON.stringify({ type: 'connection-denied', code: message.code, clientId, token }));
        UI.incomingConnectionModal.classList.remove('active');
      };
      UI.incomingConnectionModal.classList.add('active');
      return;
    }
    if (message.type === 'connection-denied') {
      showStatusMessage(`Connection request denied by ${message.from}`);
      return;
    }
    if (message.type === 'user-not-found') {
      UI.searchError.textContent = 'User not found.';
      setTimeout(() => {
        UI.searchError.textContent = '';
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
  if (UI.socket.readyState === WebSocket.OPEN && refreshToken && !refreshingToken) {
    refreshingToken = true;
    console.log('Proactively refreshing access token');
    UI.socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
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
      UI.socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token, version: keyVersion }));
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
      UI.socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token, version }));
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
function updateDots() {
  UI.userDots.innerHTML = '';
  const greenCount = totalClients;
  const redCount = maxClients - greenCount;
  const otherClientIds = Array.from(connectedClients).filter(id => id !== clientId);
  const selfDot = document.createElement('div');
  selfDot.className = 'user-dot online';
  UI.userDots.appendChild(selfDot);
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
    UI.userDots.appendChild(dot);
  });
  for (let i = 0; i < redCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'user-dot offline';
    UI.userDots.appendChild(dot);
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
  UI.socket.send(JSON.stringify(message));
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
  UI.socket.send(JSON.stringify(message));
  showStatusMessage(`Banned user ${usernames.get(targetId) || targetId}`);
}
UI.helpText.addEventListener('click', () => {
  UI.helpModal.classList.add('active');
  UI.helpModal.focus();
});
UI.helpModal.addEventListener('click', () => {
  UI.helpModal.classList.remove('active');
  UI.helpText.focus();
});
UI.helpModal.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    UI.helpModal.classList.remove('active');
    UI.helpText.focus();
  }
});
UI.addUserText.addEventListener('click', () => {
  if (isInitiator) {
    UI.addUserModal.classList.add('active');
    UI.addUserModal.focus();
  }
});
UI.addUserModal.addEventListener('click', () => {
  UI.addUserModal.classList.remove('active');
  UI.addUserText.focus();
});
UI.addUserModal.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    UI.addUserModal.classList.remove('active');
    UI.addUserText.focus();
  }
});
UI.cornerLogo.addEventListener('click', () => {
  UI.messages.innerHTML = '';
  processedMessageIds.clear();
  showStatusMessage('Chat history cleared locally.');
});
UI.userDots.addEventListener('click', (e) => {
  if (e.target.classList.contains('user-dot')) {
    e.target.classList.toggle('active');
  }
});
UI.toggleRecent.addEventListener('click', () => {
  const isHidden = UI.recentCodesList.classList.toggle('hidden');
  UI.toggleRecent.textContent = isHidden ? 'Show' : 'Hide';
});
UI.startChatToggleButton.onclick = () => {
  console.log('Start chat toggle clicked');
  UI.initialContainer.classList.add('hidden');
  UI.usernameContainer.classList.remove('hidden');
  UI.connectContainer.classList.add('hidden');
  UI.chatContainer.classList.add('hidden');
  UI.codeDisplayElement.classList.add('hidden');
  UI.copyCodeButton.classList.add('hidden');
  UI.statusElement.textContent = 'Enter a username to start a chat';
  UI.usernameInput.value = username || '';
  UI.usernameInput?.focus();
};
UI.connectToggleButton.onclick = () => {
  console.log('Connect toggle clicked');
  UI.initialContainer.classList.add('hidden');
  UI.usernameContainer.classList.add('hidden');
  UI.connectContainer.classList.remove('hidden');
  UI.chatContainer.classList.add('hidden');
  UI.codeDisplayElement.classList.add('hidden');
  UI.copyCodeButton.classList.add('hidden');
  UI.statusElement.textContent = 'Enter a username and code to join a chat';
  UI.usernameConnectInput.value = username || '';
  UI.usernameConnectInput?.focus();
};
UI.start2FAChatButton.onclick = () => {
  UI.totpOptionsModal.classList.add('active');
  UI.totpUsernameInput.value = username || '';
  UI.totpUsernameInput?.focus();
  UI.customTotpSecretContainer.classList.add('hidden');
  document.querySelector('input[name="totpType"][value="server"]').checked = true;
};
UI.connect2FAChatButton.onclick = () => {
  UI.initialContainer.classList.add('hidden');
  UI.usernameContainer.classList.add('hidden');
  UI.connectContainer.classList.remove('hidden');
  UI.chatContainer.classList.add('hidden');
  UI.codeDisplayElement.classList.add('hidden');
  UI.copyCodeButton.classList.add('hidden');
  UI.statusElement.textContent = 'Enter a username and code to join a 2FA chat';
  UI.usernameConnectInput.value = username || '';
  UI.usernameConnectInput?.focus();
  UI.connectButton.onclick = () => {
    const usernameInput = UI.usernameConnectInput.value.trim();
    const inputCode = UI.codeInput.value.trim();
    if (!validateUsername(usernameInput)) {
      showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
      UI.usernameConnectInput?.focus();
      return;
    }
    if (!validateCode(inputCode)) {
      showStatusMessage('Invalid code format: xxxx-xxxx-xxxx-xxxx.');
      UI.codeInput?.focus();
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
    UI.customTotpSecretContainer.classList.toggle('hidden', radio.value !== 'custom');
  });
});
UI.createTotpRoomButton.onclick = () => {
  const serverGenerated = document.querySelector('input[name="totpType"]:checked').value === 'server';
  startTotpRoom(serverGenerated);
};
UI.cancelTotpButton.onclick = () => {
  UI.totpOptionsModal.classList.remove('active');
  UI.initialContainer.classList.remove('hidden');
};
UI.closeTotpSecretButton.onclick = () => {
  UI.totpSecretModal.classList.remove('active');
};
UI.submitTotpCodeButton.onclick = () => {
  const totpCode = UI.totpCodeInput.value.trim();
  const codeParam = UI.totpInputModal.dataset.code;
  if (totpCode.length !== 6 || isNaN(totpCode)) {
    showStatusMessage('Invalid 2FA code: 6 digits required.');
    return;
  }
  joinWithTotp(codeParam, totpCode);
  UI.totpInputModal.classList.remove('active');
};
UI.cancelTotpInputButton.onclick = () => {
  UI.totpInputModal.classList.remove('active');
  UI.initialContainer.classList.remove('hidden');
};
UI.joinWithUsernameButton.onclick = () => {
  const usernameInput = UI.usernameInput.value.trim();
  if (!validateUsername(usernameInput)) {
    showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
    UI.usernameInput?.focus();
    return;
  }
  username = usernameInput;
  localStorage.setItem('username', username);
  console.log('Username set in localStorage:', username);
  code = generateCode();
  UI.codeDisplayElement.textContent = `Your code: ${code}`;
  UI.codeDisplayElement.classList.remove('hidden');
  UI.copyCodeButton.classList.remove('hidden');
  UI.usernameContainer.classList.add('hidden');
  UI.connectContainer.classList.add('hidden');
  UI.initialContainer.classList.add('hidden');
  UI.chatContainer.classList.remove('hidden');
  UI.messages.classList.add('waiting');
  UI.statusElement.textContent = 'Waiting for connection...';
  if (UI.socket.readyState === WebSocket.OPEN && token) {
    console.log('Sending join message for new chat');
    UI.socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  } else {
    pendingJoin = { code, clientId, username };
    if (UI.socket.readyState !== WebSocket.OPEN) {
      UI.socket.addEventListener('open', () => {
        console.log('WebSocket opened, sending join for new chat');
        if (token) {
          UI.socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
          pendingJoin = null;
        }
      }, { once: true });
    }
  }
  UI.messageInput?.focus();
};
UI.connectButton.onclick = () => {
  const usernameInput = UI.usernameConnectInput.value.trim();
  const inputCode = UI.codeInput.value.trim();
  if (!validateUsername(usernameInput)) {
    showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
    UI.usernameConnectInput?.focus();
    return;
  }
  if (!validateCode(inputCode)) {
    showStatusMessage('Invalid code format: xxxx-xxxx-xxxx-xxxx.');
    UI.codeInput?.focus();
    return;
  }
  username = usernameInput;
  localStorage.setItem('username', username);
  console.log('Username set in localStorage:', username);
  code = inputCode;
  UI.codeDisplayElement.textContent = `Using code: ${code}`;
  UI.codeDisplayElement.classList.remove('hidden');
  UI.copyCodeButton.classList.remove('hidden');
  UI.initialContainer.classList.add('hidden');
  UI.usernameContainer.classList.add('hidden');
  UI.connectContainer.classList.add('hidden');
  UI.chatContainer.classList.remove('hidden');
  UI.messages.classList.add('waiting');
  UI.statusElement.textContent = 'Waiting for connection...';
  if (UI.socket.readyState === WebSocket.OPEN && token) {
    console.log('Sending join message for existing chat');
    UI.socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  } else {
    pendingJoin = { code, clientId, username };
    if (UI.socket.readyState !== WebSocket.OPEN) {
      UI.socket.addEventListener('open', () => {
        console.log('WebSocket opened, sending join for existing chat');
        if (token) {
          UI.socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
          pendingJoin = null;
        }
      }, { once: true });
    }
  }
  UI.messageInput?.focus();
};
UI.backButton.onclick = () => {
  console.log('Back button clicked from usernameContainer');
  UI.usernameContainer.classList.add('hidden');
  UI.initialContainer.classList.remove('hidden');
  UI.connectContainer.classList.add('hidden');
  UI.chatContainer.classList.add('hidden');
  UI.codeDisplayElement.classList.add('hidden');
  UI.copyCodeButton.classList.add('hidden');
  UI.statusElement.textContent = 'Start a new chat or connect to an existing one';
  UI.messages.classList.remove('waiting');
  UI.startChatToggleButton?.focus();
  updateLogoutButtonVisibility();
};
UI.backButtonConnect.onclick = () => {
  console.log('Back button clicked from connectContainer');
  UI.connectContainer.classList.add('hidden');
  UI.initialContainer.classList.remove('hidden');
  UI.usernameContainer.classList.add('hidden');
  UI.chatContainer.classList.add('hidden');
  UI.codeDisplayElement.classList.add('hidden');
  UI.copyCodeButton.classList.add('hidden');
  UI.statusElement.textContent = 'Start a new chat or connect to an existing one';
  UI.messages.classList.remove('waiting');
  UI.connectToggleButton?.focus();
  updateLogoutButtonVisibility();
};
UI.sendButton.onclick = () => {
  const message = UI.messageInput.value.trim();
  if (message) {
    sendMessage(message);
  }
};
UI.messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    const message = UI.messageInput.value.trim();
    if (message) {
      sendMessage(message);
    }
  }
});
UI.imageButton.onclick = () => {
  UI.imageInput?.click();
};
UI.imageInput.onchange = (event) => {
  const file = event.target.files[0];
  if (file) {
    const type = file.type.startsWith('image/') ? 'image' : 'file';
    sendMedia(file, type);
    event.target.value = '';
  }
};
UI.voiceButton.onclick = () => {
  if (!mediaRecorder || mediaRecorder.state !== 'recording') {
    startVoiceRecording();
  } else {
    stopVoiceRecording();
  }
};
UI.voiceCallButton.onclick = () => {
  toggleVoiceCall();
};
UI.audioOutputButton.onclick = () => {
  toggleAudioOutput();
};
UI.grokButton.onclick = () => {
  toggleGrokBot();
};
UI.saveGrokKey.onclick = () => {
  saveGrokKey();
};
UI.newSessionButton.onclick = () => {
  console.log('New session button clicked');
  window.location.href = 'https://anonomoose.com';
};
UI.usernameInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    UI.joinWithUsernameButton?.click();
  }
});
UI.usernameConnectInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    UI.codeInput?.focus();
  }
});
UI.codeInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    UI.connectButton?.click();
  }
});
UI.codeInput.addEventListener('input', (e) => {
  let val = e.target.value.replace(/[^a-zA-Z0-9]/gi, '');
  val = val.substring(0, 16);
  let formatted = '';
  for (let i = 0; i < val.length; i++) {
    if (i > 0 && i % 4 === 0) formatted += '-';
    formatted += val[i];
  }
  e.target.value = formatted;
});
UI.copyCodeButton.onclick = () => {
  const codeText = UI.codeDisplayElement.textContent.replace('Your code: ', '').replace('Using code: ', '');
  navigator.clipboard.writeText(codeText).then(() => {
    UI.copyCodeButton.textContent = 'Copied!';
    setTimeout(() => {
      UI.copyCodeButton.textContent = 'Copy Code';
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy text: ', err);
    showStatusMessage('Failed to copy code.');
  });
  UI.copyCodeButton?.focus();
};
UI.button1.onclick = () => {
  if (isInitiator && UI.socket.readyState === WebSocket.OPEN && code && totalClients < maxClients && token) {
    UI.socket.send(JSON.stringify({ type: 'submit-random', code, clientId, token }));
    showStatusMessage(`Sent code ${code} to random board.`);
    codeSentToRandom = true;
    UI.button2.disabled = true;
  } else {
    showStatusMessage('Cannot send: Not initiator, no code, no token, or room is full.');
  }
  UI.button1?.focus();
};
UI.button2.onclick = () => {
  if (!UI.button2.disabled) {
    window.location.href = 'https://anonomoose.com/random.html';
  }
  UI.button2?.focus();
};
UI.loginButton.addEventListener('click', () => {
  if (username && token) {
    showStatusMessage('You are already logged in. Log out first to switch accounts.');
    return;
  }
  UI.loginModal.classList.add('active');
});
UI.loginSubmitButton.onclick = () => {
  if (username && token) {
    showStatusMessage('You are already logged in. Log out first to switch accounts.');
    return;
  }
  const name = UI.loginUsernameInput.value.trim();
  const pass = UI.loginPasswordInput.value;
  if (name && pass) {
    UI.socket.send(JSON.stringify({ type: 'login-username', username: name, password: pass, clientId, token }));
  }
};
UI.loginCancelButton.onclick = () => {
  UI.loginModal.classList.remove('active');
};
UI.searchUserButton.addEventListener('click', () => {
  UI.searchUserModal.classList.add('active');
});
UI.searchSubmitButton.onclick = () => {
  const name = UI.searchUsernameInput.value.trim();
  if (name) {
    UI.socket.send(JSON.stringify({ type: 'find-user', username: name, clientId, token }));
  }
};
UI.searchCancelButton.onclick = () => {
  UI.searchUserModal.classList.remove('active');
};
UI.claimUsernameButton.addEventListener('click', () => {
  if (username && token) {
    showStatusMessage('You are already logged in. Log out first to claim a new username.');
    return;
  }
  UI.claimUsernameModal.classList.add('active');
});
UI.claimCancelButton.onclick = () => {
  UI.claimUsernameModal.classList.remove('active');
};
UI.claimSubmitButton.onclick = () => {
  if (username && token) {
    showStatusMessage('You are already logged in. Log out first to claim a new username.');
    return;
  }
  const name = UI.claimUsernameInput.value.trim();
  const pass = UI.claimPasswordInput.value;
  if (validateUsername(name) && pass.length >= 8) {
    generateUserKeypair().then(publicKey => {
      UI.socket.send(JSON.stringify({ type: 'register-username', username: name, password: pass, public_key: publicKey, clientId, token }));
    }).catch(error => {
      console.error('Key generation error:', error);
      showStatusMessage('Failed to generate keys for claim.');
    });
  } else {
    showStatusMessage('Invalid username or password (min 8 chars).');
  }
};
UI.logoutButton.onclick = () => {
  console.log('Logout button clicked');
  logout();
};
updateLogoutButtonVisibility();
