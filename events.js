// events.js - All event listeners and handlers for Anonomoose Chat

// Global variables (assumed from main.js or init.js, but listed for completeness)
let socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
let code, clientId, username, isInitiator, isConnected, maxClients, totalClients;
let peerConnections = new Map();
let dataChannels = new Map();
let connectionTimeouts = new Map();
let retryCounts = new Map();
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
const CHUNK_SIZE = 8192;
const chunkBuffers = new Map();
const negotiationQueues = new Map();
let globalSendRate = { count: 0, startTime: performance.now() };
const renegotiationCounts = new Map();
const maxRenegotiations = 5;
let keyVersion = 0;
let globalSizeRate = { totalSize: 0, startTime: performance.now() };
let processedNonces = new Map();
const imageRateLimits = new Map();
const voiceRateLimits = new Map();
let globalMessageRate = { count: 0, startTime: Date.now() };
let reconnectAttempts = 0;
const maxReconnectAttempts = 5;
let refreshFailures = 0;
let refreshBackoff = 1000;
let pendingCode = null;
let pendingJoin = null;
let cycleTimeout;
let lazyObserver;

// DOM elements
let statusElement = document.getElementById('status');
let codeDisplayElement = document.getElementById('codeDisplay');
let copyCodeButton = document.getElementById('copyCodeButton');
let initialContainer = document.getElementById('initialContainer');
let usernameContainer = document.getElementById('usernameContainer');
let connectContainer = document.getElementById('connectContainer');
let chatContainer = document.getElementById('chatContainer');
let newSessionButton = document.getElementById('newSessionButton');
let maxClientsContainer = document.getElementById('maxClientsContainer');
let inputContainer = document.querySelector('.input-container');
let messages = document.getElementById('messages');
let cornerLogo = document.getElementById('cornerLogo');
let button2 = document.getElementById('button2');
let helpText = document.getElementById('helpText');
let helpModal = document.getElementById('helpModal');
let addUserText = document.getElementById('addUserText');
let addUserModal = document.getElementById('addUserModal');

// Event listeners for main buttons
document.getElementById('startAnonChatButton').onclick = () => {
  console.log('Start anonymous chat button clicked');
  initialContainer.classList.add('hidden');
  usernameContainer.classList.remove('hidden');
  document.getElementById('usernameInput').value = username || '';
  document.getElementById('usernameInput')?.focus();
};

document.getElementById('startNamedChatButton').onclick = () => {
  console.log('Start named chat button clicked');
  document.getElementById('loginModal').classList.add('active');
  document.getElementById('loginUsernameInput')?.focus();
};

document.getElementById('connectCodeButton').onclick = () => {
  console.log('Connect using code button clicked');
  initialContainer.classList.add('hidden');
  connectContainer.classList.remove('hidden');
  document.getElementById('usernameConnectInput').value = username || '';
  document.getElementById('usernameConnectInput')?.focus();
};

document.getElementById('connectUsernameButton').onclick = () => {
  console.log('Connect using username button clicked');
  document.getElementById('searchUserModal').classList.add('active');
  document.getElementById('searchUsernameInput')?.focus();
};

// Login modal handlers
document.getElementById('loginSubmitButton').onclick = () => {
  const usernameInput = document.getElementById('loginUsernameInput').value.trim();
  const password = document.getElementById('loginPasswordInput').value;
  if (!validateUsername(usernameInput) || !password) {
    document.getElementById('loginError').textContent = 'Invalid username or password.';
    document.getElementById('loginError').classList.remove('hidden');
    return;
  }
  socket.send(JSON.stringify({ type: 'login', username: usernameInput, password, clientId, token }));
};

document.getElementById('loginCancelButton').onclick = () => {
  document.getElementById('loginModal').classList.remove('active');
  initialContainer.classList.remove('hidden');
};

// Search modal handlers
document.getElementById('searchSubmitButton').onclick = () => {
  const searchUsername = document.getElementById('searchUsernameInput').value.trim();
  if (!validateUsername(searchUsername)) {
    document.getElementById('searchError').textContent = 'Invalid username.';
    document.getElementById('searchError').classList.remove('hidden');
    return;
  }
  socket.send(JSON.stringify({ type: 'find-user', username: searchUsername, clientId, token }));
};

document.getElementById('searchCancelButton').onclick = () => {
  document.getElementById('searchUserModal').classList.remove('active');
  initialContainer.classList.remove('hidden');
};

// Help modal
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

// Add user modal
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

// Join with username (for anonymous)
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
  statusElement.textContent = 'Waiting for connection...';
  if (socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  } else {
    pendingJoin = { code, clientId, username };
    if (socket.readyState !== WebSocket.OPEN) {
      socket.addEventListener('open', () => {
        if (token) {
          socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
          pendingJoin = null;
        }
      }, { once: true });
    }
  }
  document.getElementById('messageInput')?.focus();
};

// Connect button (for code)
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
  if (socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  } else {
    pendingJoin = { code, clientId, username };
    if (socket.readyState !== WebSocket.OPEN) {
      socket.addEventListener('open', () => {
        if (token) {
          socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
          pendingJoin = null;
        }
      }, { once: true });
    }
  }
  document.getElementById('messageInput')?.focus();
};

// Back buttons
document.getElementById('backButton').onclick = () => {
  usernameContainer.classList.add('hidden');
  initialContainer.classList.remove('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  document.getElementById('startAnonChatButton')?.focus();
};

document.getElementById('backButtonConnect').onclick = () => {
  connectContainer.classList.add('hidden');
  initialContainer.classList.remove('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  document.getElementById('connectCodeButton')?.focus();
};

// Send button
document.getElementById('sendButton').onclick = () => {
  const messageInput = document.getElementById('messageInput');
  const message = messageInput.value.trim();
  if (message) {
    sendMessage(message);
  }
};

// Message input keydown
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

// Image button
document.getElementById('imageButton').onclick = () => {
  document.getElementById('imageInput')?.click();
};

// Image input change
document.getElementById('imageInput').onchange = (event) => {
  const file = event.target.files[0];
  if (file) {
    const type = file.type.startsWith('image/') ? 'image' : 'file';
    sendMedia(file, type);
    event.target.value = '';
  }
};

// Voice button
document.getElementById('voiceButton').onclick = () => {
  if (!mediaRecorder || mediaRecorder.state !== 'recording') {
    startVoiceRecording();
  } else {
    stopVoiceRecording();
  }
};

// Voice call button
document.getElementById('voiceCallButton').onclick = () => {
  toggleVoiceCall();
};

// Audio output button
document.getElementById('audioOutputButton').onclick = () => {
  toggleAudioOutput();
};

// Grok button
document.getElementById('grokButton').onclick = () => {
  toggleGrokBot();
};

// Save Grok key
document.getElementById('saveGrokKey').onclick = () => {
  saveGrokKey();
};

// New session button
document.getElementById('newSessionButton').onclick = () => {
  window.location.href = 'https://anonomoose.com';
};

// Username input keydown
document.getElementById('usernameInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    document.getElementById('joinWithUsernameButton')?.click();
  }
});

// Username connect input keydown
document.getElementById('usernameConnectInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    document.getElementById('codeInput')?.focus();
  }
});

// Code input keydown
document.getElementById('codeInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    document.getElementById('connectButton')?.click();
  }
});

// Copy code button
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

// Send code to random
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

// Random chat
document.getElementById('button2').onclick = () => {
  if (!button2.disabled) {
    window.location.href = 'https://anonomoose.com/random.html';
  }
  document.getElementById('button2')?.focus();
};

// Clear chat history
cornerLogo.addEventListener('click', () => {
  document.getElementById('messages').innerHTML = '';
  processedMessageIds.clear();
  showStatusMessage('Chat history cleared locally.');
});

// Start 2FA chat
document.getElementById('start2FAChatButton').onclick = () => {
  document.getElementById('totpOptionsModal').classList.add('active');
  document.getElementById('totpUsernameInput').value = username || '';
  document.getElementById('totpUsernameInput')?.focus();
  document.getElementById('customTotpSecretContainer').classList.add('hidden');
  document.querySelector('input[name="totpType"][value="server"]').checked = true;
};

// Connect to 2FA room
document.getElementById('connect2FAChatButton').onclick = () => {
  initialContainer.classList.add('hidden');
  connectContainer.classList.remove('hidden');
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
    code = inputCode;
    showTotpInputModal(code);
  };
};

// TOTP type change
document.querySelectorAll('input[name="totpType"]').forEach(radio => {
  radio.addEventListener('change', () => {
    document.getElementById('customTotpSecretContainer').classList.toggle('hidden', radio.value !== 'custom');
  });
});

// Create TOTP room
document.getElementById('createTotpRoomButton').onclick = () => {
  const serverGenerated = document.querySelector('input[name="totpType"]:checked').value === 'server';
  startTotpRoom(serverGenerated);
};

// Cancel TOTP
document.getElementById('cancelTotpButton').onclick = () => {
  document.getElementById('totpOptionsModal').classList.remove('active');
};

// Close TOTP secret
document.getElementById('closeTotpSecretButton').onclick = () => {
  document.getElementById('totpSecretModal').classList.remove('active');
};

// Submit TOTP code
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

// Cancel TOTP input
document.getElementById('cancelTotpInputButton').onclick = () => {
  document.getElementById('totpInputModal').classList.remove('active');
  initialContainer.classList.remove('hidden');
};

// Claim username
document.getElementById('claimUsernameButton').addEventListener('click', () => {
  document.getElementById('claimError').classList.add('hidden');
  document.getElementById('claimUsernameModal').classList.add('active');
});

document.getElementById('claimSubmitButton').onclick = async () => {
  const name = document.getElementById('claimUsernameInput').value.trim();
  const pass = document.getElementById('claimPasswordInput').value;
  if (name && pass) {
    socket.send(JSON.stringify({ type: 'register-username', username: name, password: pass, clientId, token }));
  }
};

document.getElementById('claimCancelButton').onclick = () => {
  document.getElementById('claimUsernameModal').classList.remove('active');
};

// Corner logo cycle
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

// Socket setup (moved from init.js if needed, but assuming it's in main.js)

// Socket onmessage
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
          const jitter = Math.random() * 4000 + 1000; // 1-5s
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
      } else if (message.message.includes('Invalid password') || message.message.includes('Username not found')) {
        document.getElementById('loginError').textContent = message.message;
        document.getElementById('loginError').classList.remove('hidden');
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
          inputContainer.classList.remove('hidden');
          messages.classList.remove('waiting');
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
        inputContainer.classList.add('hidden');
        messages.classList.add('waiting');
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
    if (message.type === 'message' || message.type === 'image' || message.type === 'voice' || message.type === 'file') {
      if (useRelay) {
        if (processedMessageIds.has(message.messageId)) return;
        processedMessageIds.add(message.messageId);
        console.log('Received relay message:', message); // Debug
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
        messages.prepend(messageDiv);
        messages.scrollTop = 0;
        return;
      }
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
      showStatusMessage(`Username '${message.username}' claimed successfully!`);
      document.getElementById('claimUsernameModal').classList.remove('active');
      return;
    }
    if (message.type === 'login-success') {
      document.getElementById('loginModal').classList.remove('active');
      username = message.username;
      localStorage.setItem('username', username);
      // Create room
      code = generateCode();
      socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
      // Update UI
      initialContainer.classList.add('hidden');
      chatContainer.classList.remove('hidden');
      codeDisplayElement.textContent = `Your code: ${code}`;
      codeDisplayElement.classList.remove('hidden');
      copyCodeButton.classList.remove('hidden');
      messages.classList.add('waiting');
      statusElement.textContent = 'Waiting for connection...';
      document.getElementById('messageInput')?.focus();
      showStatusMessage(`Named room created for ${username}`);
      return;
    }
    if (message.type === 'user-found') {
      document.getElementById('searchUserModal').classList.remove('active');
      if (message.code) {
        autoConnect(message.code);
      } else {
        showStatusMessage('User found but no active room.');
      }
      return;
    }
    if (message.type === 'user-not-found') {
      document.getElementById('searchError').textContent = 'User not found.';
      document.getElementById('searchError').classList.remove('hidden');
      return;
    }
  } catch (error) {
    console.error('Error parsing message:', error, 'Raw data:', event.data);
  }
};

// Socket open
socket.onopen = () => {
  console.log('WebSocket opened');
  socket.send(JSON.stringify({ type: 'connect', clientId }));
  reconnectAttempts = 0;
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    pendingCode = codeParam;
  } else {
    initialContainer.classList.remove('hidden');
  }
};

// Socket error
socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  showStatusMessage('Connection error, please try again later.');
  connectionTimeouts.forEach((timeout) => clearTimeout(timeout));
};

// Socket close
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

// DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    setupWaitingForJoin(codeParam);
  }
  // Auto-format code input
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
});

// Cleanup old nonces
setInterval(() => {
  const now = Date.now();
  for (const [nonce, ts] of processedNonces) {
    if (now - ts > 3600000) { // 1hr
      processedNonces.delete(nonce);
    }
  }
  console.log(`Cleaned processedNonces, remaining: ${processedNonces.size}`);
}, 300000); // 5min
