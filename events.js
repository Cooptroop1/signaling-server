// events.js
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
const messageRateLimits = new Map();
let codeSentToRandom = false;
let useRelay = false;
let token = '';
let refreshToken = '';
let features = { enableService: true, enableImages: true, enableVoice: true, enableVoiceCalls: true, enableAudioToggle: true, enableGrokBot: true };
let keyPair;
let roomMaster;
let signingKey;
let remoteAudios = new Map();
let refreshingToken = false;
let signalingQueue = new Map();
let connectedClients = new Set();
let clientPublicKeys = new Map();
let initiatorPublic;
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
    try {
      keyPair = await CryptoUtils.generateKeyPair();
      initiatorPublic = await CryptoUtils.exportPublicKey(keyPair);
    } catch (error) {
      console.error('Failed to initialize crypto:', error);
      showStatusMessage('Crypto initialization failed.');
    }
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
helpText.addEventListener('click', () => {
  helpModal.classList.add('active');
  helpModal.focus();
});
helpModal.addEventListener('click', () => {
  helpModal.classList.remove('active');
  helpText.focus();
});
helpModal.addEventListener('keydown', (event) => {
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
cornerLogo.addEventListener('click', () => {
  document.getElementById('messages').innerHTML = '';
  processedMessageIds.clear();
  showStatusMessage('Chat history cleared locally.');
});

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
  console.log('DOM loaded, initializing maxClients UI');
  initializeMaxClientsUI();
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    setupWaitingForJoin(codeParam);
  } else {
    console.log('No valid code in URL, showing initial container');
    initialContainer.style.display = 'block';
    connectContainer.style.display = 'block';
    usernameContainer.style.display = 'none';
    chatContainer.style.display = 'none';
    statusElement.textContent = 'Enter a username and code to join or start a chat';
  }
});

socket.onopen = () => {
  console.log('WebSocket opened');
  socket.send(JSON.stringify({ type: 'connect', clientId }));
  if (pendingJoin && token) {
    console.log('WebSocket opened, sending pending join');
    socket.send(JSON.stringify({ type: 'join', ...pendingJoin, token }));
    pendingJoin = null;
  }
};

socket.onclose = () => {
  console.log('WebSocket closed');
  isConnected = false;
  showStatusMessage('Disconnected from server. Attempting to reconnect...');
  if (reconnectAttempts < 5) {
    setTimeout(() => {
      socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
      reconnectAttempts++;
    }, 5000);
  } else {
    showStatusMessage('Max reconnection attempts reached. Please refresh the page.');
  }
  stopKeepalive();
};

socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  showStatusMessage('WebSocket error occurred.');
};

let pendingJoin = null;

function validateCode(code) {
  const regex = /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/;
  return regex.test(code);
}

function validateUsername(username) {
  const regex = /^[a-zA-Z0-9]{1,16}$/;
  return regex.test(username);
}

function showStatusMessage(message) {
  statusElement.textContent = message;
  setTimeout(() => {
    if (statusElement.textContent === message) {
      statusElement.textContent = '';
    }
  }, 5000);
}

function initializeMaxClientsUI() {
  console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] initializeMaxClientsUI called, isInitiator: ${isInitiator}`);
  if (!isInitiator) {
    console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] Hiding addUserText for non-initiator`);
    document.getElementById('addUserText').style.display = 'none';
    return;
  }
  const addUserRadios = document.getElementById('addUserRadios');
  addUserRadios.innerHTML = '';
  console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] Creating buttons for maxClients in modal, current maxClients: ${maxClients}`);
  for (let i = 2; i <= 10; i++) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'user-button';
    button.textContent = i;
    button.dataset.value = i;
    button.addEventListener('click', () => {
      const n = parseInt(button.dataset.value);
      console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] Button clicked for maxClients: ${n}`);
      setMaxClients(n);
    });
    addUserRadios.appendChild(button);
  }
  console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] Buttons appended to addUserRadios`);
  updateMaxClientsUI();
}

function updateMaxClientsUI() {
  console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] updateMaxClientsUI called, maxClients: ${maxClients}, isInitiator: ${isInitiator}`);
  const buttons = document.querySelectorAll('#addUserRadios .user-button');
  console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] Found buttons in modal: ${buttons.length}`);
  buttons.forEach(button => {
    button.classList.remove('active');
    if (parseInt(button.dataset.value) === maxClients) {
      button.classList.add('active');
    }
  });
  updateDots();
}

function setMaxClients(n) {
  console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] setMaxClients called with n: ${n}, new maxClients: ${n}`);
  maxClients = n;
  updateMaxClientsUI();
  if (socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({ type: 'set-max-clients', maxClients: n, code, clientId, token }));
  }
}

let keepaliveInterval;

function startKeepalive() {
  keepaliveInterval = setInterval(() => {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'ping' }));
      console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] Sent keepalive ping`);
    }
  }, 20000);
}

function stopKeepalive() {
  console.log(`[2025-08-19T${new Date().toISOString().split('T')[1]}] Stopped keepalive`);
  clearInterval(keepaliveInterval);
}

async function sendMessage(message) {
  if (!restrictGlobalMessageRate()) {
    showStatusMessage('Message rate limit exceeded (30/min). Please wait.');
    return;
  }
  const messageId = Math.random().toString(36).substr(2, 9);
  const timestamp = Date.now();
  if (features.enableRelay && useRelay && socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({
      type: 'relay-message',
      content: message,
      messageId,
      username,
      code,
      clientId,
      timestamp,
      token
    }));
  } else if (features.enableP2P) {
    for (const [targetId, dataChannel] of dataChannels) {
      if (dataChannel.readyState === 'open') {
        const msg = JSON.stringify({ type: 'message', content: message, username, timestamp, messageId });
        dataChannel.send(msg);
      }
    }
  }
  processedMessageIds.add(messageId);
  const messageElement = document.createElement('div');
  messageElement.className = 'message sent';
  messageElement.textContent = `${username}: ${message}`;
  messages.appendChild(messageElement);
  messages.scrollTop = messages.scrollHeight;
  document.getElementById('messageInput').value = '';
}

async function sendMedia(file, type) {
  if (!restrictMediaRate(type)) {
    showStatusMessage(`${type.charAt(0).toUpperCase() + type.slice(1)} rate limit exceeded (5/min). Please wait.`);
    return;
  }
  const reader = new FileReader();
  reader.onload = async (e) => {
    const data = e.target.result;
    const messageId = Math.random().toString(36).substr(2, 9);
    const timestamp = Date.now();
    if (features.enableRelay && useRelay && socket.readyState === WebSocket.OPEN && token) {
      socket.send(JSON.stringify({
        type: `relay-${type}`,
        data,
        messageId,
        username,
        code,
        clientId,
        timestamp,
        token,
        filename: type === 'file' ? file.name : undefined
      }));
    } else if (features.enableP2P) {
      for (const [targetId, dataChannel] of dataChannels) {
        if (dataChannel.readyState === 'open') {
          const msg = JSON.stringify({ type, data, username, timestamp, messageId, filename: type === 'file' ? file.name : undefined });
          dataChannel.send(msg);
        }
      }
    }
    processedMessageIds.add(messageId);
    const messageElement = document.createElement('div');
    messageElement.className = 'message sent';
    if (type === 'image') {
      const img = document.createElement('img');
      img.src = data;
      img.alt = 'Sent image';
      messageElement.appendChild(img);
    } else if (type === 'voice') {
      const audio = document.createElement('audio');
      audio.controls = true;
      audio.src = data;
      messageElement.appendChild(audio);
    } else {
      const a = document.createElement('a');
      a.href = data;
      a.download = file.name;
      a.textContent = file.name;
      messageElement.appendChild(a);
    }
    const caption = document.createElement('div');
    caption.textContent = `${username}: ${type.charAt(0).toUpperCase() + type.slice(1)}`;
    messageElement.appendChild(caption);
    messages.appendChild(messageElement);
    messages.scrollTop = messages.scrollHeight;
  };
  reader.readAsDataURL(file);
}

function restrictGlobalMessageRate() {
  const now = performance.now();
  if (now - globalMessageRate.startTime >= 60000) {
    globalMessageRate = { count: 0, startTime: now };
  }
  globalMessageRate.count++;
  return globalMessageRate.count <= 30;
}

function restrictMediaRate(type) {
  const now = performance.now();
  const rateLimitMap = type === 'image' ? imageRateLimits : voiceRateLimits;
  const rateLimit = rateLimitMap.get(clientId) || { count: 0, startTime: now };
  if (now - rateLimit.startTime >= 60000) {
    rateLimit.count = 0;
    rateLimit.startTime = now;
  }
  rateLimit.count++;
  rateLimitMap.set(clientId, rateLimit);
  return rateLimit.count <= 5;
}

async function toggleVoiceCall() {
  showStatusMessage('Voice call functionality not implemented.');
}

function toggleAudioOutput() {
  showStatusMessage('Audio output toggle not implemented.');
}

function toggleGrokBot() {
  showStatusMessage('Grok bot functionality not implemented.');
}

function saveGrokKey() {
  showStatusMessage('Grok key saving not implemented.');
}

function setupWaitingForJoin(codeParam) {
  code = codeParam;
  initialContainer.style.display = 'none';
  connectContainer.style.display = 'none';
  usernameContainer.style.display = 'none';
  chatContainer.style.display = 'flex';
  codeDisplayElement.style.display = 'none';
  copyCodeButton.style.display = 'none';
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
      joinButton.onclick = originalOnclick;
    };
  } else {
    codeDisplayElement.textContent = `Using code: ${code}`;
    codeDisplayElement.style.display = 'block';
    copyCodeButton.style.display = 'block';
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

socket.onmessage = async (event) => {
  console.log('Received WebSocket message:', event.data);
  try {
    const message = JSON.parse(event.data);
    console.log('Parsed message:', message);
    if (message.type === 'error') {
      showStatusMessage(message.message);
      return;
    }
    if (message.type === 'connected') {
      console.log('Received authentication tokens:', message);
      token = message.accessToken;
      refreshToken = message.refreshToken;
      clientId = message.clientId;
      setCookie('clientId', clientId, 365);
      startKeepalive();
      if (pendingJoin && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'join', ...pendingJoin, token }));
        pendingJoin = null;
      }
      return;
    }
    if (message.type === 'token-refreshed') {
      console.log('Received refreshed tokens:', message);
      token = message.accessToken;
      refreshToken = message.refreshToken;
      refreshingToken = false;
      return;
    }
    if (message.type === 'init') {
      console.log(`Initialized client ${message.clientId}, username: ${username}, maxClients: ${message.maxClients}, isInitiator: ${message.isInitiator}, features:`, message.features);
      maxClients = message.maxClients;
      isInitiator = message.isInitiator;
      features = message.features;
      code = message.code || code;
      useRelay = !features.enableP2P || message.useRelay;
      codeDisplayElement.textContent = isInitiator ? `Your code: ${code}` : `Using code: ${code}`;
      codeDisplayElement.style.display = 'block';
      copyCodeButton.style.display = 'block';
      initialContainer.style.display = 'none';
      connectContainer.style.display = 'none';
      usernameContainer.style.display = 'none';
      chatContainer.style.display = 'flex';
      messages.classList.remove('waiting');
      initializeMaxClientsUI();
      if (isInitiator && features.enableP2P) {
        try {
          roomMaster = await CryptoUtils.generateRoomKey();
          signingKey = await CryptoUtils.generateSigningKey();
        } catch (error) {
          console.error('Failed to generate keys:', error);
          showStatusMessage('Failed to initialize encryption.');
        }
      }
      return;
    }
    if (message.type === 'join-notify') {
      console.log(`Join-notify received for code: ${message.code}, client: ${message.clientId}, total: ${message.totalClients}, username: ${message.username}`);
      totalClients = message.totalClients;
      usernames.set(message.clientId, message.username);
      updateMaxClientsUI();
      if (isInitiator && features.enableP2P && message.clientId !== clientId) {
        console.log(`Initiating peer connection with client ${message.clientId}`);
        startPeerConnection(message.clientId, message.code, true);
        try {
          const publicKey = await CryptoUtils.exportPublicKey(keyPair);
          socket.send(JSON.stringify({ type: 'public-key', publicKey, clientId, code: message.code, token }));
        } catch (error) {
          console.error('Failed to send public key:', error);
          showStatusMessage('Failed to send public key.');
        }
      }
      return;
    }
    if (message.type === 'public-key' && features.enableP2P) {
      console.log(`Received public-key from ${message.clientId} for code: ${message.code}`);
      try {
        const remotePublicKey = await CryptoUtils.importPublicKey(message.publicKey);
        clientPublicKeys.set(message.clientId, remotePublicKey);
        if (isInitiator) {
          const iv = await CryptoUtils.generateIV();
          const ivBase64 = btoa(String.fromCharCode.apply(null, iv));
          const roomKeyExported = await CryptoUtils.exportKey(roomMaster);
          const encryptedKey = await CryptoUtils.encryptBytes(roomKeyExported, roomMaster, iv);
          const encryptedKeyBase64 = btoa(String.fromCharCode.apply(null, encryptedKey));
          socket.send(JSON.stringify({
            type: 'encrypted-room-key',
            encryptedKey: encryptedKeyBase64,
            iv: ivBase64,
            publicKey: initiatorPublic,
            clientId,
            targetId: message.clientId,
            code: message.code,
            token
          }));
          console.log(`Sent encrypted-room-key to ${message.clientId}`);
        }
      } catch (error) {
        console.error('Error handling public-key:', error);
        showStatusMessage('Failed to process public key.');
      }
      return;
    }
    if (message.type === 'encrypted-room-key' && features.enableP2P) {
      console.log(`Received encrypted-room-key from ${message.clientId} for code: ${message.code}`);
      try {
        const remotePublicKey = clientPublicKeys.get(message.clientId);
        if (!remotePublicKey) {
          console.error('No public key for client:', message.clientId);
          return;
        }
        const sharedKey = await CryptoUtils.deriveSharedKey(keyPair.privateKey, remotePublicKey);
        const encryptedKey = new Uint8Array(atob(message.encryptedKey).split('').map(c => c.charCodeAt(0)));
        const iv = new Uint8Array(atob(message.iv).split('').map(c => c.charCodeAt(0)));
        const decryptedKey = await CryptoUtils.decryptBytes(encryptedKey, sharedKey, iv);
        roomMaster = await window.crypto.subtle.importKey(
          'raw',
          decryptedKey,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
        console.log('Imported room key successfully');
        const newIv = await CryptoUtils.generateIV();
        const newIvBase64 = btoa(String.fromCharCode.apply(null, newIv));
        const newEncryptedKey = await CryptoUtils.encryptBytes(await CryptoUtils.exportKey(roomMaster), sharedKey, newIv);
        const newEncryptedKeyBase64 = btoa(String.fromCharCode.apply(null, newEncryptedKey));
        socket.send(JSON.stringify({
          type: 'new-room-key',
          encrypted: newEncryptedKeyBase64,
          iv: newIvBase64,
          targetId: message.clientId,
          clientId,
          code: message.code,
          token
        }));
        console.log(`Sent new-room-key to ${message.clientId}`);
      } catch (error) {
        console.error('Error handling encrypted-room-key:', error);
        showStatusMessage('Failed to process encrypted room key.');
      }
      return;
    }
    if (message.type === 'new-room-key' && features.enableP2P) {
      console.log(`Received new-room-key from ${message.clientId} for code: ${message.code}`);
      try {
        const remotePublicKey = clientPublicKeys.get(message.clientId);
        if (!remotePublicKey) {
          console.error('No public key for client:', message.clientId);
          return;
        }
        const sharedKey = await CryptoUtils.deriveSharedKey(keyPair.privateKey, remotePublicKey);
        const encryptedKey = new Uint8Array(atob(message.encrypted).split('').map(c => c.charCodeAt(0)));
        const iv = new Uint8Array(atob(message.iv).split('').map(c => c.charCodeAt(0)));
        const decryptedKey = await CryptoUtils.decryptBytes(encryptedKey, sharedKey, iv);
        roomMaster = await window.crypto.subtle.importKey(
          'raw',
          decryptedKey,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
        console.log('Imported new room key successfully');
      } catch (error) {
        console.error('Error handling new-room-key:', error);
        showStatusMessage('Failed to process new room key.');
      }
      return;
    }
    if (message.type === 'answer' && features.enableP2P) {
      console.log(`Received answer from ${message.clientId} for code: ${message.code}`);
      handleAnswer(message.clientId, message.answer, message.code);
      return;
    }
    if (message.type === 'candidate' && features.enableP2P) {
      console.log(`Received ICE candidate from ${message.clientId} for code: ${message.code}`);
      handleCandidate(message.clientId, message.candidate, message.code);
      return;
    }
    if (message.type === 'client-disconnected') {
      console.log(`Client disconnected: ${message.clientId}, total: ${message.totalClients}, initiator: ${message.isInitiator}`);
      totalClients = message.totalClients;
      if (message.isInitiator && totalClients > 0) {
        console.log(`Initiator changed to ${message.newInitiator}`);
        isInitiator = message.newInitiator === clientId;
        initializeMaxClientsUI();
      }
      if (peerConnections.has(message.clientId)) {
        peerConnections.get(message.clientId).close();
        peerConnections.delete(message.clientId);
        dataChannels.delete(message.clientId);
        candidatesQueues.delete(message.clientId);
        clientPublicKeys.delete(message.clientId);
      }
      usernames.delete(message.clientId);
      updateMaxClientsUI();
      showStatusMessage(`User ${usernames.get(message.clientId) || 'unknown'} disconnected.`);
      return;
    }
    if (message.type === 'initiator-changed') {
      console.log(`Initiator changed to ${message.newInitiator}, total: ${message.totalClients}`);
      totalClients = message.totalClients;
      isInitiator = message.newInitiator === clientId;
      initializeMaxClientsUI();
      showStatusMessage(`New initiator assigned.`);
      return;
    }
    if (message.type === 'max-clients') {
      console.log(`Max clients updated to ${message.maxClients} for code: ${message.code}`);
      maxClients = message.maxClients;
      totalClients = message.totalClients;
      updateMaxClientsUI();
      return;
    }
    if (message.type === 'random-codes') {
      console.log('Received random codes:', message.codes);
      return;
    }
    if (message.type === 'totp-required') {
      showStatusMessage('TOTP code required for this chat room.');
      return;
    }
    if (message.type === 'totp-enabled') {
      showStatusMessage('TOTP enabled for this chat room.');
      return;
    }
    if (message.type === 'features-update') {
      console.log('Received features update:', message);
      features = message;
      useRelay = !features.enableP2P;
      return;
    }
    if (message.type === 'pong') {
      console.log('Received pong');
      return;
    }
    if (['message', 'image', 'voice', 'file'].includes(message.type) && !processedMessageIds.has(message.messageId)) {
      console.log(`Received ${message.type} relay message:`, message);
      processedMessageIds.add(message.messageId);
      const messageElement = document.createElement('div');
      messageElement.className = 'message received';
      if (message.type === 'message') {
        messageElement.textContent = `${message.username}: ${message.content}`;
      } else if (message.type === 'image') {
        const img = document.createElement('img');
        img.src = message.data;
        img.alt = 'Received image';
        messageElement.appendChild(img);
        const caption = document.createElement('div');
        caption.textContent = `${message.username}: Image`;
        messageElement.appendChild(caption);
      } else if (message.type === 'voice') {
        const audio = document.createElement('audio');
        audio.controls = true;
        audio.src = message.data;
        messageElement.appendChild(audio);
        const caption = document.createElement('div');
        caption.textContent = `${message.username}: Voice`;
        messageElement.appendChild(caption);
      } else if (message.type === 'file') {
        const a = document.createElement('a');
        a.href = message.data;
        a.download = message.filename;
        a.textContent = message.filename;
        messageElement.appendChild(a);
        const caption = document.createElement('div');
        caption.textContent = `${message.username}: File`;
        messageElement.appendChild(caption);
      }
      messages.appendChild(messageElement);
      messages.scrollTop = messages.scrollHeight;
    }
  } catch (error) {
    console.error('Error processing WebSocket message:', error);
    showStatusMessage('Error processing server message.');
  }
};

async function startPeerConnection(targetId, code, isOfferer) {
  console.log(`Starting peer connection with ${targetId} for code: ${code}, offerer: ${isOfferer}`);
  const configuration = {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      {
        urls: 'turn:anonomoose.com:3478',
        username: '292fcad64b5b9b5b0b734386',
        credential: 'JDYekY9rXug82QUQ'
      }
    ]
  };
  const peerConnection = new RTCPeerConnection(configuration);
  peerConnections.set(targetId, peerConnection);
  candidatesQueues.set(targetId, []);
  retryCounts.set(targetId, 0);

  peerConnection.onicecandidate = ({ candidate }) => {
    if (candidate) {
      console.log(`Sending ICE candidate to ${targetId} for code: ${code}`);
      socket.send(JSON.stringify({ type: 'candidate', candidate, targetId, code, clientId, token }));
    }
  };

  peerConnection.onicecandidateerror = (event) => {
    console.error(`ICE candidate error for ${targetId}: ${event.errorText}, code=${event.errorCode}`);
    if (event.errorCode === 701) {
      console.log(`Ignoring ICE 701 error for ${targetId}, continuing connection`);
    }
  };

  peerConnection.onicegatheringstatechange = () => {
    console.log(`ICE gathering state for ${targetId}: ${peerConnection.iceGatheringState}`);
  };

  peerConnection.onconnectionstatechange = () => {
    console.log(`Connection state for ${targetId}: ${peerConnection.connectionState}`);
    if (peerConnection.connectionState === 'connected') {
      console.log(`WebRTC connection established with ${targetId} for code: ${code}`);
      connectedClients.add(targetId);
      clearTimeout(connectionTimeouts.get(targetId));
    } else if (peerConnection.connectionState === 'failed' || peerConnection.connectionState === 'disconnected') {
      console.log(`Connection ${peerConnection.connectionState} with ${targetId}, retrying...`);
      if (retryCounts.get(targetId) < maxRetries) {
        retryCounts.set(targetId, retryCounts.get(targetId) + 1);
        peerConnection.close();
        peerConnections.delete(targetId);
        dataChannels.delete(targetId);
        candidatesQueues.delete(targetId);
        startPeerConnection(targetId, code, isOfferer);
      } else {
        console.log(`Max retries reached for ${targetId}, checking relay availability`);
        if (features.enableRelay) {
          useRelay = true;
          showStatusMessage('P2P connection failed, switching to relay mode.');
        }
      }
    }
  };

  if (isOfferer) {
    const dataChannel = peerConnection.createDataChannel('chat');
    dataChannels.set(targetId, dataChannel);
    console.log(`Created data channel for ${targetId}`);
    setupDataChannel(targetId, dataChannel, code);
    try {
      const offer = await peerConnection.createOffer();
      await peerConnection.setLocalDescription(offer);
      console.log(`Sending offer to ${targetId} for code: ${code}`);
      socket.send(JSON.stringify({ type: 'offer', offer, targetId, code, clientId, token }));
    } catch (error) {
      console.error(`Error creating offer for ${targetId}:`, error);
      showStatusMessage('Failed to create offer.');
    }
  }

  peerConnection.ondatachannel = (event) => {
    const dataChannel = event.channel;
    dataChannels.set(targetId, dataChannel);
    console.log(`Received data channel for ${targetId}`);
    setupDataChannel(targetId, dataChannel, code);
  };

  connectionTimeouts.set(targetId, setTimeout(() => {
    if (!connectedClients.has(targetId)) {
      console.log(`Connection timeout for ${targetId}, retrying...`);
      if (retryCounts.get(targetId) < maxRetries) {
        retryCounts.set(targetId, retryCounts.get(targetId) + 1);
        peerConnection.close();
        peerConnections.delete(targetId);
        dataChannels.delete(targetId);
        candidatesQueues.delete(targetId);
        startPeerConnection(targetId, code, isOfferer);
      } else {
        console.log(`Max retries reached for ${targetId}, checking relay availability`);
        if (features.enableRelay) {
          useRelay = true;
          showStatusMessage('P2P connection failed, switching to relay mode.');
        }
      }
    }
  }, 30000));
}

function setupDataChannel(targetId, dataChannel, code) {
  console.log(`setupDataChannel initialized for targetId: ${targetId}`);
  dataChannel.onopen = () => {
    console.log(`Data channel opened with ${targetId} for code: ${code}, state: ${dataChannel.readyState}`);
    connectedClients.add(targetId);
  };
  dataChannel.onclose = () => {
    console.log(`Data channel closed with ${targetId} for code: ${code}`);
    connectedClients.delete(targetId);
  };
  dataChannel.onmessage = async (event) => {
    try {
      const message = JSON.parse(event.data);
      if (processedMessageIds.has(message.messageId)) return;
      processedMessageIds.add(message.messageId);
      const messageElement = document.createElement('div');
      messageElement.className = 'message received';
      if (message.type === 'message') {
        messageElement.textContent = `${message.username}: ${message.content}`;
      } else if (message.type === 'image') {
        const img = document.createElement('img');
        img.src = message.data;
        img.alt = 'Received image';
        messageElement.appendChild(img);
        const caption = document.createElement('div');
        caption.textContent = `${message.username}: Image`;
        messageElement.appendChild(caption);
      } else if (message.type === 'voice') {
        const audio = document.createElement('audio');
        audio.controls = true;
        audio.src = message.data;
        messageElement.appendChild(audio);
        const caption = document.createElement('div');
        caption.textContent = `${message.username}: Voice`;
        messageElement.appendChild(caption);
      } else if (message.type === 'file') {
        const a = document.createElement('a');
        a.href = message.data;
        a.download = message.filename;
        a.textContent = message.filename;
        messageElement.appendChild(a);
        const caption = document.createElement('div');
        caption.textContent = `${message.username}: File`;
        messageElement.appendChild(caption);
      }
      messages.appendChild(messageElement);
      messages.scrollTop = messages.scrollHeight;
    } catch (error) {
      console.error(`Error processing data channel message from ${targetId}:`, error);
    }
  };
}

async function handleAnswer(clientId, answer, code) {
  console.log(`Handling answer from ${clientId} for code: ${code}`);
  const peerConnection = peerConnections.get(clientId);
  if (!peerConnection) {
    console.error(`No peer connection for ${clientId}`);
    return;
  }
  try {
    await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
    const queuedCandidates = candidatesQueues.get(clientId) || [];
    for (const candidate of queuedCandidates) {
      await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
    }
    candidatesQueues.set(clientId, []);
  } catch (error) {
    console.error(`Error handling answer from ${clientId}:`, error);
    showStatusMessage('Failed to process answer.');
  }
}

async function handleCandidate(clientId, candidate, code) {
  console.log(`Handling ICE candidate from ${clientId} for code: ${code}`);
  const peerConnection = peerConnections.get(clientId);
  if (!peerConnection) {
    console.error(`No peer connection for ${clientId}`);
    return;
  }
  try {
    if (peerConnection.remoteDescription) {
      await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
    } else {
      const queue = candidatesQueues.get(clientId) || [];
      queue.push(candidate);
      candidatesQueues.set(clientId, queue);
    }
  } catch (error) {
    console.error(`Error handling ICE candidate from ${clientId}:`, error);
    showStatusMessage('Failed to process ICE candidate.');
  }
}
