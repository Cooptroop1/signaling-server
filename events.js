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
let features = { enableService: true, enableImages: true, enableVoice: true, enableVoiceCalls: true, enableGrokBot: true }; // Global features state
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
// New: Ratchet state variables
let epoch = 0;
let sendingChainKey;
let sendingSeq = 0;
let receivingChainKeys = new Map(); // senderUsername => chainKey
let receivingSeq = new Map(); // senderUsername => seq

// New: Reset chains on roomMaster change
async function resetChains() {
  if (!roomMaster || !username) return;
  sendingChainKey = await deriveChainKey(roomMaster, username);
  sendingSeq = 0;
  receivingChainKeys.clear();
  receivingSeq.clear();
  signingKey = await deriveSigningKey(roomMaster); // Update signing key too
}

// Assume in the truncated code, after setting roomMaster (e.g., in socket onmessage for 'init' or 'join'), call resetChains();

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
    console.log('Detected code in URL, setting pendingCode for auto-connect');
    pendingCode = codeParam;
    if (username && validateUsername(username)) {
      if (token) {
        socket.send(JSON.stringify({ type: 'join', code: pendingCode, clientId, username, token }));
      } else {
        pendingJoin = { code: pendingCode, clientId, username };
      }
    } else {
      usernameContainer.classList.remove('hidden');
      initialContainer.classList.add('hidden');
      connectContainer.classList.add('hidden');
      chatContainer.classList.add('hidden');
      statusElement.textContent = 'Please enter a username to join the chat';
      document.getElementById('usernameInput').value = username || '';
      document.getElementById('usernameInput')?.focus();
    }
  }
};

socket.onmessage = async (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === 'token') {
    token = msg.token;
    refreshToken = msg.refreshToken;
    startKeepAlive();
    if (pendingJoin) {
      socket.send(JSON.stringify({ type: 'join', ...pendingJoin, token }));
      pendingJoin = null;
    } else if (pendingCode) {
      socket.send(JSON.stringify({ type: 'join', code: pendingCode, clientId, username, token }));
      pendingCode = null;
    }
  } else if (msg.type === 'refresh-token') {
    token = msg.token;
    refreshToken = msg.refreshToken;
    refreshingToken = false;
  } else if (msg.type === 'init') {
    code = msg.code;
    isInitiator = true;
    maxClients = msg.maxClients;
    totalClients = 1;
    usernames.set(clientId, username);
    roomMaster = new Uint8Array(msg.roomMaster);
    signingKey = await deriveSigningKey(roomMaster);
    await resetChains();
    codeDisplayElement.textContent = code;
    codeDisplayElement.classList.remove('hidden');
    copyCodeButton.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    initialContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.remove('hidden');
    newSessionButton.classList.remove('hidden');
    maxClientsContainer.classList.remove('hidden');
    inputContainer.classList.remove('hidden');
    messages.classList.remove('waiting');
    statusElement.textContent = 'Waiting for others to join...';
    updateDots();
    initializeMaxClientsUI();
    updateMaxClientsUI();
    document.getElementById('messageInput')?.focus();
  } else if (msg.type === 'joined') {
    isInitiator = msg.isInitiator;
    maxClients = msg.maxClients;
    totalClients = msg.totalClients;
    useRelay = msg.useRelay;
    if (!isInitiator) {
      initiatorPublic = msg.initiatorPublic;
    }
    roomMaster = new Uint8Array(msg.roomMaster);
    signingKey = await deriveSigningKey(roomMaster);
    await resetChains();
    codeDisplayElement.textContent = code;
    codeDisplayElement.classList.remove('hidden');
    copyCodeButton.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    initialContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.remove('hidden');
    inputContainer.classList.remove('hidden');
    messages.classList.remove('waiting');
    statusElement.textContent = `Connected (${totalClients}/${maxClients} connections)`;
    updateDots();
    initializeMaxClientsUI();
    updateMaxClientsUI();
    document.getElementById('messageInput')?.focus();
  } else if (msg.type === 'user-joined') {
    totalClients = msg.totalClients;
    usernames.set(msg.clientId, msg.username);
    connectedClients.add(msg.clientId);
    if (isInitiator) {
      clientPublicKeys.set(msg.clientId, msg.publicKey);
    }
    statusElement.textContent = `Connected (${totalClients}/${maxClients} connections)`;
    updateDots();
    showStatusMessage(`${msg.username} joined the chat.`);
  } else if (msg.type === 'user-left') {
    totalClients = msg.totalClients;
    usernames.delete(msg.clientId);
    connectedClients.delete(msg.clientId);
    if (isInitiator) {
      clientPublicKeys.delete(msg.clientId);
    }
    cleanupPeerConnection(msg.clientId);
    statusElement.textContent = `Connected (${totalClients}/${maxClients} connections)`;
    updateDots();
    showStatusMessage(`${msg.username} left the chat.`);
  } else if (msg.type === 'offer') {
    // Handle offer, create answer, etc. (original WebRTC logic, truncated in original)
  } else if (msg.type === 'answer') {
    // Handle answer (truncated)
  } else if (msg.type === 'candidate') {
    // Handle ICE candidate (truncated)
  } else if (msg.type === 'relay') {
    // Handle relay messages, decrypt if needed, then pass to handleReceivedMessage
    const { encryptedData, iv, salt, signature, messageId } = msg;
    if (processedMessageIds.has(messageId)) return;
    processedMessageIds.add(messageId);
    const verified = await verifyMessage(signingKey, signature, encryptedData);
    if (!verified) {
      showStatusMessage('Invalid signature on relayed message.');
      return;
    }
    try {
      const decrypted = await decrypt(encryptedData, iv, salt, roomMaster);
      const innerMsg = JSON.parse(decrypted);
      await handleReceivedMessage(innerMsg);
    } catch (e) {
      showStatusMessage('Failed to decrypt relayed message.');
    }
  } else if (msg.type === 'features') {
    features = msg.features;
    // Update UI toggles if needed
  } else if (msg.type === 'error') {
    showStatusMessage(msg.message);
  }
};

socket.onclose = () => {
  console.log('WebSocket closed');
  stopKeepAlive();
  if (reconnectAttempts < maxReconnectAttempts) {
    reconnectAttempts++;
    setTimeout(() => {
      socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
      // Re-attach event listeners (onopen, onmessage, etc.)
    }, 1000 * reconnectAttempts);
  } else {
    showStatusMessage('Connection lost. Please refresh the page.');
  }
};

document.getElementById('startChatButton').onclick = () => {
  if (!username || !validateUsername(username)) {
    usernameContainer.classList.remove('hidden');
    initialContainer.classList.add('hidden');
    statusElement.textContent = 'Please enter a username to start the chat';
    document.getElementById('usernameInput').value = username || '';
    document.getElementById('usernameInput')?.focus();
    return;
  }
  if (socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({ type: 'init', clientId, username, token }));
  } else {
    pendingJoin = { clientId, username }; // For init, no code
  }
};

document.getElementById('joinChatButton').onclick = () => {
  connectContainer.classList.remove('hidden');
  initialContainer.classList.add('hidden');
  document.getElementById('codeInput')?.focus();
};

document.getElementById('joinWithUsernameButton').onclick = () => {
  const usernameInput = document.getElementById('usernameInput').value.trim();
  if (!validateUsername(usernameInput)) {
    showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
    return;
  }
  username = usernameInput;
  localStorage.setItem('username', username);
  usernameContainer.classList.add('hidden');
  initialContainer.classList.remove('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
};

document.getElementById('connectButton').onclick = () => {
  const codeInput = document.getElementById('codeInput').value.trim();
  if (!validateCode(codeInput)) {
    showStatusMessage('Invalid code format: xxxx-xxxx-xxxx-xxxx');
    return;
  }
  code = codeInput;
  if (socket.readyState === WebSocket.OPEN && token) {
    socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  } else {
    pendingJoin = { code, clientId, username };
  }
  connectContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for connection...';
};

document.getElementById('copyCodeButton').onclick = () => {
  navigator.clipboard.writeText(code).then(() => {
    showStatusMessage('Code copied to clipboard.');
  });
};

document.getElementById('newSessionButton').onclick = () => {
  location.reload();
};

document.getElementById('button1').onclick = () => {
  if (isInitiator && code && token && totalClients < maxClients) {
    socket.send(JSON.stringify({ type: 'send-to-random', code, clientId, token }));
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
      // Restore original onclick if needed
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
