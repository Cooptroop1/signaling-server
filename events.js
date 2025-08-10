// Reconnection attempt counter for exponential backoff
 let reconnectAttempts = 0;
 // Image rate limiting
 const imageRateLimits = new Map();
 // Voice rate limiting
 const voiceRateLimits = new Map();
 // Global message rate limit (shared for DoS mitigation)
 let globalMessageRate = { count: 0, startTime: Date.now() };
 // Define generateCode locally
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
    { name: 'ECDH', namedCurve: 'P-256' },
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
   setTimeout(() => triggerCycle(), 60000);
  }
  setTimeout(() => triggerCycle(), 60000);
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
 let pendingCode = null;
 let pendingJoin = null;
 let mediaRecorder = null;
 let voiceTimerInterval = null;
 const maxReconnectAttempts = 5; // Limit reconnect attempts
 socket.onopen = () => {
  console.log('WebSocket opened');
  socket.send(JSON.stringify({ type: 'connect', clientId }));
  startKeepAlive();
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
   codeDisplayElement.classList.add('hidden');
   copyCodeButton.classList.add('hidden');
   statusElement.textContent = 'Start a new chat or connect to an existing one';
  }
 };
 socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  showStatusMessage('Connection error, please try again later.');
  stopKeepAlive();
  connectionTimeouts.forEach((timeout) => clearTimeout(timeout));
 };
 socket.onclose = () => {
  console.error('WebSocket closed, attempting reconnect');
  stopKeepAlive();
  showStatusMessage('Lost connection, reconnecting...');
  if (reconnectAttempts >= maxReconnectAttempts) {
   showStatusMessage('Max reconnect attempts reached. Please refresh the page.', 10000);
   return;
  }
  const delay = Math.min(30000, 5000 * Math.pow(2, reconnectAttempts));
  reconnectAttempts++;
  setTimeout(() => {
   socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
   socket.onopen = () => {
    console.log('Reconnected, sending connect');
    socket.send(JSON.stringify({ type: 'connect', clientId }));
    startKeepAlive();
    if (code && username && validateCode(code) && validateUsername(username)) {
     console.log('Rejoining with code:', code);
     socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
    }
   };
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
   if (message.type === 'pong') {
    console.log('Received keepalive pong');
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
    console.error('Server error:', message.message);
    if (message.message.includes('Invalid or expired token') || message.message.includes('Missing authentication token')) {
     // Silently handle token refresh without showing message
     if (refreshToken && !refreshingToken) {
      refreshingToken = true;
      console.log('Attempting to refresh token');
      socket.send(JSON.stringify({ type: 'refresh-token', clientId, refreshToken }));
     } else {
      console.error('No refresh token available or refresh in progress, forcing reconnect');
      stopKeepAlive();
      socket.close();
     }
    } else if (message.message.includes('Token revoked') || message.message.includes('Invalid or expired refresh token')) {
     showStatusMessage('Session expired. Reconnecting...');
     stopKeepAlive();
     token = '';
     refreshToken = '';
     socket.close();
    } else if (message.message.includes('Rate limit exceeded')) {
     showStatusMessage('Rate limit exceeded. Waiting before retrying...');
     stopKeepAlive();
     setTimeout(() => {
      if (reconnectAttempts < maxReconnectAttempts) {
       socket.send(JSON.stringify({ type: 'connect', clientId }));
       startKeepAlive();
      }
     }, 60000);
    } else if (message.message.includes('Chat is full') || message.message.includes('Username already taken') || message.message.includes('Initiator offline')) {
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
     stopKeepAlive();
     token = ''; // Clear token
     refreshToken = ''; // Clear refresh token
     showStatusMessage(message.message);
    } else {
     showStatusMessage(message.message);
    }
    return;
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
     isConnected = true;
     roomMaster = window.crypto.getRandomValues(new Uint8Array(32));
     signingKey = await deriveSigningKey(roomMaster);
    } else {
     const publicKey = await exportPublicKey(keyPair.publicKey);
     socket.send(JSON.stringify({ type: 'public-key', publicKey, clientId, code, token }));
    }
    updateMaxClientsUI();
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
    if (isInitiator && message.clientId !== clientId && !peerConnections.has(message.clientId)) {
     console.log(`Initiating peer connection with client ${message.clientId}`);
     startPeerConnection(message.clientId, true);
    }
    if (voiceCallActive) {
     renegotiate(message.clientId);
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
    if (totalClients <= 1) {
     inputContainer.classList.add('hidden');
     messages.classList.add('waiting');
    }
   }
   if (message.type === 'max-clients') {
    maxClients = Math.min(message.maxClients, 10);
    console.log(`Max clients updated to ${maxClients} for code: ${code}`);
    updateMaxClientsUI();
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
    } catch (error) {
     console.error('Error handling new-room-key:', error);
     showStatusMessage('Failed to update encryption key for PFS.');
    }
   }
   if ((message.type === 'message' || message.type === 'image' || message.type === 'voice') && useRelay) {
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
     showStatusMessage('Service disabled by admin. Disconnecting...');
     stopKeepAlive();
     token = '';
     refreshToken = '';
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
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  messages.classList.remove('waiting');
  stopKeepAlive();
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
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  messages.classList.remove('waiting');
  stopKeepAlive();
  document.getElementById('connectToggleButton')?.focus();
 };
 document.getElementById('sendButton').onclick = () => {
  const messageInput = document.getElementById('messageInput');
  const message = messageInput.value.trim();
  if (message) {
   sendMessage(message);
  }
 };
 document.getElementById('imageButton').onclick = () => {
  document.getElementById('imageInput')?.click();
 };
 document.getElementById('imageInput').onchange = (event) => {
  const file = event.target.files[0];
  if (file) {
   sendMedia(file, 'image');
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
 document.getElementById('grokButton').onclick = () => {
  toggleGrokBot();
 };
 document.getElementById('saveGrokKey').onclick = () => {
  saveGrokKey();
 };
 function startVoiceRecording() {
  if (window.location.protocol !== 'https:') {
   console.error('Insecure context: HTTPS required for microphone access');
   showStatusMessage('Error: Microphone access requires HTTPS. Please load the site over a secure connection.');
   document.getElementById('voiceButton')?.focus();
   return;
  }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
   console.error('Microphone not supported');
   showStatusMessage('Error: Microphone not supported by your browser or device or device.');
   document.getElementById('voiceButton')?.focus();
   return;
  }
  navigator.mediaDevices.getUserMedia({ audio: true })
  .then(stream => {
   mediaRecorder = new MediaRecorder(stream);
   const chunks = [];
   let startTime = Date.now();
   mediaRecorder.ondataavailable = (event) => {
    if (event.data.size > 0) {
     chunks.push(event.data);
    }
   };
   mediaRecorder.onstop = async () => {
    const blob = new Blob(chunks, { type: 'audio/webm' });
    stream.getTracks().forEach(track => track.stop());
    clearInterval(voiceTimerInterval);
    document.getElementById('voiceTimer').style.display = 'none';
    document.getElementById('voiceButton').classList.remove('recording');
    document.getElementById('voiceButton').textContent = '🎤';
    if (blob.size > 0) {
     await sendMedia(blob, 'voice');
    } else {
     showStatusMessage('Error: No audio recorded.');
    }
   };
   mediaRecorder.start();
   document.getElementById('voiceButton').classList.add('recording');
   document.getElementById('voiceButton').textContent = '⏹';
   document.getElementById('voiceTimer').style.display = 'flex';
   document.getElementById('voiceTimer').textContent = '0:00';
   voiceTimerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    if (elapsed >= 30) {
     mediaRecorder.stop();
     return;
    }
    const minutes = Math.floor(elapsed / 60);
    const seconds = elapsed % 60;
    document.getElementById('voiceTimer').textContent = `${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;
   }, 1000);
  })
  .catch(error => {
   console.error('Error accessing microphone:', error.name, error.message);
   if (error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError') {
    showStatusMessage('Error: Microphone permission denied. Please enable in browser or device settings.');
   } else if (error.name === 'NotFoundError') {
    showStatusMessage('Error: No microphone found on device.');
   } else if (error.name === 'NotReadableError') {
    showStatusMessage('Error: Microphone hardware error or in use by another app.');
   } else if (error.name === 'SecurityError') {
    showStatusMessage('Error: Insecure context. Ensure site is loaded over HTTPS.');
   } else {
    showStatusMessage('Error: Could not access microphone. Check permissions and device support.');
   }
   document.getElementById('voiceButton')?.focus();
  });
 }
 function stopVoiceRecording() {
  if (mediaRecorder && mediaRecorder.state === 'recording') {
   mediaRecorder.stop();
  }
 }
 const messageInput = document.getElementById('messageInput');
 messageInput.addEventListener('input', () => {
  messageInput.style.height = '2.5rem';
  messageInput.style.height = `${Math.min(messageInput.scrollHeight, 12.5 * 16)}px`;
 });
 messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
   event.preventDefault();
   const message = event.target.value.trim();
   if (message) {
    sendMessage(message);
   }
  }
 });
 document.getElementById('newSessionButton').onclick = () => {
  console.log('New session button clicked');
  socket.send(JSON.stringify({ type: 'leave', code, clientId, token }));
  peerConnections.forEach((pc) => pc.close());
  dataChannels.forEach((dc) => dc.close());
  peerConnections.clear();
  dataChannels.clear();
  candidatesQueues.clear();
  connectionTimeouts.clear();
  retryCounts.clear();
  processedMessageIds.clear();
  usernames.clear();
  messageRateLimits.clear();
  imageRateLimits.clear();
  voiceRateLimits.clear();
  connectedClients.clear(); // Clear on new session
  clientPublicKeys.clear();
  initiatorPublic = undefined;
  isConnected = false;
  isInitiator = false;
  maxClients = 2;
  totalClients = 0;
  code = generateCode();
  codeDisplayElement.textContent = '';
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  document.getElementById('messages').innerHTML = '';
  document.getElementById('messageInput').value = '';
  document.getElementById('messageInput').style.height = '2.5rem';
  document.getElementById('usernameInput').value = '';
  document.getElementById('usernameConnectInput').value = '';
  document.getElementById('codeInput').value = '';
  initialContainer.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  newSessionButton.classList.add('hidden');
  maxClientsContainer.classList.add('hidden');
  inputContainer.classList.add('hidden');
  messages.classList.remove('waiting');
  codeSentToRandom = false;
  button2.disabled = false;
  stopKeepAlive();
  token = ''; // Clear token
  refreshToken = ''; // Clear refresh token
  // Clear localStorage and cookies for data minimization
  localStorage.removeItem('username');
  document.cookie = 'clientId=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; Secure; HttpOnly; SameSite=Strict';
  document.getElementById('startChatToggleButton')?.focus();
  // Clean up voice call
  stopVoiceCall();
  remoteAudios.forEach(audio => audio.remove());
  remoteAudios.clear();
  signalingQueue.clear();
  refreshingToken = false;
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
 // Helper functions for cookies
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
