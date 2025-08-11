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
let roomMaster;
let signingKey; // New: Cached signing key for HMAC in relay
let remoteAudios = new Map();
let refreshingToken = false;
let signalingQueue = new Map();
let connectedClients = new Set(); // Track connected client IDs
let identity; // Ratchet identity
let ciphers = new Map(); // Per targetId AsymmetricRatchet
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
let mediaRecorder = null;
let voiceTimerInterval = null;
const maxReconnectAttempts = 5; // Limit reconnect attempts
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
 console.error('WebSocket closed, attempting reconnect');
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
 showStatusMessage('Session expired. Reconnecting...');
 token = '';
 refreshToken = '';
 socket.close();
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
 roomMaster = null;
 signingKey = null;
 }
 updateMaxClientsUI();
 turnUsername = message.turnUsername;
 turnCredential = message.turnCredential;
 if (message.existingClients) {
 message.existingClients.forEach(id => {
 const isOfferer = clientId > id;
 startPeerConnection(id, isOfferer);
 });
 }
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
 if (voiceCallActive) {
 renegotiate(message.clientId);
 }
 }
 if (message.type === 'client-disconnected') {
 totalClients = message.totalClients;
 console.log(`Client ${message.clientId} disconnected from code: ${code}, total: ${totalClients}`);
 usernames.delete(message.clientId);
 connectedClients.delete(message.clientId);
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
 if (message.type === 'prekey-bundle') {
 try {
 const bundleBuf = base64ToArrayBuffer(message.bundle);
 const bundle = await DKeyRatchet.PreKeyBundleProtocol.importProto(bundleBuf);
 const cipher = await DKeyRatchet.AsymmetricRatchet.create(identity, bundle);
 ciphers.set(message.clientId, cipher);
 const initMsg = await cipher.encrypt(new Uint8Array(0));
 const proto = await initMsg.exportProto();
 const protoB64 = arrayBufferToBase64(proto);
 sendSignalingMessage('prekey-message', { proto: protoB64, targetId: message.clientId });
 } catch (error) {
 console.error('Error handling prekey-bundle:', error);
 showStatusMessage('Key exchange failed.');
 }
 }
 if (message.type === 'prekey-message') {
 try {
 const protoBuf = base64ToArrayBuffer(message.proto);
 const proto = await DKeyRatchet.PreKeyMessageProtocol.importProto(protoBuf);
 const cipher = await DKeyRatchet.AsymmetricRatchet.create(identity, proto);
 await cipher.decrypt(proto.signedMessage); // Expect empty
 ciphers.set(message.clientId, cipher);
 console.log(`Ratchet session established with ${message.clientId}`);
 } catch (error) {
 console.error('Error handling prekey-message:', error);
 showStatusMessage('Failed to establish secure session.');
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
 token = '';
 refreshToken = '';
 socket.close();
 }
 }
 } catch (error) {
 console.error('Error parsing message:', error, 'Raw data:', event.data);
 }
};

// Initialize identity on DOM load
document.addEventListener('DOMContentLoaded', async () => {
  identity = await createIdentity();
  // ... (rest of your original DOMContentLoaded code)
});

// ... (rest of your events code, including button onclicks, etc.)
