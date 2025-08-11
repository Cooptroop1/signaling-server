// Utility to show temporary status messages
 function showStatusMessage(message, duration = 3000) {
 if (typeof statusElement !== 'undefined' && statusElement) {
 statusElement.textContent = message;
 statusElement.setAttribute('aria-live', 'assertive');
 setTimeout(() => {
 statusElement.textContent = isConnected ? `Connected (${totalClients}/${maxClients} connections)` : 'Waiting for connection...';
 statusElement.setAttribute('aria-live', 'polite');
 }, duration);
 }
 }

 // Sanitize message content to prevent XSS
 function sanitizeMessage(content) {
 const div = document.createElement('div');
 div.textContent = content;
 return div.innerHTML.replace(/</g, '&lt;').replace(/>/g, '&gt;');
 }

 function generateMessageId() {
 return Math.random().toString(36).substr(2, 9);
 }

 function validateUsername(username) {
 const regex = /^[a-zA-Z0-9]{1,16}$/;
 return username && regex.test(username);
 }

 function validateCode(code) {
 const regex = /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/;
 return code && regex.test(code);
 }

 // Keepalive timer ID
 let keepAliveTimer = null; // Moved from events.js to utils.js
 // Keepalive function to prevent WebSocket timeout
 function startKeepAlive() {
 if (keepAliveTimer) clearInterval(keepAliveTimer);
 keepAliveTimer = setInterval(() => {
 if (typeof socket !== 'undefined' && socket.readyState === WebSocket.OPEN) {
 socket.send(JSON.stringify({ type: 'ping', clientId, token }));
 log('info', 'Sent keepalive ping');
 }
 }, 20000);
 }

 function stopKeepAlive() {
 if (keepAliveTimer) {
 clearInterval(keepAliveTimer);
 keepAliveTimer = null;
 log('info', 'Stopped keepalive');
 }
 }

 let ratchets = new Map(); // Moved to utils.js

 const HKDF = async (key, salt, info) => {
  const hkdfKey = await window.crypto.subtle.importKey('raw', key, { name: 'HKDF' }, false, ['deriveKey']);
  return await window.crypto.subtle.deriveKey({ name: 'HKDF', salt, info: new TextEncoder().encode(info), hash: 'SHA-256' }, hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
 };

 async function initRatchet(targetId, sharedKey) {
  const root = await HKDF(sharedKey, new Uint8Array(), 'root');
  const send = await HKDF(root, new Uint8Array(), 'send');
  const recv = await HKDF(root, new Uint8Array(), 'recv');
  ratchets.set(targetId, { sendKey: send, recvKey: recv, sendCount: 0, recvCount: 0 });
  console.log('Ratchet initialized for', targetId);
 }

 async function ratchetEncrypt(targetId, plaintext) {
  const ratchet = ratchets.get(targetId);
  const msgKey = await HKDF(ratchet.sendKey, new Uint8Array(), 'msg' + ratchet.sendCount);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, msgKey, plaintext);
  ratchet.sendKey = await HKDF(ratchet.sendKey, new Uint8Array(), 'chain');
  ratchet.sendCount++;
  return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv) };
 }

 async function ratchetDecrypt(targetId, encrypted, iv) {
  const ratchet = ratchets.get(targetId);
  const msgKey = await HKDF(ratchet.recvKey, new Uint8Array(), 'msg' + ratchet.recvCount);
  const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToArrayBuffer(iv) }, msgKey, base64ToArrayBuffer(encrypted));
  ratchet.recvKey = await HKDF(ratchet.recvKey, new Uint8Array(), 'chain');
  ratchet.recvCount++;
  return decrypted;
 }

 function cleanupPeerConnection(targetId) {
 const peerConnection = peerConnections.get(targetId);
 const dataChannel = dataChannels.get(targetId);
 if (dataChannel && dataChannel.readyState === 'open') {
 log('info', `Skipping cleanup for ${targetId}: data channel is open`);
 return;
 }
 if (peerConnection) {
 peerConnection.close();
 peerConnections.delete(targetId);
 }
 if (dataChannel) {
 dataChannel.close();
 dataChannels.delete(targetId);
 }
 candidatesQueues.delete(targetId);
 clearTimeout(connectionTimeouts.get(targetId));
 connectionTimeouts.delete(targetId);
 retryCounts.delete(targetId);
 messageRateLimits.delete(targetId);
 imageRateLimits.delete(targetId);
 voiceRateLimits.delete(targetId);
 if (ratchets.has(targetId)) ratchets.delete(targetId);
 if (remoteAudios.has(targetId)) {
 const audio = remoteAudios.get(targetId);
 audio.remove();
 remoteAudios.delete(targetId);
 if (remoteAudios.size === 0) {
 document.getElementById('remoteAudioContainer').classList.add('hidden');
 }
 }
 isConnected = dataChannels.size > 0;
 if (typeof isInitiator !== 'undefined') {
 updateMaxClientsUI();
 }
 if (!isConnected) {
 if (inputContainer) inputContainer.classList.add('hidden');
 if (messages) messages.classList.add('waiting');
 }
 }

 let isInitiator = false; // Global to fix not defined

 function initializeMaxClientsUI() {
 if (typeof isInitiator === 'undefined') {
 log('error', 'isInitiator is not defined, skipping UI initialization');
 showStatusMessage('Error: UI initialization failed.');
 return;
 }
 log('info', `initializeMaxClientsUI called, isInitiator: ${isInitiator}`);
 const addUserText = document.getElementById('addUserText');
 const addUserModal = document.getElementById('addUserModal');
 const addUserRadios = document.getElementById('addUserRadios');
 if (addUserText && addUserModal && addUserRadios) {
 addUserText.classList.toggle('hidden', !isInitiator);
 if (isInitiator) {
 log('info', `Creating buttons for maxClients in modal, current maxClients: ${maxClients}`);
 addUserRadios.innerHTML = '';
 for (let n = 2; n <= 10; n++) {
 const button = document.createElement('button');
 button.textContent = n;
 button.setAttribute('aria-label', `Set maximum users to ${n}`);
 button.className = n === maxClients ? 'active' : '';
 button.disabled = !isInitiator;
 button.addEventListener('click', () => {
 if (isInitiator) {
 log('info', `Button clicked for maxClients: ${n}`);
 setMaxClients(n);
 document.querySelectorAll('#addUserRadios button').forEach(btn => btn.classList.remove('active'));
 button.classList.add('active');
 addUserModal.classList.remove('active');
 }
 });
 addUserRadios.appendChild(button);
 }
 log('info', 'Buttons appended to addUserRadios');
 } else {
 log('info', 'Hiding addUserText for non-initiator');
 }
 } else {
 log('error', 'Add user modal elements not found');
 showStatusMessage('Error: UI initialization failed.');
 }
 }

 function updateMaxClientsUI() {
 if (typeof isInitiator === 'undefined') {
 log('error', 'isInitiator is not defined, skipping UI update');
 return;
 }
 log('info', `updateMaxClientsUI called, maxClients: ${maxClients}, isInitiator: ${isInitiator}`);
 if (statusElement) {
 statusElement.textContent = isConnected ? `Connected (${totalClients}/${maxClients} connections)` : 'Waiting for connection...';
 }
 const addUserText = document.getElementById('addUserText');
 if (addUserText) {
 addUserText.classList.toggle('hidden', !isInitiator);
 }
 const buttons = document.querySelectorAll('#addUserRadios button');
 log('info', `Found buttons in modal: ${buttons.length}`);
 buttons.forEach(button => {
 const value = parseInt(button.textContent);
 button.classList.toggle('active', value === maxClients);
 button.disabled = !isInitiator;
 });
 if (messages) {
 if (!isConnected) {
 messages.classList.add('waiting');
 } else {
 messages.classList.remove('waiting');
 }
 }
 // Update user dots
 const userDots = document.getElementById('userDots');
 if (userDots) {
 userDots.innerHTML = '';
 // Add green dots for online users
 for (let i = 0; i < totalClients; i++) {
 const dot = document.createElement('div');
 dot.className = 'user-dot online';
 userDots.appendChild(dot);
 }
 // Add red dots for offline slots
 for (let i = 0; i < (maxClients - totalClients); i++) {
 const dot = document.createElement('div');
 dot.className = 'user-dot offline';
 userDots.appendChild(dot);
 }
 }
 }

 function setMaxClients(n) {
 if (isInitiator && clientId && socket.readyState === WebSocket.OPEN && token) {
 maxClients = Math.min(n, 10);
 log('info', `setMaxClients called with n: ${n}, new maxClients: ${maxClients}`);
 socket.send(JSON.stringify({ type: 'set-max-clients', maxClients: maxClients, code, clientId, token }));
 updateMaxClientsUI();
 } else {
 log('warn', 'setMaxClients failed: not initiator, no token, or socket not open');
 }
 }

 function log(level, ...msg) {
 const timestamp = new Date().toISOString();
 const fullMsg = `[${timestamp}] ${msg.join(' ')}`;
 if (level === 'error') {
 console.error(fullMsg);
 } else if (level === 'warn') {
 console.warn(fullMsg);
 } else {
 console.log(fullMsg);
 }
 }

 function createImageModal(base64, focusId) {
 let modal = document.getElementById('imageModal');
 if (!modal) {
 modal = document.createElement('div');
 modal.id = 'imageModal';
 modal.className = 'modal';
 modal.setAttribute('role', 'dialog');
 modal.setAttribute('aria-label', 'Image viewer');
 modal.setAttribute('tabindex', '-1');
 document.body.appendChild(modal);
 }
 modal.innerHTML = '';
 const modalImg = document.createElement('img');
 modalImg.src = base64;
 modalImg.setAttribute('alt', 'Enlarged image');
 modal.appendChild(modalImg);
 modal.classList.add('active');
 modal.focus();
 modal.addEventListener('click', () => {
 modal.classList.remove('active');
 document.getElementById(focusId)?.focus();
 });
 modal.addEventListener('keydown', (event) => {
 if (event.key === 'Escape') {
 modal.classList.remove('active');
 document.getElementById(focusId)?.focus();
 }
 });
 }

 function createAudioModal(base64, focusId) {
 let modal = document.getElementById('audioModal');
 if (!modal) {
 modal = document.createElement('div');
 modal.id = 'audioModal';
 modal.className = 'modal';
 modal.setAttribute('role', 'dialog');
 modal.setAttribute('aria-label', 'Audio player');
 modal.setAttribute('tabindex', '-1');
 document.body.appendChild(modal);
 }
 modal.innerHTML = '';
 const audio = document.createElement('audio');
 audio.src = base64;
 audio.controls = true;
 audio.setAttribute('alt', 'Voice message');
 modal.appendChild(audio);
 modal.classList.add('active');
 modal.focus();
 modal.addEventListener('click', () => {
 modal.classList.remove('active');
 document.getElementById(focusId)?.focus();
 });
 modal.addEventListener('keydown', (event) => {
 if (event.key === 'Escape') {
 modal.classList.remove('active');
 document.getElementById(focusId)?.focus();
 }
 });
 }

 function arrayBufferToBase64(buffer) {
 return btoa(String.fromCharCode(...new Uint8Array(buffer)));
 }

 function base64ToArrayBuffer(base64) {
 const binary = atob(base64);
 const bytes = new Uint8Array(binary.length);
 for (let i = 0; i < binary.length; i++) {
 bytes[i] = binary.charCodeAt(i);
 }
 return bytes.buffer;
 }

 async function encodeAudioToMp3(audioBlob) {
 const arrayBuffer = await audioBlob.arrayBuffer();
 const audioContext = new (window.AudioContext || window.webkitAudioContext)();
 const audioBuffer = await audioContext.decodeAudioData(arrayBuffer);
 const channelData = audioBuffer.getChannelData(0);
 const sampleRate = audioBuffer.sampleRate;
 const mp3encoder = new lamejs.Mp3Encoder(1, sampleRate, 96); // 96kbps
 const mp3Data = [];
 const sampleBlockSize = 1152;
 for (let i = 0; i < channelData.length; i += sampleBlockSize) {
 const samples = channelData.subarray(i, i + sampleBlockSize);
 const sampleInt16 = new Int16Array(samples.length);
 for (let j = 0; j < samples.length; j++) {
 sampleInt16[j] = samples[j] * 32767;
 }
 const mp3buf = mp3encoder.encodeBuffer(sampleInt16);
 if (mp3buf.length > 0) {
 mp3Data.push(mp3buf);
 }
 }
 const endBuf = mp3encoder.flush();
 if (endBuf.length > 0) {
 mp3Data.push(endBuf);
 }
 const mp3Blob = new Blob(mp3Data, { type: 'audio/mp3' });
 return mp3Blob;
 }

 async function exportPublicKey(key) {
 const exported = await window.crypto.subtle.exportKey('raw', key);
 return arrayBufferToBase64(exported);
 }

 async function importPublicKey(base64) {
 return window.crypto.subtle.importKey(
 'raw',
 base64ToArrayBuffer(base64),
 { name: 'ECDH', namedCurve: 'P-256' },
 true,
 []
 );
 }

 async function deriveSharedKey(privateKey, publicKey) {
 const sharedBits = await window.crypto.subtle.deriveBits(
 { name: 'ECDH', public: publicKey },
 privateKey,
 256
 );
 return await window.crypto.subtle.importKey(
 "raw",
 sharedBits,
 "AES-GCM",
 false,
 ["encrypt", "decrypt"]
 );
 }

 // Relay mode encryption (kept for fallback)
 async function encrypt(text, master) {
 const salt = window.crypto.getRandomValues(new Uint8Array(16));
 const hkdfKey = await window.crypto.subtle.importKey(
 'raw',
 master,
 { name: 'HKDF' },
 false,
 ['deriveKey']
 );
 const derivedKey = await window.crypto.subtle.deriveKey(
 { name: 'HKDF', salt, info: new Uint8Array(0), hash: 'SHA-256' },
 hkdfKey,
 { name: 'AES-GCM', length: 256 },
 false,
 ['encrypt', 'decrypt']
 );
 const iv = window.crypto.getRandomValues(new Uint8Array(12));
 const encoded = new TextEncoder().encode(text);
 const encrypted = await window.crypto.subtle.encrypt(
 { name: 'AES-GCM', iv },
 derivedKey,
 encoded
 );
 return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv), salt: arrayBufferToBase64(salt) };
 }

 async function decrypt(encrypted, iv, salt, master) {
 const hkdfKey = await window.crypto.subtle.importKey(
 'raw',
 master,
 { name: 'HKDF' },
 false,
 ['deriveKey']
 );
 const derivedKey = await window.crypto.subtle.deriveKey(
 { name: 'HKDF', salt: base64ToArrayBuffer(salt), info: new Uint8Array(0), hash: 'SHA-256' },
 hkdfKey,
 { name: 'AES-GCM', length: 256 },
 false,
 ['encrypt', 'decrypt']
 );
 const decoded = await window.crypto.subtle.decrypt(
 { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
 derivedKey,
 base64ToArrayBuffer(encrypted)
 );
 return new TextDecoder().decode(decoded);
 }

 async function encryptBytes(key, data) {
 const iv = window.crypto.getRandomValues(new Uint8Array(12));
 const encrypted = await window.crypto.subtle.encrypt(
 { name: 'AES-GCM', iv },
 key,
 data
 );
 return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv) };
 }

 async function decryptBytes(key, encrypted, iv) {
 return window.crypto.subtle.decrypt(
 { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
 key,
 base64ToArrayBuffer(encrypted)
 );
 }

 async function encryptRaw(key, data) {
 const iv = window.crypto.getRandomValues(new Uint8Array(12));
 const encoded = new TextEncoder().encode(data); // Encode string to bytes
 const encrypted = await window.crypto.subtle.encrypt(
 { name: 'AES-GCM', iv },
 key,
 encoded
 );
 return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv) };
 }

 async function signMessage(signingKey, data) {
 const encoded = new TextEncoder().encode(data);
 return arrayBufferToBase64(await window.crypto.subtle.sign(
 { name: 'HMAC' },
 signingKey,
 encoded
 ));
 }

 async function verifyMessage(signingKey, signature, data) {
 const encoded = new TextEncoder().encode(data);
 return await window.crypto.subtle.verify(
 { name: 'HMAC' },
 signingKey,
 base64ToArrayBuffer(signature),
 encoded
 );
 }

 async function deriveSigningKey(master) {
 const hkdfKey = await window.crypto.subtle.importKey(
 'raw',
 master,
 { name: 'HKDF' },
 false,
 ['deriveKey']
 );
 return await window.crypto.subtle.deriveKey(
 { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('signing'), hash: 'SHA-256' },
 hkdfKey,
 { name: 'HMAC', hash: 'SHA-256' },
 false,
 ['sign', 'verify']
 );
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
