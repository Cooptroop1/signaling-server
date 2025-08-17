// main.js
// Core logic: peer connections, message sending, handling offers, etc.
let turnUsername = '';
let turnCredential = '';
let localStream = null;
let voiceCallActive = false;
let grokBotActive = false;
let grokApiKey = localStorage.getItem('grokApiKey') || '';
// New: Flag to prevent concurrent renegotiations
let renegotiating = new Map(); // Per targetId
// New: Track audio output mode
let audioOutputMode = 'earpiece'; // Default to earpiece
// New: TOTP state
let totpEnabled = false;
let totpSecret = '';
let pendingTotpSecret = null; // New: For delaying set-totp until after init
let mediaRecorder = null;
let voiceChunks = [];
let voiceTimerInterval = null;
// New: Message counter for ratchet triggering
let messageCount = 0;

// New: Max skips for ratchet forward to prevent DoS
const MAX_RATCHET_SKIP = 100;

// Assume in onmessage or join success, call resetChains();

// Updated: Encrypt using ratchet
async function ratchetEncrypt(payloadJson) {
  if (!sendingChainKey) {
    throw new Error('Chain key not initialized');
  }
  const { msgKey, nextChainKey } = await deriveMessageKeyAndNextChain(sendingChainKey);
  sendingChainKey = nextChainKey;
  sendingSeq++;
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(payloadJson);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    msgKey,
    encoded
  );
  return { encrypted: arrayBufferToBase64(encrypted), iv: arrayBufferToBase64(iv), seq: sendingSeq };
}

// New: Decrypt using ratchet
async function ratchetDecrypt(sender, seq, encrypted, iv, messageEpoch) {
  if (messageEpoch !== epoch) {
    throw new Error(`Epoch mismatch: received ${messageEpoch}, current ${epoch}`);
  }
  let chainKey = receivingChainKeys.get(sender);
  if (!chainKey) {
    chainKey = await deriveChainKey(roomMaster, sender);
    receivingChainKeys.set(sender, chainKey);
    receivingSeq.set(sender, 0);
  }
  let currentSeq = receivingSeq.get(sender);
  if (seq <= currentSeq) {
    throw new Error('Replay or old message');
  }
  const skips = seq - currentSeq - 1;
  if (skips > MAX_RATCHET_SKIP) {
    throw new Error('Too many skipped messages');
  }
  for (let i = 0; i < skips; i++) {
    const { msgKey: _, nextChainKey } = await deriveMessageKeyAndNextChain(chainKey);
    chainKey = nextChainKey;
  }
  const { msgKey, nextChainKey } = await deriveMessageKeyAndNextChain(chainKey);
  let decoded;
  try {
    decoded = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToArrayBuffer(iv) },
      msgKey,
      base64ToArrayBuffer(encrypted)
    );
  } catch (e) {
    throw new Error('Decryption failed');
  }
  chainKey = nextChainKey;
  receivingChainKeys.set(sender, chainKey);
  receivingSeq.set(sender, seq);
  return new TextDecoder().decode(decoded);
}

// Updated: Send media with ratchet encryption
async function sendMedia(file, type) {
  const validTypes = {
    image: ['image/jpeg', 'image/png'],
    voice: ['audio/webm', 'audio/ogg', 'audio/mp4']
  };
  // Check if feature is enabled before proceeding
  if ((type === 'image' && !features.enableImages) || (type === 'voice' && !features.enableVoice)) {
    showStatusMessage(`Error: ${type.charAt(0).toUpperCase() + type.slice(1)} messages are disabled by admin.`);
    document.getElementById(`${type}Button`)?.focus();
    return;
  }
  if (!file || (type !== 'file' && !validTypes[type]?.includes(file.type)) || !username || dataChannels.size === 0) {
    showStatusMessage(`Error: Select a ${type === 'image' ? 'JPEG/PNG image' : type === 'voice' ? 'valid audio format' : 'valid file'} and ensure you are connected.`);
    document.getElementById(`${type}Button`)?.focus();
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    showStatusMessage(`Error: ${type.charAt(0).toUpperCase() + type.slice(1)} size exceeds 5MB limit.`);
    document.getElementById(`${type}Button`)?.focus();
    return;
  }
  // Rate limiting
  const rateLimits = type === 'image' ? imageRateLimits : voiceRateLimits;
  const now = performance.now();
  const rateLimit = rateLimits.get(clientId) || { count: 0, startTime: now };
  if (now - rateLimit.startTime >= 60000) {
    rateLimit.count = 0;
    rateLimit.startTime = now;
  }
  rateLimit.count += 1;
  rateLimits.set(clientId, rateLimit);
  if (rateLimit.count > 5) {
    showStatusMessage(`${type.charAt(0).toUpperCase() + type.slice(1)} rate limit reached (5/min). Please wait.`);
    document.getElementById(`${type}Button`)?.focus();
    return;
  }
  let base64;
  if (type === 'image') {
    const maxWidth = 640;
    const maxHeight = 360;
    let quality = 0.4;
    if (file.size > 3 * 1024 * 1024) {
      quality = 0.3;
    } else if (file.size > 1 * 1024 * 1024) {
      quality = 0.35;
    }
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();
    img.src = URL.createObjectURL(file);
    await new Promise(resolve => img.onload = resolve);
    let width = img.width;
    let height = img.height;
    if (width > height) {
      if (width > maxWidth) {
        height = Math.round((height * maxWidth) / width);
        width = maxWidth;
      }
    } else {
      if (height > maxHeight) {
        width = Math.round((width * maxHeight) / height);
        height = maxHeight;
      }
    }
    canvas.width = width;
    canvas.height = height;
    ctx.drawImage(img, 0, 0, width, height);
    // Check for WebP support and use it if available
    const format = isWebPSupported() ? 'image/webp' : 'image/jpeg';
    base64 = canvas.toDataURL(format, quality);
    URL.revokeObjectURL(img.src);
  } else if (type === 'voice') {
    base64 = await new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.readAsDataURL(file);
    });
  } else { // type === 'file'
    base64 = await new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.readAsDataURL(file);
    });
  }
  const messageId = generateMessageId();
  const timestamp = Date.now();
  const innerPayload = { messageId, type, data: base64, filename: type === 'file' ? file.name : undefined, timestamp };
  const innerJson = JSON.stringify(innerPayload);
  const ratchetData = await ratchetEncrypt(innerJson);
  const outerPayload = { type: 'encrypted_msg', username, epoch, ...ratchetData };
  const outerJson = JSON.stringify(outerPayload);
  let toSend;
  if (useRelay) {
    if (!roomMaster) {
      showStatusMessage('Error: Encryption key not available for relay mode.');
      return;
    }
    const { encrypted: relayEncrypted, iv: relayIv, salt: relaySalt } = await encrypt(outerJson, roomMaster);
    const signature = await signMessage(signingKey, relayEncrypted);
    toSend = JSON.stringify({ type: `relay-${type}`, encryptedData: relayEncrypted, iv: relayIv, salt: relaySalt, messageId, signature });
    socket.send(toSend); // Assume relay send is via socket
  } else if (dataChannels.size > 0) {
    dataChannels.forEach((dataChannel) => {
      if (dataChannel.readyState === 'open') {
        dataChannel.send(outerJson);
      }
    });
  } else {
    showStatusMessage('Error: No connections.');
    return;
  }
  // Display locally
  const messages = document.getElementById('messages');
  const messageDiv = document.createElement('div');
  messageDiv.className = 'message-bubble self';
  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (type === 'image') {
    const img = document.createElement('img');
    img.src = base64;
    img.alt = 'Sent image';
    img.onclick = () => createImageModal(base64, messageDiv.id);
    messageDiv.appendChild(img);
  } else if (type === 'voice') {
    const audio = document.createElement('audio');
    audio.src = base64;
    audio.controls = true;
    messageDiv.appendChild(audio);
  } else if (type === 'file') {
    const link = document.createElement('a');
    link.href = base64;
    link.download = file.name;
    link.textContent = `Download ${file.name}`;
    messageDiv.appendChild(link);
  }
  messageDiv.appendChild(timeSpan);
  messages.appendChild(messageDiv);
  messages.scrollTop = messages.scrollHeight;
}

// Assume similar for send text, e.g., async function sendText(text) { similar to sendMedia but type='text', no file }

// Updated: In receive logic (assume in dataChannel.onmessage or socket onmessage for relay)
async function handleReceivedMessage(msgJson) {
  if (msgJson.type === 'encrypted_msg') {
    const { username: sender, epoch: msgEpoch, encrypted, iv, seq } = msgJson;
    try {
      const innerJson = await ratchetDecrypt(sender, seq, encrypted, iv, msgEpoch);
      const payload = JSON.parse(innerJson);
      // Process payload (display message, etc.)
      const { messageId, type, data, filename, timestamp } = payload;
      if (processedMessageIds.has(messageId)) return;
      processedMessageIds.add(messageId);
      const messages = document.getElementById('messages');
      const messageDiv = document.createElement('div');
      messageDiv.className = 'message-bubble other';
      const usernameSpan = document.createElement('span');
      usernameSpan.className = 'username';
      usernameSpan.textContent = sender;
      messageDiv.appendChild(usernameSpan);
      const timeSpan = document.createElement('span');
      timeSpan.className = 'timestamp';
      timeSpan.textContent = new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      if (type === 'text') {
        const textSpan = document.createElement('span');
        textSpan.innerHTML = sanitizeMessage(data);
        messageDiv.appendChild(textSpan);
      } else if (type === 'image') {
        const img = document.createElement('img');
        img.src = data;
        img.alt = 'Received image';
        img.onclick = () => createImageModal(data, messageDiv.id);
        messageDiv.appendChild(img);
      } else if (type === 'voice') {
        const audio = document.createElement('audio');
        audio.src = data;
        audio.controls = true;
        messageDiv.appendChild(audio);
      } else if (type === 'file') {
        const link = document.createElement('a');
        link.href = data;
        link.download = filename;
        link.textContent = `Download ${filename}`;
        messageDiv.appendChild(link);
      }
      messageDiv.appendChild(timeSpan);
      messages.appendChild(messageDiv);
      messages.scrollTop = messages.scrollHeight;
      messageCount++;
      if (messageCount % 50 === 0 && isInitiator) {
        triggerRatchet();
      }
    } catch (e) {
      console.error(e);
      showStatusMessage('Failed to decrypt message: ' + e.message);
    }
  } else {
    // Original handling for non-encrypted types if any
  }
}

// Updated: deriveSharedKey for ratchet (original remains)

// Updated: triggerRatchet with epoch
async function triggerRatchet() {
  if (!isInitiator || connectedClients.size <= 1) return;
  epoch++;
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
      socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code, clientId, token, epoch }));
      success++;
    } catch (error) {
      console.error(`Error sending new room key to ${cId}:`, error);
    }
  }
  if (success > 0) {
    roomMaster = newRoomMaster;
    resetChains();
    console.log('PFS ratchet complete, new roomMaster set.');
  } else {
    console.warn('PFS ratchet failed: No keys available to send to any clients.');
    epoch--; // Rollback if failed
  }
}

// In socket.onmessage, add case for 'new-room-key'
if (msg.type === 'new-room-key') {
  // Assume targetId check if needed
  const shared = await deriveSharedKey(keyPair.privateKey, initiatorPublic); // Assume initiatorPublic stored
  const newRoomMasterBytes = await decryptBytes(shared, msg.encrypted, msg.iv);
  roomMaster = new Uint8Array(newRoomMasterBytes);
  epoch = msg.epoch;
  resetChains();
}

async function startVoiceRecording() {
  if (!features.enableVoice) {
    showStatusMessage('Voice messages are disabled by admin.');
    return;
  }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showStatusMessage('Microphone not supported.');
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const mimeTypes = [
      'audio/mp4',
      'audio/webm;codecs=opus',
      'audio/ogg;codecs=opus',
      'audio/webm',
      'audio/ogg'
    ];
    const mimeType = mimeTypes.find(MediaRecorder.isTypeSupported) || 'audio/webm';
    if (!mimeType) {
      showStatusMessage('Voice recording not supported in this browser.');
      return;
    }
    console.log('Using mimeType for recording:', mimeType);
    mediaRecorder = new MediaRecorder(stream, { mimeType });
    voiceChunks = [];
    mediaRecorder.addEventListener('dataavailable', (event) => {
      if (event.data.size > 0) {
        voiceChunks.push(event.data);
        console.log('Data available, chunk size:', event.data.size);
      } else {
        console.warn('Empty data chunk received');
      }
    });
    mediaRecorder.addEventListener('stop', async () => {
      console.log('Recorder stopped, chunks length:', voiceChunks.length);
      const audioBlob = new Blob(voiceChunks, { type: mimeType });
      console.log('Audio blob created, size:', audioBlob.size, 'type:', mimeType);
      if (audioBlob.size === 0) {
        showStatusMessage('No audio recorded. Speak louder or check microphone.');
        return;
      }
      sendMedia(audioBlob, 'voice');
      stream.getTracks().forEach(track => track.stop());
      mediaRecorder = null;
      voiceChunks = [];
      document.getElementById('voiceButton').classList.remove('recording');
      document.getElementById('voiceTimer').style.display = 'none';
      document.getElementById('voiceTimer').textContent = '';
      clearInterval(voiceTimerInterval);
    });
    mediaRecorder.start(1000); // Collect data every 1 second
    document.getElementById('voiceButton').classList.add('recording');
    document.getElementById('voiceTimer').style.display = 'flex';
    let time = 0;
    voiceTimerInterval = setInterval(() => {
      time++;
      document.getElementById('voiceTimer').textContent = `00:${time < 10 ? '0' + time : time}`;
      if (time >= 30) {
        stopVoiceRecording();
      }
    }, 1000);
  } catch (error) {
    console.error('Error starting voice recording:', error);
    showStatusMessage('Failed to access microphone for voice message.');
  }
}

// Function to stop voice recording
function stopVoiceRecording() {
  if (mediaRecorder && mediaRecorder.state === 'recording') {
    mediaRecorder.stop();
  }
}

// New: Function to check WebP support
function isWebPSupported() {
  const elem = document.createElement('canvas');
  if (!!(elem.getContext && elem.getContext('2d'))) {
    return elem.toDataURL('image/webp').indexOf('data:image/webp') === 0;
  }
  return false;
}

// Assume dataChannel setup and onmessage:
dataChannels.forEach(dc => {
  dc.onmessage = async (event) => {
    const msgJson = JSON.parse(event.data);
    await handleReceivedMessage(msgJson);
  };
});
