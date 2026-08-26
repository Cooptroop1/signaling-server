let turnUsername = '';
let turnCredential = '';
let localStream = null;
let voiceCallActive = false;
let grokBotActive = false;
let grokApiKey = localStorage.getItem('grokApiKey') || '';
let renegotiating = new Map();
let audioOutputMode = 'speaker';
let totpEnabled = false;
let totpSecret = '';
let pendingTotpSecret = null;
let mediaRecorder = null;
let voiceChunks = [];
let voiceTimerInterval = null;
let voiceRecordStream = null;
let voiceRecordStartedAt = 0;
let voiceStopping = false;
let messageCount = 0;
const CHUNK_SIZE = 32768;
const chunkBuffers = new Map(); // {chunkId: {chunks: [], total: m}}
const negotiationQueues = new Map(); // Queue pending negotiations per peer
let globalSendRate = { count: 0, startTime: performance.now() }; // Global send limit
const renegotiationCounts = new Map(); // New: Per-peer renegotiation attempt counter
const maxRenegotiations = 5; // New: Max renegotiation attempts per peer
let keyVersion = 0; // New: Global key version counter for ratcheting
let globalSizeRate = { totalSize: 0, startTime: performance.now() }; // New: Client-side size tracking (mirror server 1MB/min)
let processedNonces = new Map(); // Changed to Map<nonce, timestamp> for cleanup
let messageQueue = new Map(); // New: Per-target message queue for retries
function appendMessage({ username, timestamp, type, content, isSelf, fileName = null }) {
  const messagesElement = document.getElementById('messages');
  const messageDiv = document.createElement('div');
  messageDiv.className = `message-bubble ${isSelf ? 'self' : 'other'}`;
  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = new Date(timestamp).toLocaleTimeString();
  messageDiv.appendChild(timeSpan);
  messageDiv.appendChild(document.createTextNode(`${username}: `));
  if (type === 'image' || type === 'voice' || type === 'file') {
    let element;
    if (type === 'image') {
      element = document.createElement('img');
      element.dataset.src = content;
      element.style.maxWidth = '100%';
      element.style.borderRadius = '0.5rem';
      element.style.cursor = 'pointer';
      element.setAttribute('alt', `${isSelf ? 'Sent' : 'Received'} image`);
      element.addEventListener('click', () => createImageModal(content, `${type}Button`));
      lazyObserver.observe(element);
    } else if (type === 'voice') {
      element = makeVoiceNotePlayer(content);
    } else {
      element = document.createElement('a');
      element.href = content;
      element.download = fileName;
      element.textContent = `Download ${fileName}`;
      element.setAttribute('alt', `${isSelf ? 'Sent' : 'Received'} file`);
    }
    messageDiv.appendChild(element);
  } else {
    messageDiv.appendChild(document.createTextNode(content));
  }
  messagesElement.prepend(messageDiv);
  messagesElement.scrollTop = 0;
}
function checkAndUpdateRateLimit(rateObj, maxValue, isSize = false, addValue = 1, windowMs = 60000) {
  const now = performance.now();
  if (now - rateObj.startTime >= windowMs) {
    rateObj[isSize ? 'totalSize' : 'count'] = 0;
    rateObj.startTime = now;
  }
  const current = rateObj[isSize ? 'totalSize' : 'count'];
  if (current + addValue > maxValue) {
    return false;
  }
  rateObj[isSize ? 'totalSize' : 'count'] += addValue;
  return true;
}
function hasOpenDataChannel() {
  let open = false;
  dataChannels.forEach(dc => {
    if (dc && dc.readyState === 'open') open = true;
  });
  return open;
}
async function prepareAndSendMessage({ content, type = 'message', file = null, base64 = null }) {
  const p2pOpen = hasOpenDataChannel();
  if (!username || (!p2pOpen && !useRelay && !features.enableRelay)) {
    showStatusMessage('Error: Ensure you are connected and have a username.');
    return;
  }
  const now = performance.now();
  // Global send rate limit check
  if (!checkAndUpdateRateLimit(globalSendRate, 50)) {
    showStatusMessage('Global message rate limit exceeded (50/min). Please wait.');
    return;
  }
  // Client-side size limit check
  const payloadSize = (content || base64 || '').length * 3 / 4; // Approximate byte size
  if (!checkAndUpdateRateLimit(globalSizeRate, 6 * 1048576, true, payloadSize)) {
    showStatusMessage('Too much data this minute. Wait a moment and send the photo again.');
    return;
  }
  let dataToSend = content || base64;
  if (type === 'image' || type === 'file') {
    if (!features.enableImages) {
      showStatusMessage('Error: Images/Files are disabled by admin.');
      return;
    }
  } else if (type === 'voice') {
    if (!features.enableVoice) {
      showStatusMessage('Error: Voice messages are disabled by admin.');
      return;
    }
  }
  if (file && file.size > 5 * 1024 * 1024) {
    showStatusMessage(`Error: ${type.charAt(0).toUpperCase() + type.slice(1)} size exceeds 5MB limit.`);
    return;
  }
  const rateLimitsMap = type === 'image' || type === 'file' ? imageRateLimits : (type === 'voice' ? voiceRateLimits : messageRateLimits);
  const rateLimit = rateLimitsMap.get(clientId) || { count: 0, startTime: now };
  if (!checkAndUpdateRateLimit(rateLimit, 5)) {
    showStatusMessage(`${type.charAt(0).toUpperCase() + type.slice(1)} rate limit reached (5/min). Please wait.`);
    return;
  }
  rateLimitsMap.set(clientId, rateLimit);
  if (file && type === 'image') {
    const img = new Image();
    img.src = URL.createObjectURL(file);
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = reject;
    });
    const format = await isWebPSupported() ? 'image/webp' : 'image/jpeg';
    const maxBytes = 1500000;
    let maxEdge = 1600;
    let quality = format === 'image/webp' ? 0.86 : 0.84;
    let dataUrl = '';
    for (let pass = 0; pass < 6; pass++) {
      let width = img.width;
      let height = img.height;
      const longEdge = Math.max(width, height);
      if (longEdge > maxEdge) {
        const scale = maxEdge / longEdge;
        width = Math.max(1, Math.round(width * scale));
        height = Math.max(1, Math.round(height * scale));
      }
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(img, 0, 0, width, height);
      dataUrl = canvas.toDataURL(format, quality);
      const bytes = Math.ceil((dataUrl.length - dataUrl.indexOf(',') - 1) * 0.75);
      if (bytes <= maxBytes) break;
      if (quality > 0.7) quality -= 0.06;
      else maxEdge = Math.round(maxEdge * 0.85);
    }
    dataToSend = dataUrl;
    URL.revokeObjectURL(img.src);
  } else if (file) {
    dataToSend = await new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.readAsDataURL(file);
    });
  }
  const messageId = generateMessageId();
  const timestamp = Date.now();
  const jitter = Math.floor(Math.random() * 31) * -1000; // 0 to -30s
  const jitteredTimestamp = timestamp + jitter;
  const nonce = crypto.randomUUID();
  const sanitizedContent = content ? sanitizeMessage(content) : null;
  const metadata = JSON.stringify({ username, timestamp: jitteredTimestamp, type });
  let rawData = metadata + (dataToSend || sanitizedContent);
  const paddedLength = Math.min(Math.ceil(rawData.length / 512) * 512, 5 * 1024 * 1024);
  rawData = rawData.padEnd(paddedLength, ' ');
  const messageKey = await deriveMessageKey();
  const { encrypted, iv } = await encryptRaw(messageKey, rawData, String(messageId) + '|' + String(nonce));
  const toSign = rawData + nonce;
  const signature = await signMessage(signingKey, toSign);
  await initIdentityKeys();
  const identitySig = await signIdentitySignature(identityKeyPair.privateKey, String(messageId) + String(nonce) + String(encrypted));
  const payload = {
    messageId,
    nonce,
    iv,
    signature,
    identityPublic: identityPubB64,
    identitySig,
    timestamp: jitteredTimestamp
  };
  if (type === 'file') payload.filename = file?.name;
  const sendViaP2p = p2pOpen;
  if (sendViaP2p) useRelay = false;
  let sent = false;
  if (sendViaP2p) {
    updatePrivacyStatus('E2E Encrypted (P2P)');
    payload.encryptedBlob = encrypted;
    const jsonString = JSON.stringify(payload);
    dataChannels.forEach((dataChannel, id) => {
      if (!dataChannel || dataChannel.readyState !== 'open') return;
      if (jsonString.length > CHUNK_SIZE) {
        const chunkId = generateMessageId();
        const chunks = [];
        for (let i = 0; i < jsonString.length; i += CHUNK_SIZE) {
          chunks.push(jsonString.slice(i, i + CHUNK_SIZE));
        }
        for (let index = 0; index < chunks.length; index++) {
          dataChannel.send(JSON.stringify({ chunk: true, chunkId, index, total: chunks.length, data: chunks[index] }));
        }
      } else {
        dataChannel.send(jsonString);
      }
      sent = true;
    });
    if (!sent) {
      console.log('No open data channels, queuing message for retry');
      if (!messageQueue.has('global')) messageQueue.set('global', []);
      messageQueue.get('global').push({ type, payload });
    }
  } else if (features.enableRelay) {
    useRelay = true;
    updatePrivacyStatus('Relay Mode (E2EE)');
    if (type === 'message') payload.encryptedContent = encrypted;
    else {
      payload.encryptedData = encrypted;
      if (file?.type) payload.mime = file.type;
    }
    sendMessageViaSocket(type, payload, true);
    sent = true;
  } else {
    showStatusMessage('Waiting for peer connection...');
    return;
  }
  if (sent) {
    appendMessage({ username, timestamp, type, content: sanitizedContent || dataToSend, isSelf: true, fileName: file?.name });
    processedMessageIds.add(messageId);
    processedNonces.set(nonce, Date.now());
    messageCount++;
    if (isInitiator && messageCount % 100 === 0) {
      await triggerRatchet();
    }
  }
}
async function sendMessage(content) {
  if (!content) return;
  if (grokBotActive && content.startsWith('/grok ')) {
    const query = content.slice(6).trim();
    if (query) await sendToGrok(query);
  } else if (content === '/ratchet' && isInitiator) {
    await triggerRatchet();
    showStatusMessage('Key ratchet triggered manually.');
  } else {
    await prepareAndSendMessage({ content });
  }
  const messageInput = document.getElementById('messageInput');
  messageInput.value = '';
  messageInput.style.height = '2.5rem';
  messageInput?.focus();
  if (typeof updateComposerSend === 'function') updateComposerSend();
}
async function sendMedia(file, type) {
  const validTypes = {
    image: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif', 'image/heic', 'image/heif'],
    voice: ['audio/webm', 'audio/ogg', 'audio/mp4', 'audio/mpeg', 'audio/aac']
  };
  if (type === 'image' && file.type && !file.type.startsWith('image/') && !validTypes.image.includes(file.type)) {
    showStatusMessage('That file is not a photo.');
    return;
  }
  await prepareAndSendMessage({ type, file });
}
async function startPeerConnection(targetId, isOfferer) {
  console.log(`Starting peer connection with ${targetId} for code: ${code}, offerer: ${isOfferer}`);
  if (!features.enableP2P) {
    console.log('P2P disabled by admin, forcing relay mode');
    useRelay = true;
    updatePrivacyStatus('Relay Mode (E2EE)');
    isConnected = true;
    updateUIState(true);
    updateMaxClientsUI();
    return;
  }
  if (peerConnections.has(targetId)) {
    console.log(`Cleaning up existing connection with ${targetId}`);
    cleanupPeerConnection(targetId);
  }
  const iceServers = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun.relay.metered.ca:80' }
  ];
  if (turnUsername && turnCredential) {
    iceServers.push(
      { urls: 'turn:global.relay.metered.ca:80', username: turnUsername, credential: turnCredential },
      { urls: 'turn:global.relay.metered.ca:80?transport=tcp', username: turnUsername, credential: turnCredential },
      { urls: 'turn:global.relay.metered.ca:443', username: turnUsername, credential: turnCredential },
      { urls: 'turns:global.relay.metered.ca:443?transport=tcp', username: turnUsername, credential: turnCredential }
    );
  }
  const peerConnection = new RTCPeerConnection({
    iceServers,
    iceTransportPolicy: 'all'
  });
  peerConnections.set(targetId, peerConnection);
  candidatesQueues.set(targetId, []);
  let dataChannel;
  if (isOfferer) {
    dataChannel = peerConnection.createDataChannel('chat');
    console.log(`Created data channel for ${targetId}`);
    setupDataChannel(dataChannel, targetId);
    dataChannels.set(targetId, dataChannel);
  }
  peerConnection.onicecandidate = (event) => {
    if (event.candidate) {
      console.log(`Sending ICE candidate to ${targetId} for code: ${code}`);
      sendSignalingMessage('candidate', { candidate: event.candidate, targetId });
    }
  };
  peerConnection.onicecandidateerror = (event) => {
    console.error(`ICE candidate error for ${targetId}: ${event.errorText}, code=${event.errorCode}`);
    if (event.errorCode !== 701) {
      const retryCount = retryCounts.get(targetId) || 0;
      if (retryCount < maxRetries) {
        retryCounts.set(targetId, retryCount + 1);
        console.log(`Retrying connection with ${targetId}, attempt ${retryCount + 1}`);
        startPeerConnection(targetId, isOfferer);
      }
    } else {
      console.log(`Ignoring ICE 701 error for ${targetId}, continuing connection`);
    }
  };
  peerConnection.onicegatheringstatechange = () => {
    console.log(`ICE gathering state for ${targetId}: ${peerConnection.iceGatheringState}`);
  };
  peerConnection.onconnectionstatechange = () => {
    console.log(`Connection state for ${targetId}: ${peerConnection.connectionState}`);
    if (peerConnection.connectionState === 'disconnected' || peerConnection.connectionState === 'failed') {
      const dc = dataChannels.get(targetId);
      if (dc && dc.readyState === 'open') {
        console.log(`ICE blip with ${targetId} but data channel still open — keep P2P`);
        return;
      }
      console.log(`Connection failed with ${targetId}`);
      cleanupPeerConnection(targetId);
      const retryCount = retryCounts.get(targetId) || 0;
      if (retryCount < maxRetries) {
        retryCounts.set(targetId, retryCount + 1);
        console.log(`Retrying connection attempt ${retryCount + 1} with ${targetId}`);
        startPeerConnection(targetId, isOfferer);
        setTimeout(() => processMessageQueue(targetId), 2000);
      }
    } else if (peerConnection.connectionState === 'connected') {
      console.log(`WebRTC connection established with ${targetId} for code: ${code}`);
      isConnected = true;
      useRelay = false;
      retryCounts.delete(targetId);
      clearTimeout(connectionTimeouts.get(targetId));
      updateMaxClientsUI();
      updatePrivacyStatus('E2E Encrypted (P2P)');
      processMessageQueue(targetId);
    }
  };
  peerConnection.ontrack = (event) => {
    console.log(`Received remote track from ${targetId}`);
    const stream = event.streams[0] || new MediaStream([event.track]);
    let audio = remoteAudios.get(targetId);
    if (!audio) {
      audio = document.createElement('audio');
      audio.autoplay = true;
      audio.playsInline = true;
      audio.setAttribute('playsinline', '');
      document.getElementById('remoteAudioContainer').appendChild(audio);
      document.getElementById('remoteAudioContainer').classList.remove('hidden');
      remoteAudios.set(targetId, audio);
    }
    audio.srcObject = stream;
    audio.volume = audioOutputMode === 'earpiece' ? 0.55 : 1;
    audio.play().catch(error => console.error('Error playing remote audio:', error));
    setAudioOutput(audio, targetId);
    if (voiceCallActive) {
      document.getElementById('audioOutputButton')?.classList.remove('hidden');
    }
  };
  peerConnection.ondatachannel = (event) => {
    console.log(`Received data channel from ${targetId}`);
    if (dataChannels.has(targetId)) {
      console.log(`Closing existing data channel for ${targetId}`);
      const existingChannel = dataChannels.get(targetId);
      existingChannel.close();
    }
    dataChannel = event.channel;
    setupDataChannel(dataChannel, targetId);
    dataChannels.set(targetId, dataChannel);
  };
  peerConnection.onsignalingstatechange = () => {
    console.log(`Signaling state for ${targetId}: ${peerConnection.signalingState}`);
  };
  if (isOfferer) {
    peerConnection.createOffer().then(offer => {
      return peerConnection.setLocalDescription(offer);
    }).then(() => {
      console.log(`Sending offer to ${targetId} for code: ${code}`);
      sendSignalingMessage('offer', { offer: peerConnection.localDescription, targetId });
    }).catch(error => {
      console.error(`Error creating offer for ${targetId}:`, error);
    });
  }
  const timeout = setTimeout(() => {
    if (hasOpenDataChannel()) {
      useRelay = false;
      updatePrivacyStatus('E2E Encrypted (P2P)');
      return;
    }
    if (!dataChannels.get(targetId) || dataChannels.get(targetId).readyState !== 'open') {
      console.log(`P2P failed with ${targetId}, checking relay availability`);
      if (features.enableRelay) {
        useRelay = true;
        updatePrivacyStatus('Relay Mode (E2EE)');
        isConnected = true;
        updateUIState(true);
      } else {
        showStatusMessage('P2P connection failed and relay mode is disabled. Cannot send messages.');
        cleanupPeerConnection(targetId);
      }
    }
  }, 10000);
  connectionTimeouts.set(targetId, timeout);
}
function setupDataChannel(dataChannel, targetId) {
  console.log('setupDataChannel initialized for targetId:', targetId);
  dataChannel.onopen = () => {
    console.log(`Data channel opened with ${targetId} for code: ${code}, state: ${dataChannel.readyState}`);
    isConnected = true;
    useRelay = false;
    updatePrivacyStatus('E2E Encrypted (P2P)');
    try {
      ensurePersistentKeys().then(me => {
        if (me && me.ecdhPubB64 && dataChannel.readyState === 'open') {
          dataChannel.send(JSON.stringify({ type: 'dr-hello', ecdh: me.ecdhPubB64, identityPublic: identityPubB64 || me.ecdsaPubB64 }));
        }
      }).catch(() => {});
    } catch (e) {}
    updateUIState(true, true);
    clearTimeout(connectionTimeouts.get(targetId));
    retryCounts.delete(targetId);
    updateMaxClientsUI();
    document.getElementById('messageInput')?.focus();
    if (voiceCallActive) {
      document.getElementById('audioOutputButton')?.classList.remove('hidden');
    }
    processMessageQueue(targetId);
  };
  dataChannel.onmessage = async (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch (e) {
      console.error(`Invalid message from ${targetId}:`, e);
      showStatusMessage('Invalid message received.');
      return;
    }
    if (data.chunk) {
      const { chunkId, index, total, data: chunkData } = data;
      if (!chunkBuffers.has(chunkId)) {
        chunkBuffers.set(chunkId, { chunks: new Array(total), received: 0 });
      }
      const buffer = chunkBuffers.get(chunkId);
      buffer.chunks[index] = chunkData;
      buffer.received++;
      if (buffer.received === total) {
        const fullMessage = buffer.chunks.join('');
        chunkBuffers.delete(chunkId);
        try {
          data = JSON.parse(fullMessage);
        } catch (e) {
          console.error(`Invalid reassembled message from ${targetId}:`, e);
          return;
        }
        await processReceivedMessage(data, targetId);
      }
      return;
    }
    const now = performance.now();
    const rateLimit = messageRateLimits.get(targetId) || { count: 0, startTime: now };
    if (!checkAndUpdateRateLimit(rateLimit, 30, false, 1, 1000)) {
      console.warn(`Rate limit exceeded for ${targetId}: ${rateLimit.count} messages in 1s`);
      showStatusMessage('Message rate limit reached, please slow down.');
      return;
    }
    messageRateLimits.set(targetId, rateLimit);
    await processReceivedMessage(data, targetId);
  };
  dataChannel.onerror = (error) => {
    console.error(`Data channel error with ${targetId}:`, error);
  };
  dataChannel.onclose = () => {
    console.log(`Data channel closed with ${targetId}`);
    cleanupPeerConnection(targetId);
    messageRateLimits.delete(targetId);
    imageRateLimits.delete(targetId);
    voiceRateLimits.delete(targetId);
    if (remoteAudios.has(targetId)) {
      const audio = remoteAudios.get(targetId);
      audio.remove();
      remoteAudios.delete(targetId);
      if (remoteAudios.size === 0) {
        document.getElementById('remoteAudioContainer').classList.add('hidden');
      }
    }
    if (dataChannels.size === 0) {
      updateUIState(false);
      document.getElementById('audioOutputButton').classList.add('hidden');
    }
  };
}
function processMessageQueue(targetId) {
  if (messageQueue.has(targetId)) {
    const queue = messageQueue.get(targetId);
    while (queue.length > 0) {
      const msg = queue.shift();
      const dataChannel = dataChannels.get(targetId);
      if (dataChannel && dataChannel.readyState === 'open') {
        dataChannel.send(msg);
      }
    }
    if (queue.length === 0) messageQueue.delete(targetId);
  }
}
async function processReceivedMessage(data, targetId) {
  if (data.type === 'room-wipe') {
    applyRemoteRoomWipe();
    return;
  }
  if (data.type === 'voice-call-start') {
    if (!voiceCallActive) {
      startVoiceCall();
    }
    return;
  }
  if (data.type === 'voice-call-end') {
    if (voiceCallActive) {
      stopVoiceCall();
    }
    return;
  }
  if (data.type === 'kick' || data.type === 'ban') {
    if (data.targetId === clientId) {
      showStatusMessage(`You have been ${data.type}ed from the room.`);
      socket.close();
      window.location.reload();
    }
    return;
  }
  if (data.type === 'dr-hello') {
    if (data.ecdh && typeof clientEcdhKeys !== 'undefined') clientEcdhKeys.set(targetId, data.ecdh);
    if (data.identityPublic && typeof clientIdentityKeys !== 'undefined') clientIdentityKeys.set(targetId, data.identityPublic);
    return;
  }
  const isDr = !!(data.header && data.body);
  const isSk = !!data.sk;
  if (!data.messageId || (!isDr && !isSk && !data.encryptedBlob && !data.encryptedContent && !data.encryptedData)) {
    console.log(`Invalid message format from ${targetId}:`, data);
    return;
  }
  if (processedMessageIds.has(data.messageId)) {
    console.log(`Duplicate message ${data.messageId} from ${targetId}`);
    return;
  }
  if (processedNonces.has(data.nonce)) {
    console.log(`Duplicate nonce ${data.nonce} from ${targetId}`);
    return;
  }
  const now = Date.now();
  if (Math.abs(now - data.timestamp) > 300000) {
    console.warn(`Rejecting message with timestamp ${data.timestamp} (now: ${now}), outside window`);
    return;
  }
  processedMessageIds.add(data.messageId);
  processedNonces.set(data.nonce, Date.now());
  let senderUsername, timestamp, contentType, contentOrData;
  try {
    let rawData = null;
    if (isDr || isSk) {
      rawData = await decryptLivePacket(data, targetId);
    } else {
      const messageKey = await deriveMessageKey();
      const encrypted = data.encryptedBlob || data.encryptedContent || data.encryptedData;
      rawData = await decryptRaw(messageKey, encrypted, data.iv, String(data.messageId) + '|' + String(data.nonce));
      const toVerify = rawData + data.nonce;
      const valid = await verifyMessage(signingKey, data.signature, toVerify);
      if (!valid) {
        console.warn(`Invalid signature for message from ${targetId}`);
        showStatusMessage('Invalid message signature detected.');
        return;
      }
      const encryptedVal = data.encryptedBlob || data.encryptedContent || data.encryptedData;
      if (!data.identityPublic || !data.identitySig) {
        console.warn(`Missing identity signature from ${targetId}`);
        showStatusMessage('Unsigned message rejected.');
        return;
      }
      if (clientIdentityKeys.has(targetId) && clientIdentityKeys.get(targetId) !== data.identityPublic) {
        console.warn(`Identity key changed from ${targetId}, accepting verified new key`);
      }
      const identityOk = await verifyIdentitySignature(
        data.identityPublic,
        data.identitySig,
        String(data.messageId) + String(data.nonce) + String(encryptedVal)
      );
      if (!identityOk) {
        console.warn(`Invalid identity signature from ${targetId}`);
        showStatusMessage('Message identity check failed.');
        return;
      }
      clientIdentityKeys.set(targetId, data.identityPublic);
    }
    if (data.identityEcdh && typeof clientEcdhKeys !== 'undefined') {
      clientEcdhKeys.set(targetId, data.identityEcdh);
    }
    let metadataStr = '';
    let braceCount = 0;
    for (let i = 0; i < rawData.length; i++) {
      metadataStr += rawData[i];
      if (rawData[i] === '{') braceCount++;
      if (rawData[i] === '}') braceCount--;
      if (braceCount === 0 && metadataStr.startsWith('{')) break;
    }
    const metadata = JSON.parse(metadataStr);
    senderUsername = usernames.get(targetId) || metadata.username;
    timestamp = metadata.timestamp;
    contentType = metadata.type;
    contentOrData = rawData.substring(metadataStr.length).trimEnd();
  } catch (error) {
    console.error(`Decryption/verification failed for message from ${targetId}:`, error);
    showStatusMessage('Failed to decrypt/verify message.');
    return;
  }
  appendMessage({ username: senderUsername, timestamp, type: contentType, content: sanitizeMessage(contentOrData), isSelf: senderUsername === username, fileName: data.filename || 'file' });
  if (isInitiator && !isDr && !isSk) {
    dataChannels.forEach((dc, id) => {
      if (id !== targetId && dc.readyState === 'open') {
        try { dc.send(JSON.stringify(data)); } catch (e) {}
      }
    });
  }
}
async function handleOffer(offer, targetId) {
  console.log(`Handling offer from ${targetId} for code: ${code}`);
  if (offer.type !== 'offer') {
    console.error(`Invalid offer type from ${targetId}:`, offer.type);
    return;
  }
  if (!peerConnections.has(targetId)) {
    console.log(`No existing peer connection for ${targetId}, starting new one`);
    startPeerConnection(targetId, false);
  }
  const peerConnection = peerConnections.get(targetId);
  try {
    if (peerConnection.signalingState === 'have-local-offer') {
      console.log(`Negotiation glare detected for ${targetId}, rolling back local offer`);
      await peerConnection.setLocalDescription({type: 'rollback'});
    }
    await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);
    sendSignalingMessage('answer', { answer: peerConnection.localDescription, targetId });
    const queue = candidatesQueues.get(targetId) || [];
    await processCandidateQueue(peerConnection, queue);
    candidatesQueues.set(targetId, []);
  } catch (error) {
    console.error(`Error handling offer from ${targetId}:`, error);
  }
}
async function handleAnswer(answer, targetId) {
  console.log(`Handling answer from ${targetId} for code: ${code}`);
  if (!peerConnections.has(targetId)) {
    console.log(`No peer connection for ${targetId}, starting new one and queuing answer`);
    startPeerConnection(targetId, false);
    candidatesQueues.get(targetId).push({ type: 'answer', answer });
    return;
  }
  const peerConnection = peerConnections.get(targetId);
  if (answer.type !== 'answer') {
    console.error(`Invalid answer type from ${targetId}:`, answer.type);
    return;
  }
  if (peerConnection.signalingState !== 'have-local-offer') {
    console.log(`Queuing answer from ${targetId}`);
    candidatesQueues.get(targetId).push({ type: 'answer', answer });
    return;
  }
  try {
    await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
    const queue = candidatesQueues.get(targetId) || [];
    await processCandidateQueue(peerConnection, queue);
    candidatesQueues.set(targetId, []);
  } catch (error) {
    console.error(`Error handling answer from ${targetId}:`, error);
  }
}
async function handleCandidate(candidate, targetId) {
  console.log(`Handling ICE candidate from ${targetId} for code: ${code}`);
  if (candidate.sdpMid === null && candidate.sdpMLineIndex === null) {
    console.warn(`Ignoring invalid ICE candidate from ${targetId}: both sdpMid and sdpMLineIndex null`);
    return;
  }
  const peerConnection = peerConnections.get(targetId);
  if (peerConnection && peerConnection.remoteDescription) {
    try {
      await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (error) {
      console.error(`Error adding ICE candidate from ${targetId}:`, error);
    }
  } else {
    const queue = candidatesQueues.get(targetId) || [];
    queue.push({ type: 'candidate', candidate });
    candidatesQueues.set(targetId, queue);
  }
}
async function processCandidateQueue(peerConnection, queue) {
  for (const item of queue) {
    if (item.type === 'answer') {
      try {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(item.answer));
      } catch (error) {
        console.error(`Error applying queued answer:`, error);
      }
    } else if (item.type === 'candidate') {
      try {
        await peerConnection.addIceCandidate(new RTCIceCandidate(item.candidate));
      } catch (error) {
        console.error(`Error adding queued ICE candidate:`, error);
      }
    }
  }
}
async function toggleVoiceCall() {
  if (!features.enableVoiceCalls) {
    showStatusMessage('Voice calls are disabled by admin.');
    return;
  }
  if (voiceCallActive) {
    stopVoiceCall();
    broadcastVoiceCallEvent('voice-call-end');
  } else {
    startVoiceCall();
    broadcastVoiceCallEvent('voice-call-start');
  }
}
function updateAudioTracks(action) {
  peerConnections.forEach((peerConnection, targetId) => {
    if (action === 'add' && localStream) {
      localStream.getAudioTracks().forEach(track => {
        const sender = peerConnection.getSenders().find(s => s.track && s.track.kind === 'audio');
        if (sender) {
          sender.replaceTrack(track).catch(() => {
            try { peerConnection.addTrack(track, localStream); } catch (e) {}
          });
        } else {
          try { peerConnection.addTrack(track, localStream); } catch (e) {}
        }
      });
    } else if (action === 'remove') {
      peerConnection.getSenders().forEach(sender => {
        if (sender.track && sender.track.kind === 'audio') {
          try { sender.replaceTrack(null); } catch (e) {}
          try { peerConnection.removeTrack(sender); } catch (e) {}
        }
      });
    }
    if (peerConnection.signalingState === 'stable') {
      renegotiate(targetId);
    }
  });
}
async function startVoiceCall() {
  if (voiceCallActive && localStream) return;
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showStatusMessage('Microphone not supported.');
    return;
  }
  try {
    localStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
    });
    updateAudioTracks('add');
    voiceCallActive = true;
    const callBtn = document.getElementById('voiceCallButton');
    callBtn.classList.add('active');
    callBtn.title = 'End call';
    callBtn.setAttribute('aria-label', 'End call');
    document.getElementById('audioOutputButton')?.classList.remove('hidden');
    if (typeof updateAttachButton === 'function') updateAttachButton();
    if (typeof updateSpeakerButton === 'function') updateSpeakerButton();
    showStatusMessage('Call started. Use speaker if you cannot hear them.');
  } catch (error) {
    console.error('Error starting voice call:', error);
    voiceCallActive = true;
    document.getElementById('voiceCallButton')?.classList.add('active');
    document.getElementById('audioOutputButton')?.classList.remove('hidden');
    if (error && error.name === 'NotFoundError') {
      showStatusMessage('No microphone on this device. You can still hear the other person.');
    } else if (error && error.name === 'NotAllowedError') {
      showStatusMessage('Microphone blocked. Allow mic in the browser, then tap call again.');
    } else {
      showStatusMessage('Could not start microphone. You can still hear them if they are in the call.');
    }
  }
}
function stopVoiceCall() {
  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localStream = null;
  }
  updateAudioTracks('remove');
  voiceCallActive = false;
  const callBtn = document.getElementById('voiceCallButton');
  if (callBtn) {
    callBtn.classList.remove('active');
    callBtn.title = 'Start voice call';
    callBtn.setAttribute('aria-label', 'Start voice call');
  }
  document.getElementById('audioOutputButton')?.classList.add('hidden');
  if (typeof updateAttachButton === 'function') updateAttachButton();
  showStatusMessage('Call ended.');
}
async function renegotiate(targetId) {
  const peerConnection = peerConnections.get(targetId);
  if (peerConnection) {
    const count = renegotiationCounts.get(targetId) || 0;
    if (count >= maxRenegotiations) {
      console.warn(`Max renegotiations reached for ${targetId} (${maxRenegotiations}), aborting.`);
      cleanupPeerConnection(targetId);
      return;
    }
    renegotiationCounts.set(targetId, count + 1);
    if (!negotiationQueues.has(targetId)) {
      negotiationQueues.set(targetId, Promise.resolve());
    }
    negotiationQueues.set(targetId, negotiationQueues.get(targetId).then(async () => {
      if (renegotiating.get(targetId)) {
        console.log(`Renegotiation already in progress for ${targetId}, skipping.`);
        return;
      }
      if (peerConnection.signalingState !== 'stable') {
        console.log(`Cannot renegotiate with ${targetId}: state is ${peerConnection.signalingState}. Queuing.`);
        return renegotiate(targetId);
      }
      renegotiating.set(targetId, true);
      try {
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        sendSignalingMessage('offer', { offer: peerConnection.localDescription, targetId });
      } catch (error) {
        console.error(`Error renegotiating with ${targetId}:`, error);
      } finally {
        renegotiating.set(targetId, false);
      }
    }).catch(error => {
      console.error(`Negotiation queue error for ${targetId}:`, error);
    }));
  } else {
    console.log(`No peer connection for ${targetId}, cannot renegotiate.`);
  }
}
function sendMessageViaSocket(type, additionalData, isRelay = false) {
  if (!token || refreshingToken) {
    console.log('Token missing or refresh in progress, queuing message');
    if (!signalingQueue.has('global')) signalingQueue.set('global', []);
    signalingQueue.get('global').push({ type: isRelay ? `relay-${type}` : type, additionalData });
    if (!refreshingToken) refreshAccessToken();
    return;
  }
  const message = { type: isRelay ? `relay-${type}` : type, ...additionalData, code, clientId, token };
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
  } else {
    console.log('Socket not open, queuing message');
    if (!signalingQueue.has('global')) signalingQueue.set('global', []);
    signalingQueue.get('global').push({ type: isRelay ? `relay-${type}` : type, additionalData });
  }
}
function sendSignalingMessage(type, additionalData) {
  sendMessageViaSocket(type, additionalData, false);
}
function sendRelayMessage(type, additionalData) {
  sendMessageViaSocket(type, additionalData, true);
}
function broadcastVoiceCallEvent(eventType) {
  dataChannels.forEach((dataChannel) => {
    if (dataChannel.readyState === 'open') {
      dataChannel.send(JSON.stringify({ type: eventType }));
    }
  });
}
function processSignalingQueue() {
  signalingQueue.forEach((queue, key) => {
    while (queue.length > 0) {
      const { type, additionalData } = queue.shift();
      sendMessageViaSocket(type.replace('relay-', ''), additionalData, type.startsWith('relay-'));
    }
  });
  signalingQueue.clear();
}
function updatePrivacyStatus(text) {
  const privacyStatus = document.getElementById('privacyStatus');
  if (privacyStatus) {
    privacyStatus.textContent = text;
    privacyStatus.classList.remove('hidden');
  }
}
function updateUIState(isConnected = false, hasChat = false) {
  initialContainer.classList.toggle('hidden', isConnected || hasChat);
  usernameContainer.classList.toggle('hidden', isConnected || hasChat);
  connectContainer.classList.toggle('hidden', isConnected || hasChat);
  chatContainer.classList.toggle('hidden', !isConnected && !hasChat);
  newSessionButton.classList.toggle('hidden', !isConnected);
  inputContainer.classList.toggle('hidden', !isConnected);
  messages.classList.toggle('waiting', !isConnected);
}
async function autoConnect(codeParam) {
  console.log('autoConnect running with code:', codeParam);
  if (code === codeParam && token && socket && socket.readyState === WebSocket.OPEN && !pendingCode) {
    console.log('Already joining this code, skip duplicate autoConnect');
    return;
  }
  code = codeParam;
  updateUIState(false, true);
  codeDisplayElement.classList.add('hidden');
  copyCodeButton?.classList.add('hidden');
  if (validateCode(codeParam)) {
    if (validateUsername(username)) {
      console.log('Valid username and code, joining chat');
      codeDisplayElement.textContent = `Using code: ${code}`;
      codeDisplayElement.classList.remove('hidden');
      copyCodeButton?.classList.remove('hidden');
      messages.classList.add('waiting');
      statusElement.textContent = 'Waiting for connection...';
      if (socket.readyState === WebSocket.OPEN) {
        console.log('Sending check-totp');
        ensureServerForCode(codeParam).then(() => {
          socket.send(JSON.stringify({ type: 'check-totp', code: codeParam, clientId, token }));
        }).catch(err => {
          console.error(err);
          showStatusMessage('Could not reach the server for this code.');
        });
      } else {
        console.log('WebSocket not open, waiting for open event to send check-totp');
        pendingCode = codeParam;
        ensureServerForCode(codeParam).catch(() => {});
      }
      document.getElementById('messageInput')?.focus();
      updateFeaturesUI();
    } else {
      console.log('No valid username, prompting for username');
      usernameContainer.classList.remove('hidden');
      chatContainer.classList.add('hidden');
      statusElement.textContent = 'Please enter a username to join the chat';
      document.getElementById('usernameInput').value = username || '';
      document.getElementById('usernameInput')?.focus();
      document.getElementById('joinWithUsernameButton').onclick = () => {
        const usernameInput = document.getElementById('usernameInput').value.trim();
        if (!validateUsername(usernameInput)) {
          showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
          document.getElementById('usernameInput')?.focus();
          return;
        }
        username = usernameInput;
        localStorage.setItem('username', username);
        usernameContainer.classList.add('hidden');
        chatContainer.classList.remove('hidden');
        codeDisplayElement.textContent = `Using code: ${code}`;
        codeDisplayElement.classList.remove('hidden');
        copyCodeButton?.classList.remove('hidden');
        messages.classList.add('waiting');
        statusElement.textContent = 'Waiting for connection...';
        socket.send(JSON.stringify({ type: 'check-totp', code, clientId, token }));
        document.getElementById('messageInput')?.focus();
      };
    }
  } else {
    console.log('Invalid code, showing initial container');
    initialContainer.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    showStatusMessage('Invalid code format. Please enter a valid code.');
    document.getElementById('connectToggleButton')?.focus();
  }
}
function updateFeaturesUI() {
  const attachPhotos = document.getElementById('attachPhotos');
  const attachCamera = document.getElementById('attachCamera');
  const attachFile = document.getElementById('attachFile');
  const attachVoice = document.getElementById('attachVoice');
  const voiceCallButton = document.getElementById('voiceCallButton');
  const audioOutputButton = document.getElementById('audioOutputButton');
  const grokButton = document.getElementById('grokButton');
  if (attachPhotos) attachPhotos.classList.toggle('hidden', !features.enableImages);
  if (attachCamera) attachCamera.classList.toggle('hidden', !features.enableImages);
  if (attachFile) attachFile.classList.toggle('hidden', !features.enableImages);
  if (attachVoice) attachVoice.classList.toggle('hidden', !features.enableVoice);
  if (voiceCallButton) {
    voiceCallButton.classList.toggle('hidden', !features.enableVoiceCalls);
    if (!features.enableVoiceCalls && voiceCallActive) stopVoiceCall();
  }
  if (audioOutputButton) {
    const shouldHide = !voiceCallActive;
    audioOutputButton.classList.toggle('hidden', shouldHide);
    updateSpeakerButton();
  }
  if (grokButton) {
    grokButton.classList.toggle('hidden', !features.enableGrokBot);
    grokButton.title = features.enableGrokBot ? 'Toggle Grok Bot' : 'Grok bot disabled by admin';
  }
  if (!features.enableService) {
    showStatusMessage('Service disabled by admin. Disconnecting...');
    socket.close();
  }
  if (!features.enableP2P && !features.enableRelay) {
    showStatusMessage('Both P2P and relay disabled. Messaging unavailable.');
    inputContainer.classList.add('hidden');
  } else if (!features.enableP2P && features.enableRelay && isConnected) {
    inputContainer.classList.remove('hidden');
    messages.classList.remove('waiting');
  }
}
async function sendToGrok(query) {
  if (!grokApiKey) {
    showStatusMessage('Error: xAI API key not set. Enter it in the Grok bot settings.');
    return;
  }
  try {
    const response = await fetch('https://api.x.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${grokApiKey}`
      },
      body: JSON.stringify({ model: 'grok-4', messages: [{ role: 'user', content: query }] })
    });
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`);
    }
    const data = await response.json();
    const botResponse = data.choices[0].message.content;
    appendMessage({ username: 'Grok Bot', timestamp: Date.now(), type: 'message', content: sanitizeMessage(botResponse), isSelf: false });
  } catch (error) {
    console.error('Grok API error:', error);
    showStatusMessage('Error querying Grok: ' + error.message + '. Check your API key or visit https://x.ai/api for details.');
  }
}
function toggleGrokBot() {
  grokBotActive = !grokBotActive;
  const grokButton = document.getElementById('grokButton');
  const grokKeyContainer = document.getElementById('grokKeyContainer');
  grokButton.classList.toggle('active', grokBotActive);
  grokKeyContainer.classList.toggle('active', grokBotActive && !grokApiKey);
  if (grokBotActive) {
    if (!grokApiKey) {
      showStatusMessage('Grok bot enabled. Enter your xAI API key below. For details, visit https://x.ai/api.');
    } else {
      showStatusMessage('Grok bot enabled. Use /grok <query> to ask questions.');
    }
  } else {
    showStatusMessage('Grok bot disabled.');
  }
}
function saveGrokKey() {
  const keyInput = document.getElementById('grokApiKey');
  grokApiKey = keyInput.value.trim();
  if (grokApiKey) {
    localStorage.setItem('grokApiKey', grokApiKey);
    document.getElementById('grokKeyContainer').classList.remove('active');
    showStatusMessage('API key saved. Use /grok <query> to ask Grok.');
    keyInput.value = '';
  } else {
    showStatusMessage('Error: Enter a valid API key.');
  }
}
async function setAudioOutput(audioElement, targetId) {
  if (!audioElement) return;
  audioElement.volume = audioOutputMode === 'earpiece' ? 0.55 : 1;
  try {
    if (typeof audioElement.setSinkId === 'function') {
      const sink = audioOutputMode === 'speaker' ? 'default' : '';
      if (sink) await audioElement.setSinkId('default');
    }
  } catch (error) {
    console.warn(`Speaker routing not available on this phone (${targetId})`);
  }
}
function updateSpeakerButton() {
  const audioOutputButton = document.getElementById('audioOutputButton');
  if (!audioOutputButton) return;
  const loud = audioOutputMode === 'speaker';
  audioOutputButton.title = loud ? 'Speaker on — tap for quieter' : 'Quiet — tap for speaker';
  audioOutputButton.setAttribute('aria-label', audioOutputButton.title);
  audioOutputButton.textContent = loud ? '🔊' : '🔈';
  audioOutputButton.classList.toggle('speaker', loud);
  audioOutputButton.classList.toggle('hidden', !voiceCallActive);
}
function toggleAudioOutput() {
  audioOutputMode = audioOutputMode === 'earpiece' ? 'speaker' : 'earpiece';
  remoteAudios.forEach((audio, targetId) => {
    setAudioOutput(audio, targetId);
    audio.play().catch(() => {});
  });
  updateSpeakerButton();
  showStatusMessage(audioOutputMode === 'speaker' ? 'Speaker on' : 'Quieter output');
}
function resetVoiceRecordingUi() {
  if (typeof setComposerRecording === 'function') setComposerRecording(false);
  const timer = document.getElementById('voiceTimer');
  if (timer) {
    timer.style.display = 'none';
    timer.textContent = '';
    timer.classList.remove('active');
  }
  if (voiceTimerInterval) {
    clearInterval(voiceTimerInterval);
    voiceTimerInterval = null;
  }
  if (typeof updateAttachButton === 'function') updateAttachButton();
  if (typeof updateComposerSend === 'function') updateComposerSend();
}
function cleanupVoiceRecorder() {
  try {
    if (mediaRecorder && mediaRecorder.state === 'recording') mediaRecorder.stop();
  } catch (e) {}
  if (voiceRecordStream) {
    voiceRecordStream.getTracks().forEach(t => t.stop());
    voiceRecordStream = null;
  }
  mediaRecorder = null;
  voiceChunks = [];
  voiceStopping = false;
  voiceRecordStartedAt = 0;
  resetVoiceRecordingUi();
}
function startVoiceRecording() {
  if (!features.enableVoice) {
    showStatusMessage('Voice notes are disabled by admin.');
    return;
  }
  if (voiceCallActive) {
    showStatusMessage('End the call before sending a voice note.');
    return;
  }
  if (mediaRecorder && mediaRecorder.state === 'recording') {
    stopVoiceRecording();
    return;
  }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia || typeof MediaRecorder === 'undefined') {
    showStatusMessage('Voice notes not supported in this browser.');
    return;
  }
  navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
  }).then(stream => {
    voiceRecordStream = stream;
    const mimeTypes = [
      'audio/webm;codecs=opus',
      'audio/mp4',
      'audio/webm',
      'audio/ogg;codecs=opus',
      'audio/ogg'
    ];
    const mimeType = (MediaRecorder.isTypeSupported && mimeTypes.find(t => MediaRecorder.isTypeSupported(t))) || '';
    try {
      mediaRecorder = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);
    } catch (e) {
      stream.getTracks().forEach(t => t.stop());
      showStatusMessage('Could not start recorder.');
      return;
    }
    voiceChunks = [];
    voiceStopping = false;
    voiceRecordStartedAt = Date.now();
    mediaRecorder.addEventListener('dataavailable', (event) => {
      if (event.data && event.data.size > 0) voiceChunks.push(event.data);
    });
    mediaRecorder.addEventListener('error', () => {
      showStatusMessage('Recording failed.');
      cleanupVoiceRecorder();
    });
    mediaRecorder.addEventListener('stop', async () => {
      const chunks = voiceChunks.slice();
      const type = mediaRecorder && mediaRecorder.mimeType ? mediaRecorder.mimeType : (mimeType || 'audio/webm');
      if (voiceRecordStream) {
        voiceRecordStream.getTracks().forEach(t => t.stop());
        voiceRecordStream = null;
      }
      mediaRecorder = null;
      voiceChunks = [];
      resetVoiceRecordingUi();
      if (typeof voiceCancelled !== 'undefined' && voiceCancelled) {
        voiceCancelled = false;
        voiceStopping = false;
        return;
      }
      const audioBlob = new Blob(chunks, { type: type.split(';')[0] });
      if (audioBlob.size < 200) {
        showStatusMessage('Voice note was empty. Hold the mic a second longer.');
        voiceStopping = false;
        return;
      }
      try {
        await prepareAndSendMessage({ type: 'voice', file: audioBlob });
      } catch (e) {
        console.error('Voice send failed', e);
        showStatusMessage('Could not send voice note.');
      }
      voiceStopping = false;
    });
    try {
      mediaRecorder.start(250);
    } catch (e) {
      try { mediaRecorder.start(); } catch (e2) {
        showStatusMessage('Could not start recording.');
        cleanupVoiceRecorder();
        return;
      }
    }
    if (typeof setComposerRecording === 'function') setComposerRecording(true);
    const timer = document.getElementById('voiceTimer');
    if (timer) {
      timer.style.display = 'flex';
      timer.classList.add('active');
      timer.textContent = '0:00';
    }
    let time = 0;
    voiceTimerInterval = setInterval(() => {
      time++;
      if (timer) timer.textContent = formatVoiceTime(time);
      if (time >= 30) stopVoiceRecording();
    }, 1000);
  }).catch(error => {
    console.error('Error starting voice recording:', error);
    cleanupVoiceRecorder();
    if (error && error.name === 'NotAllowedError') {
      showStatusMessage('Allow the microphone, then tap the mic again.');
    } else if (error && error.name === 'NotFoundError') {
      showStatusMessage('No microphone found on this device.');
    } else {
      showStatusMessage('Could not start voice note.');
    }
  });
}
function stopVoiceRecording() {
  if (voiceStopping) return;
  if (!mediaRecorder) {
    cleanupVoiceRecorder();
    return;
  }
  if (Date.now() - voiceRecordStartedAt < 400) {
    setTimeout(stopVoiceRecording, 400);
    return;
  }
  voiceStopping = true;
  try {
    if (mediaRecorder.state === 'recording') {
      try { mediaRecorder.requestData(); } catch (e) {}
      mediaRecorder.stop();
    } else {
      cleanupVoiceRecorder();
    }
  } catch (e) {
    cleanupVoiceRecorder();
  }
  setTimeout(() => {
    if (voiceStopping) cleanupVoiceRecorder();
  }, 2500);
}
async function startTotpRoom(serverGenerated) {
  const usernameInput = document.getElementById('totpUsernameInput').value.trim();
  if (!validateUsername(usernameInput)) {
    showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
    return;
  }
  username = usernameInput;
  localStorage.setItem('username', username);
  let totpSecret;
  if (serverGenerated) {
    totpSecret = generateTotpSecret();
  } else {
    totpSecret = document.getElementById('customTotpSecret').value.trim();
    const base32Regex = /^[A-Z2-7]+=*$/i;
    if (!base32Regex.test(totpSecret) || totpSecret.length < 16) {
      showStatusMessage('Invalid custom TOTP secret format (base32, min 16 chars).');
      return;
    }
  }
  let secretToSend = totpSecret.toUpperCase().replace(/=+$/, '');
  const len = secretToSend.length;
  const paddingLen = (8 - len % 8) % 8;
  secretToSend += '='.repeat(paddingLen);
  totpEnabled = true;
  code = generateCode();
  pendingTotpSecret = { display: totpSecret, send: secretToSend };
  sendJoin().catch(err => {
    console.error(err);
    showStatusMessage('Failed to create 2FA room.');
  });
  document.getElementById('totpOptionsModal').classList.remove('active');
  codeDisplayElement.textContent = `Your code: ${code}`;
  codeDisplayElement.classList.remove('hidden');
  copyCodeButton?.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  initialContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for connection...';
  document.getElementById('messageInput')?.focus();
}
function showTotpSecretModal(secret) {
  console.log('Showing TOTP modal with secret:', secret);
  document.getElementById('totpSecretDisplay').textContent = secret;
  const qrCanvas = document.getElementById('qrCodeCanvas');
  qrCanvas.innerHTML = '';
  new QRCode(qrCanvas, generateTotpUri(code, secret));
  document.getElementById('totpSecretModal').classList.add('active');
}
async function joinWithTotp(roomCode, totpCode) {
  if (roomCode) code = roomCode;
  sendJoin({ totpCode }).catch(err => {
    console.error(err);
    showStatusMessage('Failed to join 2FA room.');
  });
}
async function isWebPSupported() {
  const elem = document.createElement('canvas');
  if (!!(elem.getContext && elem.getContext('2d'))) {
    return elem.toDataURL('image/webp').indexOf('data:image/webp') === 0;
  }
  return false;
}
async function generateThumbnail(dataURL, width = 100, height = 100) {
  return new Promise((resolve) => {
    const img = new Image();
    img.src = dataURL;
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL('image/jpeg', 0.5));
    };
    img.onerror = () => resolve(dataURL); // Fallback to full if error
  });
}
// New: Cleanup old nonces every 5min
setInterval(() => {
  const now = Date.now();
  for (const [nonce, ts] of processedNonces) {
    if (now - ts > 3600000) { // 1hr = 3600000ms
      processedNonces.delete(nonce);
    }
  }
  console.log(`Cleaned processedNonces, remaining: ${processedNonces.size}`);
}, 300000); // 5min
// New: Claim username handler (in socket.onmessage or separate)
document.getElementById('claimSubmitButton').onclick = async () => {
  const name = document.getElementById('claimUsernameInput').value.trim();
  const pass = document.getElementById('claimPasswordInput').value;
  if (name && pass) {
    socket.send(JSON.stringify({ type: 'register-username', username: name, password: pass, clientId, token }));
  }
};
// New: Search user handler
document.getElementById('searchSubmitButton').onclick = () => {
  const name = document.getElementById('searchUsernameInput').value.trim();
  if (name) {
    socket.send(JSON.stringify({ type: 'find-user', username: name, clientId, token }));
  }
};
