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

function sanitizeMessage(content) {
  return DOMPurify.sanitize(content, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
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

let keepAliveTimer = null;
function startKeepAlive() {
  if (keepAliveTimer) clearInterval(keepAliveTimer);
  keepAliveTimer = setInterval(() => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'ping', clientId, token }));
      log('info', 'Sent keepalive ping');
    }
  }, 50000);
}

function stopKeepAlive() {
  if (keepAliveTimer) {
    clearInterval(keepAliveTimer);
    keepAliveTimer = null;
    log('info', 'Stopped keepalive');
  }
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
  if (remoteAudios.has(targetId)) {
    const audio = remoteAudios.get(targetId);
    audio.remove();
    remoteAudios.delete(targetId);
    if (remoteAudios.size === 0) {
      document.getElementById('remoteAudioContainer').classList.add('hidden');
    }
  }
  isConnected = dataChannels.size > 0;
  updateMaxClientsUI();
  if (!isConnected) {
    if (inputContainer) inputContainer.classList.add('hidden');
    if (messages) messages.classList.add('waiting');
  }
}

function initializeMaxClientsUI() {
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
    showStatusMessage('Error: UI initialization failed. Please refresh.');
  }
}

function updateMaxClientsUI() {
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
  }, { once: true });
  modal.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      modal.classList.remove('active');
      document.getElementById(focusId)?.focus();
    }
  }, { once: true });
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
  }, { once: true });
  modal.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      modal.classList.remove('active');
      document.getElementById(focusId)?.focus();
    }
  }, { once: true });
}

function generateTotpSecret() {
  return otplib.authenticator.generateSecret(32);
}

function generateTotpUri(roomCode, secret) {
  return otplib.authenticator.keyuri(roomCode, 'Anonomoose Chat', secret);
}

async function prepareAndSendMessage({ content, type = 'message', file = null, base64 = null }) {
  if (!username || (dataChannels.size === 0 && !useRelay)) {
    showStatusMessage('Error: Ensure you are connected and have a username.');
    return;
  }
  const now = performance.now();
  if (now - globalSendRate.startTime >= 60000) {
    globalSendRate.count = 0;
    globalSendRate.startTime = now;
  }
  if (globalSendRate.count >= 50) {
    showStatusMessage('Global message rate limit exceeded (50/min). Please wait.');
    return;
  }
  if (now - globalSizeRate.startTime >= 60000) {
    globalSizeRate.totalSize = 0;
    globalSizeRate.startTime = now;
  }
  const payloadSize = (content || base64 || '').length * 3 / 4;
  if (globalSizeRate.totalSize + payloadSize > 1048576) {
    showStatusMessage('Message size limit exceeded (1MB/min total). Please wait.');
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
  if (now - rateLimit.startTime >= 60000) {
    rateLimit.count = 0;
    rateLimit.startTime = now;
  }
  rateLimit.count += 1;
  rateLimitsMap.set(clientId, rateLimit);
  if (rateLimit.count > 5) {
    showStatusMessage(`${type.charAt(0).toUpperCase() + type.slice(1)} rate limit reached (5/min). Please wait.`);
    return;
  }
  if (file && type === 'image') {
    const maxWidth = 640;
    const maxHeight = 360;
    let quality = 0.4;
    if (file.size > 3 * 1024 * 1024) quality = 0.3;
    else if (file.size > 1 * 1024 * 1024) quality = 0.35;
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
    const format = await isWebPSupported() ? 'image/webp' : 'image/jpeg';
    dataToSend = canvas.toDataURL(format, quality);
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
  const jitter = Math.floor(Math.random() * 61) - 30;
  const jitteredTimestamp = timestamp + jitter * 1000;
  const nonce = crypto.randomUUID();
  const sanitizedContent = content ? sanitizeMessage(content) : null;
  const messageKey = await deriveMessageKey();
  const metadata = JSON.stringify({ username, timestamp: jitteredTimestamp, type });
  let rawData = metadata + (dataToSend || sanitizedContent);
  const paddedLength = Math.min(Math.ceil(rawData.length / 512) * 512, 5 * 1024 * 1024);
  rawData = rawData.padEnd(paddedLength, ' ');
  const { encrypted, iv } = await encryptRaw(messageKey, rawData);
  const toSign = rawData + nonce;
  const signature = await signMessage(signingKey, toSign);
  let payload = { messageId, nonce, iv, signature, encryptedBlob: encrypted };
  if (dataToSend && type === 'file') {
    payload.filename = file?.name;
  }
  const jsonString = JSON.stringify(payload);
  if (useRelay) {
    sendRelayMessage(`relay-${type}`, payload);
  } else if (dataChannels.size > 0) {
    if (jsonString.length > CHUNK_SIZE) {
      const chunkId = generateMessageId();
      const chunks = [];
      for (let i = 0; i < jsonString.length; i += CHUNK_SIZE) {
        chunks.push(jsonString.slice(i, i + CHUNK_SIZE));
      }
      for (const dataChannel of dataChannels.values()) {
        if (dataChannel.readyState === 'open') {
          for (let index = 0; index < chunks.length; index++) {
            const chunk = chunks[index];
            dataChannel.send(JSON.stringify({ chunk: true, chunkId, index, total: chunks.length, data: chunk }));
            await new Promise(resolve => setTimeout(resolve, 1));
          }
        }
      }
    } else {
      for (const dataChannel of dataChannels.values()) {
        if (dataChannel.readyState === 'open') {
          dataChannel.send(jsonString);
        }
      }
    }
  } else {
    showStatusMessage('Error: No connections.');
    return;
  }
  globalSendRate.count += 1;
  globalSizeRate.totalSize += payloadSize;
  const messagesElement = document.getElementById('messages');
  const messageDiv = document.createElement('div');
  messageDiv.className = 'message-bubble self';
  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = new Date(timestamp).toLocaleTimeString();
  messageDiv.appendChild(timeSpan);
  messageDiv.appendChild(document.createTextNode(`${username}: `));
  if (type === 'image' || type === 'voice' || type === 'file') {
    let element;
    if (type === 'image') {
      element = document.createElement('img');
      element.dataset.src = dataToSend;
      element.style.maxWidth = '100%';
      element.style.borderRadius = '0.5rem';
      element.style.cursor = 'pointer';
      element.setAttribute('alt', 'Sent image');
      element.addEventListener('click', () => createImageModal(dataToSend, `${type}Button`));
      lazyObserver.observe(element);
    } else if (type === 'voice') {
      element = document.createElement('audio');
      element.dataset.src = dataToSend;
      element.controls = true;
      element.setAttribute('alt', 'Sent voice message');
      element.addEventListener('click', () => createAudioModal(dataToSend, `${type}Button`));
      lazyObserver.observe(element);
    } else {
      element = document.createElement('a');
      element.href = dataToSend;
      element.download = file.name;
      element.textContent = `Download ${file.name}`;
      element.setAttribute('alt', 'Sent file');
    }
    messageDiv.appendChild(element);
  } else {
    messageDiv.appendChild(document.createTextNode(sanitizedContent));
  }
  messagesElement.prepend(messageDiv);
  messagesElement.scrollTop = 0;
  processedMessageIds.add(messageId);
  processedNonces.set(nonce, Date.now());
  messageCount++;
  if (isInitiator && messageCount % 100 === 0) {
    await triggerRatchet();
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
}

async function sendMedia(file, type) {
  const validTypes = {
    image: ['image/jpeg', 'image/png'],
    voice: ['audio/webm', 'audio/ogg', 'audio/mp4']
  };
  if (type !== 'file' && !validTypes[type]?.includes(file.type)) {
    showStatusMessage(`Error: Invalid file type for ${type}.`);
    return;
  }
  await prepareAndSendMessage({ type, file });
  document.getElementById(`${type}Button`)?.focus();
}

async function startPeerConnection(targetId, isOfferer) {
  console.log(`Starting peer connection with ${targetId} for code: ${code}, offerer: ${isOfferer}`);
  if (!features.enableP2P) {
    console.log('P2P disabled by admin, forcing relay mode');
    useRelay = true;
    const privacyStatus = document.getElementById('privacyStatus');
    if (privacyStatus) {
      privacyStatus.textContent = 'Relay Mode (E2EE)';
      privacyStatus.classList.remove('hidden');
    }
    isConnected = true;
    inputContainer.classList.remove('hidden');
    messages.classList.remove('waiting');
    updateMaxClientsUI();
    return;
  }
  if (peerConnections.has(targetId)) {
    console.log(`Cleaning up existing connection with ${targetId}`);
    cleanupPeerConnection(targetId);
  }
  const peerConnection = new RTCPeerConnection({
    iceServers: [
      { urls: "stun:stun.relay.metered.ca:80" },
      {
        urls: "turn:global.relay.metered.ca:80",
        username: turnUsername,
        credential: turnCredential
      },
      {
        urls: "turn:global.relay.metered.ca:80?transport=tcp",
        username: turnUsername,
        credential: turnCredential
      },
      {
        urls: "turn:global.relay.metered.ca:443",
        username: turnUsername,
        credential: turnCredential
      },
      {
        urls: "turns:global.relay.metered.ca:443?transport=tcp",
        username: turnUsername,
        credential: turnCredential
      }
    ],
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
      console.log(`Connection failed with ${targetId}`);
      cleanupPeerConnection(targetId);
      const retryCount = retryCounts.get(targetId) || 0;
      if (retryCount < maxRetries) {
        retryCounts.set(targetId, retryCount + 1);
        console.log(`Retrying connection attempt ${retryCount + 1} with ${targetId}`);
        startPeerConnection(targetId, isOfferer);
      }
    } else if (peerConnection.connectionState === 'connected') {
      console.log(`WebRTC connection established with ${targetId} for code: ${code}`);
      isConnected = true;
      retryCounts.delete(targetId);
      clearTimeout(connectionTimeouts.get(targetId));
      updateMaxClientsUI();
      const privacyStatus = document.getElementById('privacyStatus');
      if (privacyStatus) {
        privacyStatus.textContent = 'E2E Encrypted (P2P)';
        privacyStatus.classList.remove('hidden');
      }
    }
  };
  peerConnection.ontrack = (event) => {
    console.log(`Received remote track from ${targetId}`);
    if (!remoteAudios.has(targetId)) {
      const audio = document.createElement('audio');
      audio.srcObject = event.streams[0];
      audio.autoplay = true;
      audio.volume = audioOutputMode === 'earpiece' ? 0.5 : 1.0;
      audio.play().catch(error => console.error('Error playing remote audio:', error));
      remoteAudios.set(targetId, audio);
      document.getElementById('remoteAudioContainer').appendChild(audio);
      document.getElementById('remoteAudioContainer').classList.remove('hidden');
      setAudioOutput(audio, targetId);
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
    if (!dataChannels.get(targetId) || dataChannels.get(targetId).readyState !== 'open') {
      console.log(`P2P failed with ${targetId}, checking relay availability`);
      if (features.enableRelay) {
        useRelay = true;
        const privacyStatus = document.getElementById('privacyStatus');
        if (privacyStatus) {
          privacyStatus.textContent = 'Relay Mode (E2EE)';
          privacyStatus.classList.remove('hidden');
        }
        isConnected = true;
        inputContainer.classList.remove('hidden');
        messages.classList.remove('waiting');
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
    initialContainer.classList.add('hidden');
    usernameContainer.classList.add('hidden');
    connectContainer.classList.add('hidden');
    chatContainer.classList.remove('hidden');
    newSessionButton.classList.remove('hidden');
    inputContainer.classList.remove('hidden');
    messages.classList.remove('waiting');
    clearTimeout(connectionTimeouts.get(targetId));
    retryCounts.delete(targetId);
    updateMaxClientsUI();
    document.getElementById('messageInput')?.focus();
    if (features.enableVoiceCalls && features.enableAudioToggle) {
      document.getElementById('audioOutputButton').classList.remove('hidden');
    } else {
      document.getElementById('audioOutputButton').classList.add('hidden');
    }
  };
  dataChannel.onmessage = async (event) => {
    const now = performance.now();
    const rateLimit = messageRateLimits.get(targetId) || { count: 0, startTime: now };
    if (now - rateLimit.startTime >= 1000) {
      rateLimit.count = 0;
      rateLimit.startTime = now;
    }
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
    rateLimit.count += 1;
    messageRateLimits.set(targetId, rateLimit);
    if (rateLimit.count > 10) {
      console.warn(`Rate limit exceeded for ${targetId}: ${rateLimit.count} messages in 1s`);
      showStatusMessage('Message rate limit reached, please slow down.');
      return;
    }
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
      inputContainer.classList.add('hidden');
      messages.classList.add('waiting');
      document.getElementById('audioOutputButton').classList.add('hidden');
    }
  };
}

async function processReceivedMessage(data, targetId) {
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
  if (!data.messageId || !data.encryptedBlob) {
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
    const messageKey = await deriveMessageKey();
    const rawData = await decryptRaw(messageKey, data.encryptedBlob, data.iv);
    const toVerify = rawData + data.nonce;
    const valid = await verifyMessage(signingKey, data.signature, toVerify);
    if (!valid) {
      console.warn(`Invalid signature for message from ${targetId}`);
      showStatusMessage('Invalid message signature detected.');
      return;
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
    senderUsername = metadata.username;
    timestamp = metadata.timestamp;
    contentType = metadata.type;
    contentOrData = rawData.substring(metadataStr.length).trimEnd();
  } catch (error) {
    console.error(`Decryption/verification failed for message from ${targetId}:`, error);
    showStatusMessage('Failed to decrypt/verify message.');
    return;
  }
  const messages = document.getElementById('messages');
  const isSelf = senderUsername === username;
  const messageDiv = document.createElement('div');
  messageDiv.className = `message-bubble ${isSelf ? 'self' : 'other'}`;
  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = new Date(timestamp).toLocaleTimeString();
  messageDiv.appendChild(timeSpan);
  messageDiv.appendChild(document.createTextNode(`${senderUsername}: `));
  if (contentType === 'image') {
    const img = document.createElement('img');
    img.dataset.src = contentOrData;
    img.style.maxWidth = '100%';
    img.style.borderRadius = '0.5rem';
    img.style.cursor = 'pointer';
    img.setAttribute('alt', 'Received image');
    img.addEventListener('click', () => createImageModal(contentOrData, 'messageInput'));
    lazyObserver.observe(img);
    messageDiv.appendChild(img);
  } else if (contentType === 'voice') {
    const audio = document.createElement('audio');
    audio.dataset.src = contentOrData;
    audio.controls = true;
    audio.setAttribute('alt', 'Received voice message');
    audio.addEventListener('click', () => createAudioModal(contentOrData, 'messageInput'));
    lazyObserver.observe(audio);
    messageDiv.appendChild(audio);
  } else if (contentType === 'file') {
    const link = document.createElement('a');
    link.href = contentOrData;
    link.download = data.filename || 'file';
    link.textContent = `Download ${data.filename || 'file'}`;
    link.setAttribute('alt', 'Received file');
    messageDiv.appendChild(link);
  } else {
    messageDiv.appendChild(document.createTextNode(sanitizeMessage(contentOrData)));
  }
  messages.prepend(messageDiv);
  messages.scrollTop = 0;
  if (isInitiator) {
    dataChannels.forEach((dc, id) => {
      if (id !== targetId && dc.readyState === 'open') {
        dc.send(JSON.stringify(data));
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
      await peerConnection.setLocalDescription({ type: 'rollback' });
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

async function startVoiceCall() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showStatusMessage('Microphone not supported.');
    return;
  }
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    peerConnections.forEach((peerConnection, targetId) => {
      localStream.getTracks().forEach(track => {
        peerConnection.addTrack(track, localStream);
      });
      renegotiate(targetId);
    });
    voiceCallActive = true;
    document.getElementById('voiceCallButton').classList.add('active');
    document.getElementById('voiceCallButton').title = 'End Voice Call';
    document.getElementById('audioOutputButton').classList.remove('hidden');
    showStatusMessage('Voice call started.');
  } catch (error) {
    console.error('Error starting voice call:', error);
    showStatusMessage('Failed to access microphone for voice call.');
  }
}

function stopVoiceCall() {
  if (localStream) {
    localStream.getTracks().forEach(track => track.stop());
    localStream = null;
  }
  peerConnections.forEach((peerConnection, targetId) => {
    peerConnection.getSenders().forEach(sender => {
      if (sender.track && sender.track.kind === 'audio') {
        peerConnection.removeTrack(sender);
      }
    });
    renegotiate(targetId);
  });
  voiceCallActive = false;
  document.getElementById('voiceCallButton').classList.remove('active');
  document.getElementById('voiceCallButton').title = 'Start Voice Call';
  document.getElementById('audioOutputButton').classList.add('hidden');
  showStatusMessage('Voice call ended.');
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

function sendSignalingMessage(type, additionalData) {
  if (!token || refreshingToken) {
    console.log('Token missing or refresh in progress, queuing signaling message');
    if (!signalingQueue.has('global')) signalingQueue.set('global', []);
    signalingQueue.get('global').push({ type, additionalData });
    if (!refreshingToken) refreshAccessToken();
    return;
  }
  const message = { type, ...additionalData, code, clientId, token };
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
  } else {
    console.log('Socket not open, queuing signaling message');
    if (!signalingQueue.has('global')) signalingQueue.set('global', []);
    signalingQueue.get('global').push({ type, additionalData });
  }
}

function broadcastVoiceCallEvent(eventType) {
  dataChannels.forEach((dataChannel) => {
    if (dataChannel.readyState === 'open') {
      dataChannel.send(JSON.stringify({ type: eventType }));
    }
  });
}

function sendRelayMessage(type, additionalData) {
  if (!token || refreshingToken) {
    console.log('Token missing or refresh in progress, queuing relay message');
    if (!signalingQueue.has('global')) signalingQueue.set('global', []);
    signalingQueue.get('global').push({ type, additionalData });
    if (!refreshingToken) refreshAccessToken();
    return;
  }
  const message = { type, ...additionalData, code, clientId, token };
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
  } else {
    console.log('Socket not open, queuing relay message');
    if (!signalingQueue.has('global')) signalingQueue.set('global', []);
    signalingQueue.get('global').push({ type, additionalData });
  }
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

async function autoConnect(codeParam) {
  console.log('autoConnect running with code:', codeParam);
  code = codeParam;
  initialContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  if (validateCode(codeParam)) {
    if (validateUsername(username)) {
      console.log('Valid username and code, joining chat');
      codeDisplayElement.textContent = `Using code: ${code}`;
      codeDisplayElement.classList.remove('hidden');
      copyCodeButton.classList.remove('hidden');
      messages.classList.add('waiting');
      statusElement.textContent = 'Waiting for connection...';
      if (socket.readyState === WebSocket.OPEN) {
        console.log('Sending check-totp');
        socket.send(JSON.stringify({ type: 'check-totp', code: codeParam, clientId, token }));
      } else {
        console.log('WebSocket not open, waiting for open event to send check-totp');
        socket.addEventListener('open', () => {
          console.log('WebSocket opened, sent check-totp');
          socket.send(JSON.stringify({ type: 'check-totp', code: codeParam, clientId, token }));
        }, { once: true });
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
        copyCodeButton.classList.remove('hidden');
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
  const imageButton = document.getElementById('imageButton');
  const voiceButton = document.getElementById('voiceButton');
  const voiceCallButton = document.getElementById('voiceCallButton');
  const audioOutputButton = document.getElementById('audioOutputButton');
  const grokButton = document.getElementById('grokButton');
  if (imageButton) {
    imageButton.classList.toggle('hidden', !features.enableImages);
    imageButton.title = features.enableImages ? 'Send Image/File' : 'Images/Files disabled by admin';
  }
  if (voiceButton) {
    voiceButton.classList.toggle('hidden', !features.enableVoice);
    voiceButton.title = features.enableVoice ? 'Record Voice' : 'Voice disabled by admin';
  }
  if (voiceCallButton) {
    voiceCallButton.classList.toggle('hidden', !features.enableVoiceCalls);
    voiceCallButton.title = features.enableVoiceCalls ? 'Start Voice Call' : 'Voice calls disabled by admin';
    if (!features.enableVoiceCalls && voiceCallActive) {
      stopVoiceCall();
    }
  }
  if (audioOutputButton) {
    const shouldHide = !features.enableAudioToggle || !voiceCallActive || !features.enableVoiceCalls;
    audioOutputButton.classList.toggle('hidden', shouldHide);
    if (shouldHide && voiceCallActive) {
      stopVoiceCall();
    }
    audioOutputButton.title = audioOutputMode === 'earpiece' ? 'Switch to Speaker' : 'Switch to Earpiece';
    audioOutputButton.textContent = audioOutputMode === 'earpiece' ? '🔊' : '📞';
    audioOutputButton.classList.toggle('speaker', audioOutputMode === 'speaker');
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
      body: JSON.stringify({
        model: 'grok-4',
        messages: [{ role: 'user', content: query }]
      })
    });
    if (!response.ok) {
      throw new Error(`API error: ${response.statusText}`);
    }
    const data = await response.json();
    const botResponse = data.choices[0].message.content;
    const messages = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message-bubble other';
    const timeSpan = document.createElement('span');
    timeSpan.className = 'timestamp';
    timeSpan.textContent = new Date().toLocaleTimeString();
    messageDiv.appendChild(timeSpan);
    messageDiv.appendChild(document.createTextNode(`Grok Bot: ${sanitizeMessage(botResponse)}`));
    messages.prepend(messageDiv);
    messages.scrollTop = 0;
  } catch (error) {
    console.error('Grok API error:', error);
    showStatusMessage('Error querying Grok: ' + error.message + '. Check your API key or visit https://x.ai/api for details.');
  }
}

async function setAudioOutput(audioElement, targetId) {
  try {
    if ('setSinkId' in audioElement && navigator.mediaDevices.getUserMedia) {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const audioOutputs = devices.filter(device => device.kind === 'audiooutput');
      if (audioOutputs.length > 0) {
        const targetDevice = audioOutputMode === 'speaker'
          ? audioOutputs.find(device => device.label.toLowerCase().includes('speaker') || device.deviceId === 'default')
          : audioOutputs.find(device => device.label.toLowerCase().includes('earpiece') || device.deviceId === 'default') || audioOutputs[0];
        if (targetDevice) {
          await audioElement.setSinkId(targetDevice.deviceId);
          console.log(`Set audio output for ${targetId} to ${targetDevice.label}`);
        } else {
          console.warn(`No suitable ${audioOutputMode} device found for ${targetId}, using default`);
          audioElement.volume = audioOutputMode === 'earpiece' ? 0.5 : 1.0;
        }
      } else {
        console.warn(`No audio output devices available for ${targetId}`);
        audioElement.volume = audioOutputMode === 'earpiece' ? 0.5 : 1.0;
      }
    } else {
      console.log(`setSinkId not supported, using volume adjustment for ${targetId}`);
      audioElement.volume = audioOutputMode === 'earpiece' ? 0.5 : 1.0;
    }
  } catch (error) {
    console.error(`Error setting audio output for ${targetId}:`, error);
    audioElement.volume = audioOutputMode === 'earpiece' ? 0.5 : 1.0;
  }
}

async function generateUserKeypair() {
  const keypair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const privateJwk = await window.crypto.subtle.exportKey('jwk', keypair.privateKey);
  const publicBase64 = await exportPublicKey(keypair.publicKey);
  localStorage.setItem('userPrivateKey', JSON.stringify(privateJwk));
  userPrivateKey = privateJwk;
  userPublicKey = publicBase64;
  return publicBase64;
}

async function sendOfflineMessage(to_username, messageText) {
  if (!userPrivateKey) {
    showStatusMessage('No private key. Please re-claim username on this device.');
    return;
  }
  const ephemeralKeypair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    false,
    ['deriveKey', 'deriveBits']
  );
  const recipientPublic = await importPublicKey(userPublicKey);
  const shared = await deriveSharedKey(ephemeralKeypair.privateKey, recipientPublic);
  const { encrypted, iv } = await encryptRaw(shared, messageText);
  const ephemeralPublic = await exportPublicKey(ephemeralKeypair.publicKey);
  console.log('Sending offline message:', { to_username, encrypted, iv, ephemeral_public: ephemeralPublic });
  socket.send(JSON.stringify({
    type: 'send-offline-message',
    to_username,
    encrypted,
    iv,
    ephemeral_public: ephemeralPublic,
    clientId,
    token
  }));
  showStatusMessage('Offline message sent.');
}

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
let userPrivateKey = localStorage.getItem('userPrivateKey');
let userPublicKey;
const imageRateLimits = new Map();
const voiceRateLimits = new Map();
let globalMessageRate = { count: 0, startTime: Date.now() };
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
let socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
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
let lazyObserver;

// Expose globals to main2.js
window.showStatusMessage = showStatusMessage;
window.sanitizeMessage = sanitizeMessage;
window.generateMessageId = generateMessageId;
window.validateUsername = validateUsername;
window.validateCode = validateCode;
window.startKeepAlive = startKeepAlive;
window.stopKeepAlive = stopKeepAlive;
window.cleanupPeerConnection = cleanupPeerConnection;
window.initializeMaxClientsUI = initializeMaxClientsUI;
window.updateMaxClientsUI = updateMaxClientsUI;
window.setMaxClients = setMaxClients;
window.log = log;
window.createImageModal = createImageModal;
window.createAudioModal = createAudioModal;
window.generateTotpSecret = generateTotpSecret;
window.generateTotpUri = generateTotpUri;
window.prepareAndSendMessage = prepareAndSendMessage;
window.sendMessage = sendMessage;
window.sendMedia = sendMedia;
window.startPeerConnection = startPeerConnection;
window.setupDataChannel = setupDataChannel;
window.processReceivedMessage = processReceivedMessage;
window.handleOffer = handleOffer;
window.handleAnswer = handleAnswer;
window.handleCandidate = handleCandidate;
window.processCandidateQueue = processCandidateQueue;
window.toggleVoiceCall = toggleVoiceCall;
window.startVoiceCall = startVoiceCall;
window.stopVoiceCall = stopVoiceCall;
window.renegotiate = renegotiate;
window.sendSignalingMessage = sendSignalingMessage;
window.broadcastVoiceCallEvent = broadcastVoiceCallEvent;
window.sendRelayMessage = sendRelayMessage;
window.processSignalingQueue = processSignalingQueue;
window.autoConnect = autoConnect;
window.updateFeaturesUI = updateFeaturesUI;
window.sendToGrok = sendToGrok;
window.setAudioOutput = setAudioOutput;
window.generateUserKeypair = generateUserKeypair;
window.sendOfflineMessage = sendOfflineMessage;
window.turnUsername = turnUsername;
window.turnCredential = turnCredential;
window.localStream = localStream;
window.voiceCallActive = voiceCallActive;
window.grokBotActive = grokBotActive;
window.grokApiKey = grokApiKey;
window.renegotiating = renegotiating;
window.audioOutputMode = audioOutputMode;
window.totpEnabled = totpEnabled;
window.totpSecret = totpSecret;
window.pendingTotpSecret = pendingTotpSecret;
window.mediaRecorder = mediaRecorder;
window.voiceChunks = voiceChunks;
window.voiceTimerInterval = voiceTimerInterval;
window.messageCount = messageCount;
window.CHUNK_SIZE = CHUNK_SIZE;
window.chunkBuffers = chunkBuffers;
window.negotiationQueues = negotiationQueues;
window.globalSendRate = globalSendRate;
window.renegotiationCounts = renegotiationCounts;
window.maxRenegotiations = maxRenegotiations;
window.keyVersion = keyVersion;
window.globalSizeRate = globalSizeRate;
window.processedNonces = processedNonces;
window.userPrivateKey = userPrivateKey;
window.userPublicKey = userPublicKey;
window.imageRateLimits = imageRateLimits;
window.voiceRateLimits = voiceRateLimits;
window.globalMessageRate = globalMessageRate;
window.code = code;
window.clientId = clientId;
window.username = username;
window.isInitiator = isInitiator;
window.isConnected = isConnected;
window.maxClients = maxClients;
window.totalClients = totalClients;
window.peerConnections = peerConnections;
window.dataChannels = dataChannels;
window.connectionTimeouts = connectionTimeouts;
window.retryCounts = retryCounts;
window.maxRetries = maxRetries;
window.candidatesQueues = candidatesQueues;
window.processedMessageIds = processedMessageIds;
window.usernames = usernames;
window.messageRateLimits = messageRateLimits;
window.codeSentToRandom = codeSentToRandom;
window.useRelay = useRelay;
window.token = token;
window.refreshToken = refreshToken;
window.features = features;
window.keyPair = keyPair;
window.roomMaster = roomMaster;
window.signingKey = signingKey;
window.signingSalt = signingSalt;
window.messageSalt = messageSalt;
window.remoteAudios = remoteAudios;
window.refreshingToken = refreshingToken;
window.signalingQueue = signalingQueue;
window.connectedClients = connectedClients;
window.clientPublicKeys = clientPublicKeys;
window.initiatorPublic = initiatorPublic;
window.socket = socket;
window.statusElement = statusElement;
window.codeDisplayElement = codeDisplayElement;
window.copyCodeButton = copyCodeButton;
window.initialContainer = initialContainer;
window.usernameContainer = usernameContainer;
window.connectContainer = connectContainer;
window.chatContainer = chatContainer;
window.newSessionButton = newSessionButton;
window.maxClientsContainer = maxClientsContainer;
window.inputContainer = inputContainer;
window.messages = messages;
window.cornerLogo = cornerLogo;
window.button2 = button2;
window.helpText = helpText;
window.helpModal = helpModal;
window.lazyObserver = lazyObserver;