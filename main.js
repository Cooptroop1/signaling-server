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
const CHUNK_SIZE = 8192; // Reduced to 8KB for better mobile compatibility
const chunkBuffers = new Map(); // {chunkId: {chunks: [], total: m}}
const negotiationQueues = new Map(); // Queue pending negotiations per peer

async function sendMedia(file, type) {
  const validTypes = {
    image: ['image/jpeg', 'image/png'],
    voice: ['audio/webm', 'audio/ogg', 'audio/mp4']
  };
  if ((type === 'image' && !features.enableImages) || (type === 'voice' && !features.enableVoice)) {
    showStatusMessage(`Error: ${type.charAt(0).toUpperCase() + type.slice(1)} messages are disabled by admin.`);
    document.getElementById(`${type}Button`)?.focus();
    return;
  }
  if (!file || (type !== 'file' && !validTypes[type]?.includes(file.type)) || !username || dataChannels.size === 0 && !useRelay) {
    showStatusMessage(`Error: Select a ${type === 'image' ? 'JPEG/PNG image' : type === 'voice' ? 'valid audio format' : 'valid file'} and ensure you are connected.`);
    document.getElementById(`${type}Button`)?.focus();
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    showStatusMessage(`Error: ${type.charAt(0).toUpperCase() + type.slice(1)} size exceeds 5MB limit.`);
    document.getElementById(`${type}Button`)?.focus();
    return;
  }
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
    const format = isWebPSupported() ? 'image/webp' : 'image/jpeg';
    base64 = canvas.toDataURL(format, quality);
    URL.revokeObjectURL(img.src);
  } else if (type === 'voice') {
    base64 = await new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.readAsDataURL(file);
    });
  } else {
    base64 = await new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.readAsDataURL(file);
    });
  }
  const messageId = generateMessageId();
  const timestamp = Date.now();
  let payload = { messageId, type, username, timestamp };
  let dataToSend = base64;
  if (!useRelay) {
    const messageKey = await deriveMessageKey(roomMaster);
    const { encrypted, iv } = await encryptRaw(messageKey, dataToSend);
    const toSign = dataToSend + timestamp;
    payload.signature = await signMessage(signingKey, toSign);
    payload.encryptedData = encrypted;
    payload.iv = iv;
    payload.filename = type === 'file' ? file.name : undefined;
  } else {
    payload.data = base64;
    payload.filename = type === 'file' ? file.name : undefined;
  }
  const jsonString = JSON.stringify(payload);
  if (useRelay) {
    sendRelayMessage(`relay-${type}`, { data: base64, messageId, username, timestamp, filename: type === 'file' ? file.name : undefined });
  } else if (dataChannels.size > 0) {
    if (jsonString.length > CHUNK_SIZE) {
      const chunkId = generateMessageId();
      const chunks = [];
      for (let i = 0; i < jsonString.length; i += CHUNK_SIZE) {
        chunks.push(jsonString.slice(i, i + CHUNK_SIZE));
      }
      dataChannels.forEach(async (dataChannel) => {
        if (dataChannel.readyState === 'open') {
          for (let index = 0; index < chunks.length; index++) {
            const chunk = chunks[index];
            dataChannel.send(JSON.stringify({ chunk: true, chunkId, index, total: chunks.length, data: chunk }));
            await new Promise(resolve => setTimeout(resolve, 1)); // Small delay to prevent burst
          }
        }
      });
    } else {
      dataChannels.forEach((dataChannel) => {
        if (dataChannel.readyState === 'open') {
          dataChannel.send(jsonString);
        }
      });
    }
  } else {
    showStatusMessage('Error: No connections.');
    return;
  }
  const messages = document.getElementById('messages');
  const messageDiv = document.createElement('div');
  messageDiv.className = 'message-bubble self';
  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = new Date(timestamp).toLocaleTimeString();
  messageDiv.appendChild(timeSpan);
  messageDiv.appendChild(document.createTextNode(`${username}: `));
  if (type === 'image') {
    const imgElement = document.createElement('img');
    imgElement.src = base64;
    imgElement.style.maxWidth = '100%';
    imgElement.style.borderRadius = '0.5rem';
    imgElement.style.cursor = 'pointer';
    imgElement.setAttribute('alt', 'Sent image');
    imgElement.addEventListener('click', () => createImageModal(base64, `${type}Button`));
    messageDiv.appendChild(imgElement);
  } else if (type === 'voice') {
    const audioElement = document.createElement('audio');
    audioElement.src = base64;
    audioElement.controls = true;
    audioElement.setAttribute('alt', 'Sent voice message');
    audioElement.addEventListener('click', () => createAudioModal(base64, `${type}Button`));
    messageDiv.appendChild(audioElement);
  } else {
    const link = document.createElement('a');
    link.href = base64;
    link.download = file.name;
    link.textContent = `Download ${file.name}`;
    link.setAttribute('alt', 'Sent file');
    messageDiv.appendChild(link);
  }
  messages.prepend(messageDiv);
  messages.scrollTop = 0;
  processedMessageIds.add(messageId);
  document.getElementById(`${type}Button`)?.focus();
  messageCount++;
  if (isInitiator && messageCount % 100 === 0) {
    triggerRatchet();
  }
}

async function startPeerConnection(targetId, isOfferer) {
  console.log(`Starting peer connection with ${targetId} for code: ${code}, offerer: ${isOfferer}`);
  if (!features.enableP2P) {
    console.log('P2P disabled by admin, forcing relay mode');
    useRelay = true;
    const privacyStatus = document.getElementById('privacyStatus');
    if (privacyStatus) {
      privacyStatus.textContent = 'Relay Mode';
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
      showStatusMessage('Peer connection failed, attempting to reconnect...');
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
      showStatusMessage('Failed to establish peer connection.');
    });
  }
  const timeout = setTimeout(() => {
    if (!dataChannels.get(targetId) || dataChannels.get(targetId).readyState !== 'open') {
      console.log(`P2P failed with ${targetId}, checking relay availability`);
      if (features.enableRelay) {
        useRelay = true;
        showStatusMessage('P2P connection failed, switching to server relay mode.');
        const privacyStatus = document.getElementById('privacyStatus');
        if (privacyStatus) {
          privacyStatus.textContent = 'Relay Mode';
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
      // Don't count chunks toward rate limit
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
        // Process the reassembled message
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
    // Count non-chunk messages
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
    showStatusMessage('Error in peer connection.');
  };
  dataChannel.onclose = () => {
    console.log(`Data channel closed with ${targetId}`);
    showStatusMessage('Peer disconnected.');
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

function processReceivedMessage(data, targetId) {
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
  if (!data.messageId || !data.username || (!data.content && !data.data && !data.encryptedContent && !data.encryptedData)) {
    console.log(`Invalid message format from ${targetId}:`, data);
    return;
  }
  if (processedMessageIds.has(data.messageId)) {
    console.log(`Duplicate message ${data.messageId} from ${targetId}`);
    return;
  }
  processedMessageIds.add(data.messageId);
  const senderUsername = usernames.get(targetId) || data.username;
  const messages = document.getElementById('messages');
  const isSelf = senderUsername === username;
  const messageDiv = document.createElement('div');
  messageDiv.className = `message-bubble ${isSelf ? 'self' : 'other'}`;
  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = new Date(data.timestamp).toLocaleTimeString();
  messageDiv.appendChild(timeSpan);
  messageDiv.appendChild(document.createTextNode(`${senderUsername}: `));
  let contentOrData = data.content || data.data;
  if (data.encryptedContent || data.encryptedData) {
    try {
      const messageKey = deriveMessageKey(roomMaster);
      const encrypted = data.encryptedContent || data.encryptedData;
      const iv = data.iv;
      contentOrData = decryptRaw(messageKey, encrypted, iv);
      const toVerify = contentOrData + data.timestamp;
      const valid = verifyMessage(signingKey, data.signature, toVerify);
      if (!valid) {
        console.warn(`Invalid signature for message from ${targetId}`);
        showStatusMessage('Invalid message signature detected.');
        return;
      }
    } catch (error) {
      console.error(`Decryption/verification failed for message from ${targetId}:`, error);
      showStatusMessage('Failed to decrypt/verify message.');
      return;
    }
  }
  if (data.type === 'image') {
    const img = document.createElement('img');
    img.src = contentOrData;
    img.style.maxWidth = '100%';
    img.style.borderRadius = '0.5rem';
    img.style.cursor = 'pointer';
    img.setAttribute('alt', 'Received image');
    img.addEventListener('click', () => createImageModal(contentOrData, 'messageInput'));
    messageDiv.appendChild(img);
  } else if (data.type === 'voice') {
    const audio = document.createElement('audio');
    audio.src = contentOrData;
    audio.controls = true;
    audio.setAttribute('alt', 'Received voice message');
    audio.addEventListener('click', () => createAudioModal(contentOrData, 'messageInput'));
    messageDiv.appendChild(audio);
  } else if (data.type === 'file') {
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
        dc.send(event.data);
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
    queue.forEach(candidate => {
      handleCandidate(candidate, targetId);
    });
    candidatesQueues.set(targetId, []);
  } catch (error) {
    console.error(`Error handling offer from ${targetId}:`, error);
    showStatusMessage('Failed to connect to peer.');
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
    queue.forEach(item => {
      if (item.type === 'answer') {
        peerConnection.setRemoteDescription(new RTCSessionDescription(item.answer)).catch(error => {
          console.error(`Error applying queued answer from ${targetId}:`, error);
          if (error.name !== 'InvalidStateError') {
            showStatusMessage('Error processing peer response.');
          }
        });
      } else {
        handleCandidate(item.candidate, targetId);
      }
    });
    candidatesQueues.set(targetId, []);
  } catch (error) {
    console.error(`Error handling answer from ${targetId}:`, error);
    if (error.name !== 'InvalidStateError') {
      showStatusMessage('Error connecting to peer.');
    }
  }
}

function handleCandidate(candidate, targetId) {
  console.log(`Handling ICE candidate from ${targetId} for code: ${code}`);
  if (candidate.sdpMid === null && candidate.sdpMLineIndex === null) {
    console.warn(`Ignoring invalid ICE candidate from ${targetId}: both sdpMid and sdpMLineIndex null`);
    return;
  }
  const peerConnection = peerConnections.get(targetId);
  if (peerConnection && peerConnection.remoteDescription) {
    peerConnection.addIceCandidate(new RTCIceCandidate(candidate)).catch(error => {
      console.error(`Error adding ICE candidate from ${targetId}:`, error);
      showStatusMessage('Error establishing peer connection.');
    });
  } else {
    const queue = candidatesQueues.get(targetId) || [];
    queue.push({ type: 'candidate', candidate });
    candidatesQueues.set(targetId, queue);
  }
}

module.exports = {
  turnUsername,
  turnCredential,
  localStream,
  voiceCallActive,
  grokBotActive,
  grokApiKey,
  renegotiating,
  audioOutputMode,
  totpEnabled,
  totpSecret,
  pendingTotpSecret,
  mediaRecorder,
  voiceChunks,
  voiceTimerInterval,
  messageCount,
  CHUNK_SIZE,
  chunkBuffers,
  negotiationQueues,
  sendMedia,
  startPeerConnection,
  setupDataChannel,
  processReceivedMessage,
  handleOffer,
  handleAnswer,
  handleCandidate
};

require('./main2.js');
