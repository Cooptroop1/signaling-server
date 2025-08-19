const {
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
} = require('./main.js');

async function sendMessage(content) {
  if (content && username) {
    if (grokBotActive && content.startsWith('/grok ')) {
      const query = content.slice(6).trim();
      if (query) {
        await sendToGrok(query);
      }
      const messageInput = document.getElementById('messageInput');
      messageInput.value = '';
      messageInput.style.height = '2.5rem';
      messageInput?.focus();
      return;
    }
    if (content === '/ratchet' && isInitiator) {
      triggerRatchet();
      showStatusMessage('Key ratchet triggered manually.');
      const messageInput = document.getElementById('messageInput');
      messageInput.value = '';
      messageInput.style.height = '2.5rem';
      messageInput?.focus();
      return;
    }
    const messageId = generateMessageId();
    const sanitizedContent = sanitizeMessage(content);
    const timestamp = Date.now();
    let payload = { messageId, username, timestamp };
    let contentToSend = sanitizedContent;
    if (!useRelay) {
      const messageKey = await deriveMessageKey(roomMaster);
      const { encrypted, iv } = await encryptRaw(messageKey, contentToSend);
      const toSign = contentToSend + timestamp;
      payload.signature = await signMessage(signingKey, toSign);
      payload.encryptedContent = encrypted;
      payload.iv = iv;
    } else {
      payload.content = sanitizedContent;
    }
    const jsonString = JSON.stringify(payload);
    if (useRelay) {
      sendRelayMessage('relay-message', { content: sanitizedContent, messageId, username, timestamp });
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
    messageDiv.appendChild(document.createTextNode(`${username}: ${sanitizedContent}`));
    messages.prepend(messageDiv);
    messages.scrollTop = 0;
    processedMessageIds.add(messageId);
    const messageInput = document.getElementById('messageInput');
    messageInput.value = '';
    messageInput.style.height = '2.5rem';
    messageInput?.focus();
    messageCount++;
    if (isInitiator && messageCount % 100 === 0) {
      triggerRatchet();
    }
  } else {
    showStatusMessage('Error: No connections or username not set.');
    document.getElementById('messageInput')?.focus();
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
        return renegotiate(targetId); // Recurse to queue again
      }
      renegotiating.set(targetId, true);
      try {
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        sendSignalingMessage('offer', { offer: peerConnection.localDescription, targetId });
      } catch (error) {
        console.error(`Error renegotiating with ${targetId}:`, error);
        showStatusMessage('Failed to renegotiate peer connection.');
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
          console.log('WebSocket opened, sending check-totp');
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
        updateFeaturesUI();
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
    showStatusMessage('Error: xAI API key not set. Enter it in the Grok bot settings. For details, visit https://x.ai/api.');
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

function toggleAudioOutput() {
  audioOutputMode = audioOutputMode === 'earpiece' ? 'speaker' : 'earpiece';
  console.log(`Toggling audio output to ${audioOutputMode}`);
  remoteAudios.forEach((audio, targetId) => {
    setAudioOutput(audio, targetId);
  });
  const audioOutputButton = document.getElementById('audioOutputButton');
  audioOutputButton.title = audioOutputMode === 'earpiece' ? 'Switch to Speaker' : 'Switch to Earpiece';
  audioOutputButton.textContent = audioOutputMode === 'earpiece' ? '🔊' : '📞';
  audioOutputButton.classList.toggle('speaker', audioOutputMode === 'speaker');
  showStatusMessage(`Audio output set to ${audioOutputMode}`);
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
  socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  document.getElementById('totpOptionsModal').classList.remove('active');
  codeDisplayElement.textContent = `Your code: ${code}`;
  codeDisplayElement.classList.remove('hidden');
  copyCodeButton.classList.remove('hidden');
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

async function joinWithTotp(code, totpCode) {
  socket.send(JSON.stringify({ type: 'join', code, clientId, username, totpCode, token }));
}

function startVoiceRecording() {
  if (!features.enableVoice) {
    showStatusMessage('Voice messages are disabled by admin.');
    return;
  }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    showStatusMessage('Microphone not supported.');
    return;
  }
  navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
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
    mediaRecorder.start(1000);
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
  }).catch(error => {
    console.error('Error starting voice recording:', error);
    showStatusMessage('Failed to access microphone for voice message.');
  });
}

function stopVoiceRecording() {
  if (mediaRecorder && mediaRecorder.state === 'recording') {
    mediaRecorder.stop();
  }
}

async function isWebPSupported() {
  const elem = document.createElement('canvas');
  if (!!(elem.getContext && elem.getContext('2d'))) {
    return elem.toDataURL('image/webp').indexOf('data:image/webp') === 0;
  }
  return false;
}