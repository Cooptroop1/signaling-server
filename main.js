let turnUsername = '';
let turnCredential = '';
let localStream = null;
let voiceCallActive = false;
let grokBotActive = false;
let renegotiating = new Map();
let audioOutputMode = 'earpiece';
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

// Define features with non-text off by default
let features = {
  enableImages: false,
  enableVoice: false,
  enableVoiceCalls: false,
  enableGrokBot: false,
  enableAudioToggle: false,
  enableP2P: true,
  enableRelay: true,
  enableService: true
};

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
  if (type !== 'message') {
    if (!features[`enable${type.charAt(0).toUpperCase() + type.slice(1)}`]) {
      showStatusMessage(`Error: ${type.charAt(0).toUpperCase() + type.slice(1)} is disabled.`);
      return;
    }
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
  if (type === 'message') {
    messageDiv.appendChild(document.createTextNode(sanitizedContent));
  } // Removed media elements since features start off
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
  if (content === '/ratchet' && isInitiator) {
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
  // Stub for media, but checks feature
  await prepareAndSendMessage({ type, file });
}

// ... (keep startPeerConnection, setupDataChannel, etc., as is, but remove voice call, track, and media logic)

// In setupDataChannel, remove voice call event handling in onmessage
async function processReceivedMessage(data, targetId) {
  // ... (keep core, remove type checks for 'voice-call-start', 'voice-call-end', 'kick', 'ban')
  // Add feature update handling
  if (data.type === 'feature-update') {
    features[data.feature] = data.value;
    updateFeaturesUI();
    return;
  }
  // ... (keep decryption, but remove media rendering for images/voice/file)
  if (contentType === 'message') {
    messageDiv.appendChild(document.createTextNode(sanitizeMessage(contentOrData)));
  }
  // ... (keep append and scroll)
}

// Remove toggleVoiceCall, startVoiceCall, stopVoiceCall, renegotiate (if not needed), setAudioOutput, toggleAudioOutput
// Remove sendToGrok, toggleGrokBot, saveGrokKey
// Remove startTotpRoom, showTotpSecretModal, joinWithTotp
// Remove startVoiceRecording, stopVoiceRecording, isWebPSupported, generateThumbnail

// Add admin panel logic after chatContainer.classList.remove('hidden') in relevant functions (e.g., autoConnect or connection success)
if (isInitiator) {
  const adminButton = document.createElement('button');
  adminButton.id = 'adminButton';
  adminButton.textContent = 'Admin Panel';
  adminButton.onclick = showAdminPanel;
  document.getElementById('inputContainer').appendChild(adminButton);
}

function showAdminPanel() {
  const modal = document.getElementById('adminModal');
  if (!modal) return; // Assume HTML has <div id="adminModal" class="modal hidden"></div>
  modal.innerHTML = '';
  modal.classList.add('active');
  for (const key in features) {
    if (['enableImages', 'enableVoice', 'enableVoiceCalls', 'enableGrokBot', 'enableAudioToggle'].includes(key)) {
      const label = document.createElement('label');
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.checked = features[key];
      input.onchange = () => {
        features[key] = input.checked;
        updateFeaturesUI();
        // Broadcast update
        if (useRelay) {
          sendRelayMessage('feature-update', { feature: key, value: input.checked });
        } else {
          dataChannels.forEach(dc => {
            if (dc.readyState === 'open') {
              dc.send(JSON.stringify({ type: 'feature-update', feature: key, value: input.checked }));
            }
          });
        }
      };
      label.appendChild(input);
      label.appendChild(document.createTextNode(key.replace('enable', 'Enable ')));
      modal.appendChild(label);
    }
  }
  const closeButton = document.createElement('button');
  closeButton.textContent = 'Close';
  closeButton.onclick = () => modal.classList.remove('active');
  modal.appendChild(closeButton);
}

// Update updateFeaturesUI to hide/show based on features, remove grok/voice/image buttons if off
function updateFeaturesUI() {
  // ... (adapt to hide buttons for disabled features)
  document.getElementById('imageButton')?.classList.toggle('hidden', !features.enableImages);
  document.getElementById('voiceButton')?.classList.toggle('hidden', !features.enableVoice);
  document.getElementById('voiceCallButton')?.classList.toggle('hidden', !features.enableVoiceCalls);
  document.getElementById('grokButton')?.classList.toggle('hidden', !features.enableGrokBot);
  document.getElementById('audioOutputButton')?.classList.toggle('hidden', !features.enableAudioToggle || !voiceCallActive);
  // ... (keep other logic)
}

// Remove claimSubmitButton and searchSubmitButton onclick handlers at the end

// Keep interval for nonce cleanup
setInterval(() => {
  const now = Date.now();
  for (const [nonce, ts] of processedNonces) {
    if (now - ts > 3600000) {
      processedNonces.delete(nonce);
    }
  }
}, 300000);

// Rest of the code (handleOffer, handleAnswer, etc.) remains similar, with removals for disabled features
