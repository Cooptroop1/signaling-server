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
  // Switch to DOMPurify for better sanitization
  return DOMPurify.sanitize(content, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }); // Plain text only, no HTML
}

function generateMessageId() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  const bytes = window.crypto.getRandomValues(new Uint8Array(16));
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
}

function newClientId() {
  return generateMessageId();
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
    if (typeof socket !== 'undefined' && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'ping', clientId, token }));
      log('info', 'Sent keepalive ping');
    }
  }, 50000); // Adjusted to 50 seconds
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

function createMediaModal(type, base64, focusId) {
  const modalId = `${type}Modal`;
  const ariaLabel = type === 'image' ? 'Image viewer' : 'Audio player';
  let modal = document.getElementById(modalId);
  if (!modal) {
    modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-label', ariaLabel);
    modal.setAttribute('tabindex', '-1');
    document.body.appendChild(modal);
  }
  modal.innerHTML = '';
  let mediaElement;
  if (type === 'image') {
    mediaElement = document.createElement('img');
    mediaElement.src = base64;
    mediaElement.setAttribute('alt', 'Enlarged image');
  } else if (type === 'audio') {
    mediaElement = document.createElement('audio');
    mediaElement.src = base64;
    mediaElement.controls = true;
    mediaElement.setAttribute('alt', 'Voice message');
  }
  modal.appendChild(mediaElement);
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

function createImageModal(base64, focusId) {
  createMediaModal('image', base64, focusId);
}

function createAudioModal(base64, focusId) {
  createMediaModal('audio', base64, focusId);
}

function contentToPlayableUrl(content) {
  if (!content) return '';
  if (content.indexOf('blob:') === 0 || content.indexOf('http') === 0) return content;
  if (content.indexOf('data:') !== 0) return content;
  try {
    const comma = content.indexOf(',');
    const head = content.slice(0, comma);
    const b64 = content.slice(comma + 1);
    const mime = (head.match(/data:([^;]+)/) || [, 'audio/webm'])[1];
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return URL.createObjectURL(new Blob([arr], { type: mime }));
  } catch (e) {
    return content;
  }
}

function formatVoiceTime(secs) {
  if (!isFinite(secs) || secs < 0) return '0:00';
  const s = Math.floor(secs % 60);
  const m = Math.floor(secs / 60);
  return m + ':' + (s < 10 ? '0' : '') + s;
}

function pauseOtherVoiceNotes(exceptAudio) {
  document.querySelectorAll('.voice-note').forEach(note => {
    const a = note.querySelector('audio');
    const b = note.querySelector('.voice-note-play');
    if (a && a !== exceptAudio) {
      a.pause();
      if (b) b.textContent = '▶';
    }
  });
}

function makeVoiceNotePlayer(content) {
  const wrap = document.createElement('div');
  wrap.className = 'voice-note';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'voice-note-play';
  btn.setAttribute('aria-label', 'Play voice note');
  btn.textContent = '▶';
  const bar = document.createElement('div');
  bar.className = 'voice-note-bar';
  const fill = document.createElement('div');
  fill.className = 'voice-note-fill';
  bar.appendChild(fill);
  const time = document.createElement('span');
  time.className = 'voice-note-time';
  time.textContent = '0:00';
  const audio = document.createElement('audio');
  audio.preload = 'metadata';
  audio.playsInline = true;
  audio.src = contentToPlayableUrl(content);
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    pauseOtherVoiceNotes(audio);
    if (audio.paused) {
      audio.play().then(() => { btn.textContent = '❚❚'; }).catch(() => {
        showStatusMessage('Could not play voice note.');
      });
    } else {
      audio.pause();
      btn.textContent = '▶';
    }
  });
  audio.addEventListener('timeupdate', () => {
    const dur = audio.duration || 0;
    const pct = dur ? (audio.currentTime / dur) * 100 : 0;
    fill.style.width = pct + '%';
    time.textContent = formatVoiceTime(audio.currentTime) + (dur ? ' / ' + formatVoiceTime(dur) : '');
  });
  audio.addEventListener('loadedmetadata', () => {
    time.textContent = formatVoiceTime(audio.duration);
  });
  audio.addEventListener('ended', () => {
    btn.textContent = '▶';
    fill.style.width = '0%';
    time.textContent = formatVoiceTime(audio.duration);
  });
  audio.addEventListener('error', () => {
    time.textContent = 'error';
  });
  wrap.appendChild(btn);
  wrap.appendChild(bar);
  wrap.appendChild(time);
  wrap.appendChild(audio);
  return wrap;
}

function generateTotpSecret() {
  return otplib.authenticator.generateSecret(32);
}

function generateTotpUri(roomCode, secret) {
  return otplib.authenticator.keyuri(roomCode, 'Anonomoose Chat', secret);
}

function burnBlobUrls(root) {
  if (!root || !root.querySelectorAll) return;
  root.querySelectorAll('img, audio, video, a, source').forEach(el => {
    ['src', 'href'].forEach(attr => {
      const v = el.getAttribute && el.getAttribute(attr);
      if (v && v.indexOf('blob:') === 0) {
        try { URL.revokeObjectURL(v); } catch (e) {}
      }
    });
    if (el.dataset && el.dataset.src && String(el.dataset.src).indexOf('blob:') === 0) {
      try { URL.revokeObjectURL(el.dataset.src); } catch (e) {}
    }
    try {
      el.removeAttribute('src');
      if (el.tagName === 'A') el.removeAttribute('href');
      if (el.dataset) delete el.dataset.src;
    } catch (e) {}
  });
}

function burnTranscript() {
  const messagesEl = document.getElementById('messages');
  if (messagesEl) {
    burnBlobUrls(messagesEl);
    messagesEl.textContent = '';
    messagesEl.innerHTML = '';
  }
  ['imageModal', 'audioModal'].forEach(id => {
    const modal = document.getElementById(id);
    if (modal) {
      burnBlobUrls(modal);
      modal.innerHTML = '';
      modal.classList.remove('active');
    }
  });
  const input = document.getElementById('messageInput');
  if (input) {
    input.value = '';
    input.style.height = '2.5rem';
  }
  const fileInput = document.getElementById('imageInput');
  if (fileInput) fileInput.value = '';
  const totpDisplay = document.getElementById('totpSecretDisplay');
  if (totpDisplay) totpDisplay.textContent = '';
  if (typeof processedMessageIds !== 'undefined' && processedMessageIds && processedMessageIds.clear) processedMessageIds.clear();
  if (typeof processedNonces !== 'undefined' && processedNonces && processedNonces.clear) processedNonces.clear();
  if (typeof messageQueue !== 'undefined' && messageQueue && messageQueue.clear) messageQueue.clear();
  if (typeof chunkBuffers !== 'undefined' && chunkBuffers && chunkBuffers.clear) chunkBuffers.clear();
  if (typeof signalingQueue !== 'undefined' && signalingQueue && signalingQueue.clear) signalingQueue.clear();
  if (typeof voiceChunks !== 'undefined' && Array.isArray(voiceChunks)) voiceChunks.length = 0;
  if (typeof mediaRecorder !== 'undefined' && mediaRecorder && mediaRecorder.state === 'recording') {
    try { mediaRecorder.stop(); } catch (e) {}
  }
  try { sessionStorage.removeItem('anonomoose-draft'); } catch (e) {}
}

function burnChatSession() {
  burnTranscript();
  try { localStorage.removeItem('recentCodes'); } catch (e) {}
  const recent = document.getElementById('recentCodesList');
  if (recent) recent.innerHTML = '';
  const recentWrap = document.getElementById('recentChats');
  if (recentWrap) recentWrap.classList.add('hidden');
  if (typeof endChat === 'function') {
    try { endChat(); } catch (e) {}
  }
}

let remoteWipeInFlight = false;

function applyRemoteRoomWipe() {
  if (remoteWipeInFlight) return;
  remoteWipeInFlight = true;
  showStatusMessage('The other person burned the chat on every device in this room.');
  burnChatSession();
  setTimeout(() => { remoteWipeInFlight = false; }, 2000);
}

function requestRoomWipe() {
  const payload = JSON.stringify({ type: 'room-wipe' });
  if (typeof dataChannels !== 'undefined' && dataChannels) {
    dataChannels.forEach((dc) => {
      if (dc && dc.readyState === 'open') {
        try { dc.send(payload); } catch (e) {}
      }
    });
  }
  try {
    if (typeof socket !== 'undefined' && socket && socket.readyState === WebSocket.OPEN && code && token) {
      socket.send(JSON.stringify({ type: 'room-wipe', code, clientId, token }));
    }
  } catch (e) {}
}
