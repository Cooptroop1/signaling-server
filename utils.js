// utils.js
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
  isConnected = dataChannels.size > 0;
  updateMaxClientsUI();
  if (!isConnected) {
    if (inputContainer) inputContainer.classList.add('hidden');
    if (messages) messages.classList.add('waiting');
  }
}

function initializeMaxClientsUI() {
  log('info', `initializeMaxClientsUI called, isInitiator: ${typeof isInitiator !== 'undefined' ? isInitiator : 'undefined (defaulting to false)'}`);
  const effectiveInitiator = typeof isInitiator !== 'undefined' ? isInitiator : false;
  const addUserText = document.getElementById('addUserText');
  const addUserModal = document.getElementById('addUserModal');
  const addUserRadios = document.getElementById('addUserRadios');
  if (addUserText && addUserModal && addUserRadios) {
    addUserText.classList.toggle('hidden', !effectiveInitiator);
    if (effectiveInitiator) {
      log('info', `Creating buttons for maxClients in modal, current maxClients: ${maxClients}`);
      addUserRadios.innerHTML = '';
      for (let n = 2; n <= 10; n++) {
        const button = document.createElement('button');
        button.textContent = n;
        button.setAttribute('aria-label', `Set maximum users to ${n}`);
        button.className = n === maxClients ? 'active' : '';
        button.disabled = !effectiveInitiator;
        button.addEventListener('click', () => {
          if (effectiveInitiator) {
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

function generateTotpSecret() {
  return otplib.authenticator.generateSecret(32);
}

function generateTotpUri(roomCode, secret) {
  return otplib.authenticator.keyuri(roomCode, 'Anonomoose Chat', secret);
}
