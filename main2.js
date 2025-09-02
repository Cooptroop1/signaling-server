function toggleGrokBot() {
  window.grokBotActive = !window.grokBotActive;
  const grokButton = document.getElementById('grokButton');
  const grokKeyContainer = document.getElementById('grokKeyContainer');
  grokButton.classList.toggle('active', window.grokBotActive);
  grokKeyContainer.classList.toggle('active', window.grokBotActive && !window.grokApiKey);
  if (window.grokBotActive) {
    if (!window.grokApiKey) {
      window.showStatusMessage('Grok bot enabled. Enter your xAI API key below. For details, visit https://x.ai/api.');
    } else {
      window.showStatusMessage('Grok bot enabled. Use /grok <query> to ask questions.');
    }
  } else {
    window.showStatusMessage('Grok bot disabled.');
  }
}

function saveGrokKey() {
  const keyInput = document.getElementById('grokApiKey');
  window.grokApiKey = keyInput.value.trim();
  if (window.grokApiKey) {
    localStorage.setItem('grokApiKey', window.grokApiKey);
    document.getElementById('grokKeyContainer').classList.remove('active');
    window.showStatusMessage('API key saved. Use /grok <query> to ask Grok.');
    keyInput.value = '';
  } else {
    window.showStatusMessage('Error: Enter a valid API key.');
  }
}

function toggleAudioOutput() {
  window.audioOutputMode = window.audioOutputMode === 'earpiece' ? 'speaker' : 'earpiece';
  console.log(`Toggling audio output to ${window.audioOutputMode}`);
  window.remoteAudios.forEach((audio, targetId) => {
    window.setAudioOutput(audio, targetId);
  });
  const audioOutputButton = document.getElementById('audioOutputButton');
  audioOutputButton.title = window.audioOutputMode === 'earpiece' ? 'Switch to Speaker' : 'Switch to Earpiece';
  audioOutputButton.textContent = window.audioOutputMode === 'earpiece' ? '🔊' : '📞';
  audioOutputButton.classList.toggle('speaker', window.audioOutputMode === 'speaker');
  window.showStatusMessage(`Audio output set to ${window.audioOutputMode}`);
}

async function startTotpRoom(serverGenerated) {
  const usernameInput = document.getElementById('totpUsernameInput').value.trim();
  if (!window.validateUsername(usernameInput)) {
    window.showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
    return;
  }
  window.username = usernameInput;
  localStorage.setItem('username', window.username);
  let totpSecret;
  if (serverGenerated) {
    totpSecret = window.generateTotpSecret();
  } else {
    totpSecret = document.getElementById('customTotpSecret').value.trim();
    const base32Regex = /^[A-Z2-7]+=*$/i;
    if (!base32Regex.test(totpSecret) || totpSecret.length < 16) {
      window.showStatusMessage('Invalid custom TOTP secret format (base32, min 16 chars).');
      return;
    }
  }
  let secretToSend = totpSecret.toUpperCase().replace(/=+$/, '');
  const len = secretToSend.length;
  const paddingLen = (8 - len % 8) % 8;
  secretToSend += '='.repeat(paddingLen);
  window.totpEnabled = true;
  window.code = window.generateCode();
  window.pendingTotpSecret = { display: totpSecret, send: secretToSend };
  window.socket.send(JSON.stringify({ type: 'join', code: window.code, clientId: window.clientId, username: window.username, token: window.token }));
  document.getElementById('totpOptionsModal').classList.remove('active');
  window.codeDisplayElement.textContent = `Your code: ${window.code}`;
  window.codeDisplayElement.classList.remove('hidden');
  window.copyCodeButton.classList.remove('hidden');
  window.usernameContainer.classList.add('hidden');
  window.connectContainer.classList.add('hidden');
  window.initialContainer.classList.add('hidden');
  window.chatContainer.classList.remove('hidden');
  window.messages.classList.add('waiting');
  window.statusElement.textContent = 'Waiting for connection...';
  document.getElementById('messageInput')?.focus();
}

function showTotpSecretModal(secret) {
  console.log('Showing TOTP modal with secret:', secret);
  document.getElementById('totpSecretDisplay').textContent = secret;
  const qrCanvas = document.getElementById('qrCodeCanvas');
  qrCanvas.innerHTML = '';
  new QRCode(qrCanvas, window.generateTotpUri(window.code, secret));
  document.getElementById('totpSecretModal').classList.add('active');
}

async function joinWithTotp(code, totpCode) {
  window.socket.send(JSON.stringify({ type: 'join', code, clientId: window.clientId, username: window.username, totpCode, token: window.token }));
}

function startVoiceRecording() {
  if (!window.features.enableVoice) {
    window.showStatusMessage('Voice messages are disabled by admin.');
    return;
  }
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    window.showStatusMessage('Microphone not supported.');
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
      window.showStatusMessage('Voice recording not supported in this browser.');
      return;
    }
    console.log('Using mimeType for recording:', mimeType);
    window.mediaRecorder = new MediaRecorder(stream, { mimeType });
    window.voiceChunks = [];
    window.mediaRecorder.addEventListener('dataavailable', (event) => {
      if (event.data.size > 0) {
        window.voiceChunks.push(event.data);
        console.log('Data available, chunk size:', event.data.size);
      } else {
        console.warn('Empty data chunk received');
      }
    });
    window.mediaRecorder.addEventListener('stop', async () => {
      console.log('Recorder stopped, chunks length:', window.voiceChunks.length);
      const audioBlob = new Blob(window.voiceChunks, { type: mimeType });
      console.log('Audio blob created, size:', audioBlob.size, 'type:', mimeType);
      if (audioBlob.size === 0) {
        window.showStatusMessage('No audio recorded. Speak louder or check microphone.');
        return;
      }
      await window.prepareAndSendMessage({ type: 'voice', file: audioBlob });
      stream.getTracks().forEach(track => track.stop());
      window.mediaRecorder = null;
      window.voiceChunks = [];
      document.getElementById('voiceButton').classList.remove('recording');
      document.getElementById('voiceTimer').style.display = 'none';
      document.getElementById('voiceTimer').textContent = '';
      clearInterval(window.voiceTimerInterval);
    });
    window.mediaRecorder.start(1000);
    document.getElementById('voiceButton').classList.add('recording');
    document.getElementById('voiceTimer').style.display = 'flex';
    let time = 0;
    window.voiceTimerInterval = setInterval(() => {
      time++;
      document.getElementById('voiceTimer').textContent = `00:${time < 10 ? '0' + time : time}`;
      if (time >= 30) {
        window.stopVoiceRecording();
      }
    }, 1000);
  }).catch(error => {
    console.error('Error starting voice recording:', error);
    window.showStatusMessage('Failed to access microphone for voice message.');
  });
}

function stopVoiceRecording() {
  if (window.mediaRecorder && window.mediaRecorder.state === 'recording') {
    window.mediaRecorder.stop();
  }
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
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();
    img.src = dataURL;
    img.onload = () => {
      canvas.width = width;
      canvas.height = height;
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL('image/jpeg', 0.5));
    };
    img.onerror = () => resolve(dataURL);
  });
}

setInterval(() => {
  const now = Date.now();
  for (const [nonce, ts] of window.processedNonces) {
    if (now - ts > 3600000) {
      window.processedNonces.delete(nonce);
    }
  }
  console.log(`Cleaned processedNonces, remaining: ${window.processedNonces.size}`);
}, 300000);

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

function setCookie(name, value, days) {
  let expires = '';
  if (days) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    expires = '; expires=' + date.toUTCString();
  }
  document.cookie = name + '=' + (value || '') + expires + '; path=/; Secure; HttpOnly; SameSite=Strict';
}

function updateLogoutButtonVisibility() {
  const logoutButton = document.getElementById('logoutButton');
  if (logoutButton) {
    logoutButton.classList.toggle('hidden', !window.isLoggedIn);
  }
}

function logout() {
  if (window.socket.readyState === WebSocket.OPEN && window.token) {
    window.socket.send(JSON.stringify({ type: 'logout', clientId: window.clientId, token: window.token }));
  }
  window.username = '';
  window.token = '';
  window.refreshToken = '';
  window.isLoggedIn = false;
  window.clientId = Math.random().toString(36).substr(2, 9);
  setCookie('clientId', window.clientId, 365);
  localStorage.removeItem('username');
  localStorage.removeItem('userPrivateKey');
  window.userPrivateKey = null;
  window.userPublicKey = null;
  window.processedMessageIds.clear();
  window.connectedClients.clear();
  window.peerConnections.forEach((pc) => pc.close());
  window.peerConnections.clear();
  window.dataChannels.forEach((dc) => dc.close());
  window.dataChannels.clear();
  window.socket.close();
  window.initialContainer.classList.remove('hidden');
  window.usernameContainer.classList.add('hidden');
  window.connectContainer.classList.add('hidden');
  window.chatContainer.classList.add('hidden');
  window.codeDisplayElement.classList.add('hidden');
  window.copyCodeButton.classList.add('hidden');
  updateLogoutButtonVisibility();
  window.showStatusMessage('Logged out successfully.');
  document.getElementById('startChatToggleButton')?.focus();
}

function refreshAccessToken() {
  if (window.socket.readyState === WebSocket.OPEN && window.refreshToken && !window.refreshingToken) {
    window.refreshingToken = true;
    console.log('Proactively refreshing access token');
    window.socket.send(JSON.stringify({ type: 'refresh-token', clientId: window.clientId, refreshToken: window.refreshToken }));
  } else {
    console.log('Cannot refresh token: WebSocket not open, no refresh token, or refresh in progress');
  }
}

async function triggerRatchet() {
  if (!window.isInitiator || window.connectedClients.size <= 1) return;
  window.keyVersion++;
  const newRoomMaster = window.crypto.getRandomValues(new Uint8Array(32));
  const newSigningSalt = window.crypto.getRandomValues(new Uint8Array(16));
  const newMessageSalt = window.crypto.getRandomValues(new Uint8Array(16));
  let success = 0;
  let failures = [];
  for (const cId of window.connectedClients) {
    if (cId === window.clientId) continue;
    const publicKey = window.clientPublicKeys.get(cId);
    if (!publicKey) {
      console.warn(`No public key for client ${cId}, skipping ratchet send`);
      failures.push(cId);
      continue;
    }
    try {
      const importedPublic = await window.importPublicKey(publicKey);
      const shared = await window.deriveSharedKey(window.keyPair.privateKey, importedPublic);
      const payload = {
        roomMaster: window.arrayBufferToBase64(newRoomMaster),
        signingSalt: window.arrayBufferToBase64(newSigningSalt),
        messageSalt: window.arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await window.encryptRaw(shared, payloadStr);
      window.socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code: window.code, clientId: window.clientId, token: window.token, version: window.keyVersion }));
      success++;
    } catch (error) {
      console.error(`Error sending new room key to ${cId}:`, error);
      failures.push(cId);
    }
  }
  if (success > 0) {
    window.roomMaster = newRoomMaster;
    window.signingSalt = newSigningSalt;
    window.messageSalt = newMessageSalt;
    window.signingKey = await window.deriveSigningKey();
    console.log(`PFS ratchet complete (version ${window.keyVersion}), new roomMaster and salts set.`);
    if (failures.length > 0) {
      console.warn(`Partial ratchet failure for clients: ${failures.join(', ')}. Retrying...`);
      triggerRatchetPartial(failures, newRoomMaster, newSigningSalt, newMessageSalt, window.keyVersion, 1);
    }
  } else {
    console.warn(`PFS ratchet failed (version ${window.keyVersion}): No keys available to send to any clients.`);
    window.keyVersion--;
  }
}

async function triggerRatchetPartial(failures, newRoomMaster, newSigningSalt, newMessageSalt, version, retryCount) {
  if (retryCount > 3) {
    console.warn(`Max retries (3) reached for partial ratchet (version ${version}). Giving up.`);
    return;
  }
  const backoffTimes = [10000, 30000, 60000];
  const delay = backoffTimes[retryCount - 1];
  console.log(`Scheduling retry ${retryCount} in ${delay / 1000}s for version ${version}`);
  await new Promise(resolve => setTimeout(resolve, delay));
  let retrySuccess = 0;
  let newFailures = [];
  for (const cId of failures) {
    const publicKey = window.clientPublicKeys.get(cId);
    if (!publicKey) {
      newFailures.push(cId);
      continue;
    }
    try {
      const importedPublic = await window.importPublicKey(publicKey);
      const shared = await window.deriveSharedKey(window.keyPair.privateKey, importedPublic);
      const payload = {
        roomMaster: window.arrayBufferToBase64(newRoomMaster),
        signingSalt: window.arrayBufferToBase64(newSigningSalt),
        messageSalt: window.arrayBufferToBase64(newMessageSalt)
      };
      const payloadStr = JSON.stringify(payload);
      const { encrypted, iv } = await window.encryptRaw(shared, payloadStr);
      window.socket.send(JSON.stringify({ type: 'new-room-key', encrypted, iv, targetId: cId, code: window.code, clientId: window.clientId, token: window.token, version }));
      retrySuccess++;
    } catch (error) {
      console.error(`Retry ${retryCount} failed for ${cId}:`, error);
      newFailures.push(cId);
    }
  }
  if (retrySuccess > 0) {
    console.log(`Partial ratchet retry ${retryCount} successful for ${retrySuccess} clients (version ${version}).`);
  }
  if (newFailures.length > 0) {
    console.warn(`Still failures after retry ${retryCount}: ${newFailures.join(', ')}. Trying again...`);
    triggerRatchetPartial(newFailures, newRoomMaster, newSigningSalt, newMessageSalt, version, retryCount + 1);
  } else {
    console.log(`All partial ratchet retries complete for version ${version}.`);
  }
}

function updateDots() {
  const userDots = document.getElementById('userDots');
  if (!userDots) return;
  userDots.innerHTML = '';
  const greenCount = window.totalClients;
  const redCount = window.maxClients - greenCount;
  const otherClientIds = Array.from(window.connectedClients).filter(id => id !== window.clientId);
  const selfDot = document.createElement('div');
  selfDot.className = 'user-dot online';
  userDots.appendChild(selfDot);
  otherClientIds.forEach((targetId, index) => {
    const dot = document.createElement('div');
    dot.className = 'user-dot online';
    dot.dataset.targetId = targetId;
    if (window.isInitiator) {
      const menu = document.createElement('div');
      menu.className = 'user-menu';
      const kickButton = document.createElement('button');
      kickButton.textContent = 'Kick';
      kickButton.onclick = () => kickUser(targetId);
      const banButton = document.createElement('button');
      banButton.textContent = 'Ban';
      banButton.onclick = () => banUser(targetId);
      menu.appendChild(kickButton);
      menu.appendChild(banButton);
      dot.appendChild(menu);
    }
    userDots.appendChild(dot);
  });
  for (let i = 0; i < redCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'user-dot offline';
    userDots.appendChild(dot);
  }
}

async function kickUser(targetId) {
  if (!window.isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for kick:', targetId);
    window.showStatusMessage('Invalid target user for kick.');
    return;
  }
  console.log('Kicking user', targetId);
  const toSign = targetId + 'kick' + window.code;
  const signature = await window.signMessage(window.signingKey, toSign);
  const message = { type: 'kick', targetId, code: window.code, clientId: window.clientId, token: window.token, signature };
  console.log('Sending kick message:', message);
  window.socket.send(JSON.stringify(message));
  window.showStatusMessage(`Kicked user ${window.usernames.get(targetId) || targetId}`);
}

async function banUser(targetId) {
  if (!window.isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for ban:', targetId);
    window.showStatusMessage('Invalid target user for ban.');
    return;
  }
  console.log('Banning user', targetId);
  const toSign = targetId + 'ban' + window.code;
  const signature = await window.signMessage(window.signingKey, toSign);
  const message = { type: 'ban', targetId, code: window.code, clientId: window.clientId, token: window.token, signature };
  console.log('Sending ban message:', message);
  window.socket.send(JSON.stringify(message));
  window.showStatusMessage(`Banned user ${window.usernames.get(targetId) || targetId}`);
}

function setupLazyObserver() {
  window.lazyObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const elem = entry.target;
        if (elem.dataset.src) {
          elem.src = elem.dataset.src;
          delete elem.dataset.src;
          window.lazyObserver.unobserve(elem);
        }
        if (elem.dataset.fullSrc) {
          elem.src = elem.dataset.fullSrc;
          delete elem.dataset.fullSrc;
          window.lazyObserver.unobserve(elem);
        }
      }
    });
  }, { rootMargin: '100px' });
}

function loadRecentCodes() {
  const recentCodes = JSON.parse(localStorage.getItem('recentCodes')) || [];
  const recentCodesList = document.getElementById('recentCodesList');
  recentCodesList.innerHTML = '';
  if (recentCodes.length > 0) {
    document.getElementById('recentChats').classList.remove('hidden');
    recentCodes.forEach(recentCode => {
      const button = document.createElement('button');
      button.textContent = recentCode;
      button.onclick = () => window.autoConnect(recentCode);
      recentCodesList.appendChild(button);
    });
  } else {
    document.getElementById('recentChats').classList.add('hidden');
  }
}

function updateRecentCodes(code) {
  let recentCodes = JSON.parse(localStorage.getItem('recentCodes')) || [];
  if (recentCodes.includes(code)) {
    recentCodes = recentCodes.filter(c => c !== code);
  }
  recentCodes.unshift(code);
  if (recentCodes.length > 5) {
    recentCodes = recentCodes.slice(0, 5);
  }
  localStorage.setItem('recentCodes', JSON.stringify(recentCodes));
  loadRecentCodes();
}

function setupWaitingForJoin(codeParam) {
  window.code = codeParam;
  window.initialContainer.classList.add('hidden');
  window.connectContainer.classList.add('hidden');
  window.usernameContainer.classList.add('hidden');
  window.chatContainer.classList.remove('hidden');
  window.codeDisplayElement.classList.add('hidden');
  window.copyCodeButton.classList.add('hidden');
  if (window.validateCode(codeParam)) {
    if (window.validateUsername(window.username)) {
      console.log('Valid username and code, waiting for join approval');
      window.codeDisplayElement.textContent = `Waiting for approval: ${window.code}`;
      window.codeDisplayElement.classList.remove('hidden');
      window.copyCodeButton.classList.remove('hidden');
      window.messages.classList.add('waiting');
      window.statusElement.textContent = 'Waiting for connection approval...';
      window.socket.send(JSON.stringify({ type: 'request-join', code: window.code, clientId: window.clientId, username: window.username, token: window.token }));
      document.getElementById('messageInput')?.focus();
    } else {
      console.log('No valid username, prompting for username');
      window.usernameContainer.classList.remove('hidden');
      window.chatContainer.classList.add('hidden');
      window.statusElement.textContent = 'Please enter a username to request to join';
      document.getElementById('usernameInput').value = window.username || '';
      document.getElementById('usernameInput')?.focus();
      document.getElementById('joinWithUsernameButton').onclick = () => {
        const usernameInput = document.getElementById('usernameInput').value.trim();
        if (!window.validateUsername(usernameInput)) {
          window.showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
          document.getElementById('usernameInput')?.focus();
          return;
        }
        window.username = usernameInput;
        localStorage.setItem('username', window.username);
        window.usernameContainer.classList.add('hidden');
        window.chatContainer.classList.remove('hidden');
        window.codeDisplayElement.textContent = `Waiting for approval: ${window.code}`;
        window.codeDisplayElement.classList.remove('hidden');
        window.copyCodeButton.classList.remove('hidden');
        window.messages.classList.add('waiting');
        window.statusElement.textContent = 'Waiting for connection approval...';
        window.socket.send(JSON.stringify({ type: 'request-join', code: window.code, clientId: window.clientId, username: window.username, token: window.token }));
        document.getElementById('messageInput')?.focus();
      };
    }
  } else {
    console.log('Invalid code, showing initial container');
    window.initialContainer.classList.remove('hidden');
    window.usernameContainer.classList.add('hidden');
    window.chatContainer.classList.add('hidden');
    window.showStatusMessage('Invalid code format. Please enter a valid code.');
    document.getElementById('connectToggleButton')?.focus();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, initializing maxClients UI');
  window.initializeMaxClientsUI();
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && window.validateCode(codeParam)) {
    setupWaitingForJoin(codeParam);
  }
  const codeInput = document.getElementById('codeInput');
  if (codeInput) {
    codeInput.addEventListener('input', (e) => {
      let val = e.target.value.replace(/[^a-zA-Z0-9]/gi, '');
      val = val.substring(0, 16);
      let formatted = '';
      for (let i = 0; i < val.length; i++) {
        if (i > 0 && i % 4 === 0) formatted += '-';
        formatted += val[i];
      }
      e.target.value = formatted;
    });
  }
  setupLazyObserver();
  loadRecentCodes();
  document.getElementById('userDots').addEventListener('click', (e) => {
    if (e.target.classList.contains('user-dot')) {
      e.target.classList.toggle('active');
    }
  });
  const toggleRecent = document.getElementById('toggleRecent');
  const recentCodesList = document.getElementById('recentCodesList');
  toggleRecent.addEventListener('click', () => {
    const isHidden = recentCodesList.classList.toggle('hidden');
    toggleRecent.textContent = isHidden ? 'Show' : 'Hide';
  });
  document.getElementById('loginButton').addEventListener('click', () => {
    if (window.isLoggedIn) {
      window.showStatusMessage('You are already logged in. Log out first to switch accounts.');
      return;
    }
    document.getElementById('loginModal').classList.add('active');
    document.getElementById('loginUsernameInput').value = window.username || '';
    document.getElementById('loginUsernameInput')?.focus();
  });
  document.getElementById('loginSubmitButton').onclick = () => {
    if (window.isLoggedIn) {
      window.showStatusMessage('You are already logged in. Log out first to switch accounts.');
      return;
    }
    const name = document.getElementById('loginUsernameInput').value.trim();
    const pass = document.getElementById('loginPasswordInput').value;
    if (window.validateUsername(name) && pass.length >= 8) {
      if (!window.userPrivateKey) {
        window.generateUserKeypair().then(() => {
          window.showStatusMessage('New device detected. Generated new keys (old offline messages may be lost).');
          window.socket.send(JSON.stringify({ type: 'login-username', username: name, password: pass, clientId: window.clientId, token: window.token }));
          localStorage.setItem('password', pass);
        }).catch(error => {
          console.error('Key generation error:', error);
          window.showStatusMessage('Failed to generate keys for login.');
        });
      } else {
        window.socket.send(JSON.stringify({ type: 'login-username', username: name, password: pass, clientId: window.clientId, token: window.token }));
        localStorage.setItem('password', pass);
      }
    } else {
      window.showStatusMessage('Invalid username or password (min 8 chars).');
    }
  };
  document.getElementById('loginCancelButton').onclick = () => {
    document.getElementById('loginModal').classList.remove('active');
  };
  document.getElementById('searchUserButton').addEventListener('click', () => {
    if (!window.isLoggedIn) {
      window.showStatusMessage('Please log in to search for users.');
      document.getElementById('loginModal').classList.add('active');
      document.getElementById('loginUsernameInput')?.focus();
      return;
    }
    document.getElementById('searchUserModal').classList.add('active');
  });
  document.getElementById('searchSubmitButton').onclick = () => {
    if (!window.isLoggedIn) {
      window.showStatusMessage('Please log in to search for users.');
      document.getElementById('searchUserModal').classList.remove('active');
      document.getElementById('loginModal').classList.add('active');
      document.getElementById('loginUsernameInput')?.focus();
      return;
    }
    const name = document.getElementById('searchUsernameInput').value.trim();
    if (name) {
      window.socket.send(JSON.stringify({ type: 'find-user', username: name, from_username: window.username, clientId: window.clientId, token: window.token }));
    }
  };
  document.getElementById('searchCancelButton').onclick = () => {
    document.getElementById('searchUserModal').classList.remove('active');
  };
  window.helpText.addEventListener('click', () => {
    window.helpModal.classList.add('active');
    window.helpModal.focus();
  });
  window.helpModal.addEventListener('click', () => {
    window.helpModal.classList.remove('active');
    window.helpText.focus();
  });
  window.helpModal.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      window.helpModal.classList.remove('active');
      window.helpText.focus();
    }
  });
  const addUserText = document.getElementById('addUserText');
  const addUserModal = document.getElementById('addUserModal');
  addUserText.addEventListener('click', () => {
    if (window.isInitiator) {
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
});

window.socket.onopen = () => {
  console.log('WebSocket opened');
  window.socket.send(JSON.stringify({ type: 'connect', clientId: window.clientId }));
  window.reconnectAttempts = 0;
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && window.validateCode(codeParam)) {
    console.log('Detected code in URL, setting pendingCode for autoConnect after token');
    window.pendingCode = codeParam;
  } else {
    console.log('No valid code in URL, showing initial container');
    window.initialContainer.classList.remove('hidden');
    window.usernameContainer.classList.add('hidden');
    window.connectContainer.classList.add('hidden');
    window.chatContainer.classList.add('hidden');
    window.codeDisplayElement.classList.add('hidden');
    window.copyCodeButton.classList.add('hidden');
  }
  if (window.username && !window.isLoggedIn) {
    const password = localStorage.getItem('password');
    if (password) {
      console.log('Attempting auto-login with stored username:', window.username);
      window.socket.send(JSON.stringify({ type: 'login-username', username: window.username, password, clientId: window.clientId }));
    }
  }
  updateLogoutButtonVisibility();
};

window.socket.onerror = (error) => {
  console.error('WebSocket error:', error);
  window.showStatusMessage('Connection error, please try again later.');
  window.connectionTimeouts.forEach((timeout) => clearTimeout(timeout));
};

window.socket.onclose = () => {
  console.log('WebSocket closed');
  window.stopKeepAlive();
  if (window.reconnectAttempts >= window.maxReconnectAttempts) {
    window.showStatusMessage('Max reconnect attempts reached. Please refresh the page.', 10000);
    return;
  }
  const delay = Math.min(30000, 5000 * Math.pow(2, window.reconnectAttempts));
  window.reconnectAttempts++;
  setTimeout(() => {
    window.socket = new WebSocket('wss://signaling-server-zc6m.onrender.com');
    window.socket.onopen = window.socket.onopen;
    window.socket.onerror = window.socket.onerror;
    window.socket.onclose = window.socket.onclose;
    window.socket.onmessage = window.socket.onmessage;
  }, delay);
};

window.socket.onmessage = async (event) => {
  console.log('Received WebSocket message:', event.data);
  try {
    const message = JSON.parse(event.data);
    console.log('Parsed message:', message);
    if (!message.type) {
      console.error('Invalid message: missing type');
      window.showStatusMessage('Invalid server message received.');
      return;
    }
    if (message.type === 'ping') {
      window.socket.send(JSON.stringify({ type: 'pong' }));
      console.log('Received ping, sent pong');
      return;
    }
    if (message.type === 'connected') {
      window.token = message.accessToken;
      window.refreshToken = message.refreshToken;
      console.log('Received authentication tokens:', { accessToken: window.token, refreshToken: window.refreshToken });
      window.startKeepAlive();
      setTimeout(window.refreshAccessToken, 5 * 60 * 1000);
      if (window.pendingCode) {
        window.autoConnect(window.pendingCode);
        window.pendingCode = null;
      }
      window.processSignalingQueue();
      updateLogoutButtonVisibility();
      return;
    }
    if (message.type === 'token-refreshed') {
      window.token = message.accessToken;
      window.refreshToken = message.refreshToken;
      console.log('Received new tokens:', { accessToken: window.token, refreshToken: window.refreshToken });
      window.refreshFailures = 0;
      window.refreshBackoff = 1000;
      setTimeout(window.refreshAccessToken, 5 * 60 * 1000);
      if (window.pendingJoin) {
        window.socket.send(JSON.stringify({ type: 'join', ...window.pendingJoin, token: window.token }));
        window.pendingJoin = null;
      }
      window.processSignalingQueue();
      window.refreshingToken = false;
      updateLogoutButtonVisibility();
      return;
    }
    if (message.type === 'error') {
      console.log('Server response:', message.message, 'Code:', message.code || 'N/A');
      if (message.message.includes('Username taken')) {
        const claimError = document.getElementById('claimError');
        claimError.textContent = 'Username already taken. Please try another.';
        setTimeout(() => {
          claimError.textContent = '';
        }, 5000);
        document.getElementById('claimUsernameInput').value = '';
        document.getElementById('claimPasswordInput').value = '';
        document.getElementById('claimUsernameInput')?.focus();
        return;
      }
      if (message.message.includes('Invalid login credentials')) {
        const loginError = document.getElementById('loginError');
        loginError.textContent = 'Invalid username or password. Please try again.';
        setTimeout(() => {
          loginError.textContent = '';
        }, 5000);
        document.getElementById('loginUsernameInput').value = '';
        document.getElementById('loginPasswordInput').value = '';
        document.getElementById('loginUsernameInput')?.focus();
        window.isLoggedIn = false;
        updateLogoutButtonVisibility();
        return;
      }
      if (message.message.includes('Must be logged in to search users.')) {
        window.showStatusMessage('Please log in to search for users.');
        document.getElementById('searchUserModal').classList.remove('active');
        document.getElementById('loginModal').classList.add('active');
        document.getElementById('loginUsernameInput')?.focus();
        return;
      }
      if (message.message.includes('Invalid or expired token') || message.message.includes('Missing authentication token')) {
        if (window.refreshToken && !window.refreshingToken) {
          window.refreshingToken = true;
          console.log('Attempting to refresh token');
          window.socket.send(JSON.stringify({ type: 'refresh-token', clientId: window.clientId, refreshToken: window.refreshToken }));
        } else {
          console.error('No refresh token available or refresh in progress, forcing reconnect');
          window.socket.close();
        }
      } else if (message.message.includes('Token revoked') || message.message.includes('Invalid or expired refresh token')) {
        window.refreshFailures++;
        console.log(`Refresh failure count: ${window.refreshFailures}`);
        if (window.refreshFailures > 3) {
          console.log('Exceeded refresh failures, forcing full reconnect with new clientId');
          window.clientId = Math.random().toString(36).substr(2, 9);
          setCookie('clientId', window.clientId, 365);
          window.token = '';
          window.refreshToken = '';
          window.refreshFailures = 0;
          window.refreshBackoff = 1000;
          window.socket.close();
        } else {
          const jitter = Math.random() * 4000 + 1000;
          const delay = Math.min(window.refreshBackoff + jitter, 8000);
          setTimeout(() => {
            if (window.refreshToken && !window.refreshingToken) {
              window.refreshingToken = true;
              window.socket.send(JSON.stringify({ type: 'refresh-token', clientId: window.clientId, refreshToken: window.refreshToken }));
            }
          }, delay);
          window.refreshBackoff = Math.min(window.refreshBackoff * 2, 8000);
        }
      } else if (message.message.includes('Rate limit exceeded')) {
        window.showStatusMessage('Rate limit exceeded. Waiting before retrying...');
        setTimeout(() => {
          if (window.reconnectAttempts < window.maxReconnectAttempts) {
            window.socket.send(JSON.stringify({ type: 'connect', clientId: window.clientId }));
          }
        }, 60000);
      } else if (message.message.includes('Chat is full') ||
        message.message.includes('Username already taken') ||
        message.message.includes('Initiator offline') ||
        message.message.includes('Invalid code format')) {
        console.log(`Join failed: ${message.message}`);
        window.showStatusMessage(`Failed to join chat: ${message.message}`);
        window.socket.send(JSON.stringify({ type: 'leave', code: window.code, clientId: window.clientId, token: window.token }));
        window.initialContainer.classList.remove('hidden');
        window.usernameContainer.classList.add('hidden');
        window.connectContainer.classList.add('hidden');
        window.codeDisplayElement.classList.add('hidden');
        window.copyCodeButton.classList.add('hidden');
        window.chatContainer.classList.add('hidden');
        window.newSessionButton.classList.add('hidden');
        window.maxClientsContainer.classList.add('hidden');
        window.inputContainer.classList.add('hidden');
        window.messages.classList.remove('waiting');
        window.codeSentToRandom = false;
        window.button2.disabled = false;
        window.token = '';
        window.refreshToken = '';
        updateLogoutButtonVisibility();
        return;
      } else if (message.message.includes('Service has been disabled by admin.')) {
        window.showStatusMessage(message.message);
        window.initialContainer.classList.remove('hidden');
        window.usernameContainer.classList.add('hidden');
        window.connectContainer.classList.add('hidden');
        window.codeDisplayElement.classList.add('hidden');
        window.copyCodeButton.classList.add('hidden');
        window.chatContainer.classList.add('hidden');
        window.newSessionButton.classList.add('hidden');
        window.maxClientsContainer.classList.add('hidden');
        window.inputContainer.classList.add('hidden');
        window.messages.classList.remove('waiting');
        window.socket.close();
        updateLogoutButtonVisibility();
        return;
      } else {
        window.showStatusMessage(message.message);
      }
      return;
    }
    if (message.type === 'totp-required') {
      showTotpInputModal(message.code);
      return;
    }
    if (message.type === 'totp-not-required') {
      if (window.pendingTotpSecret) {
        window.showTotpSecretModal(window.pendingTotpSecret.display);
        window.pendingTotpSecret = null;
      }
      window.socket.send(JSON.stringify({ type: 'join', code: window.code, clientId: window.clientId, username: window.username, token: window.token }));
      return;
    }
    if (message.type === 'init') {
      window.clientId = message.clientId;
      window.maxClients = Math.min(message.maxClients, 10);
      window.isInitiator = message.isInitiator;
      window.features = message.features || window.features;
      if (!window.features.enableP2P) {
        window.useRelay = true;
      }
      window.totalClients = 1;
      console.log(`Initialized client ${window.clientId}, username: ${window.username}, maxClients: ${window.maxClients}, isInitiator: ${window.isInitiator}, features: ${JSON.stringify(window.features)}`);
      window.usernames.set(window.clientId, window.username);
      window.connectedClients.add(window.clientId);
      window.initializeMaxClientsUI();
      window.updateFeaturesUI();
      if (window.isInitiator) {
        window.roomMaster = window.crypto.getRandomValues(new Uint8Array(32));
        window.signingSalt = window.crypto.getRandomValues(new Uint8Array(16));
        window.messageSalt = window.crypto.getRandomValues(new Uint8Array(16));
        window.signingKey = await window.deriveSigningKey();
        console.log('Generated initial roomMaster, signingSalt, messageSalt, and signingKey for initiator.');
        window.isConnected = true;
        if (window.pendingTotpSecret) {
          window.socket.send(JSON.stringify({ type: 'set-totp', secret: window.pendingTotpSecret.send, code: window.code, clientId: window.clientId, token: window.token }));
          window.showTotpSecretModal(window.pendingTotpSecret.display);
          window.pendingTotpSecret = null;
        }
        setInterval(window.triggerRatchet, 5 * 60 * 1000);
        if (window.useRelay) {
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode (E2EE)';
            privacyStatus.classList.remove('hidden');
          }
          window.isConnected = true;
          window.inputContainer.classList.remove('hidden');
          window.messages.classList.remove('waiting');
          window.updateMaxClientsUI();
        }
      } else {
        const publicKey = await window.exportPublicKey(window.keyPair.publicKey);
        window.socket.send(JSON.stringify({ type: 'public-key', publicKey, clientId: window.clientId, code: window.code, token: window.token }));
      }
      window.updateMaxClientsUI();
      updateDots();
      window.turnUsername = message.turnUsername;
      window.turnCredential = message.turnCredential;
      updateRecentCodes(window.code);
      return;
    }
    if (message.type === 'initiator-changed') {
      console.log(`Initiator changed to ${message.newInitiator} for code: ${window.code}`);
      window.isInitiator = message.newInitiator === window.clientId;
      window.initializeMaxClientsUI();
      window.updateMaxClientsUI();
      return;
    }
    if (message.type === 'join-notify' && message.code === window.code) {
      window.totalClients = message.totalClients;
      console.log(`Join-notify received for code: ${window.code}, client: ${message.clientId}, total: ${window.totalClients}, username: ${message.username}`);
      if (message.username) {
        window.usernames.set(message.clientId, message.username);
      }
      window.connectedClients.add(message.clientId);
      window.updateMaxClientsUI();
      updateDots();
      if (window.isInitiator && message.clientId !== window.clientId && !window.peerConnections.has(message.clientId)) {
        console.log(`Initiating peer connection with client ${message.clientId}`);
        window.startPeerConnection(message.clientId, true);
      }
      if (window.voiceCallActive) {
        window.renegotiate(message.clientId);
      }
      if (window.useRelay) {
        window.isConnected = true;
        window.inputContainer.classList.remove('hidden');
        window.messages.classList.remove('waiting');
        window.updateMaxClientsUI();
      }
      updateRecentCodes(window.code);
      return;
    }
    if (message.type === 'client-disconnected') {
      window.totalClients = message.totalClients;
      console.log(`Client ${message.clientId} disconnected from code: ${window.code}, total: ${window.totalClients}`);
      window.usernames.delete(message.clientId);
      window.connectedClients.delete(message.clientId);
      window.clientPublicKeys.delete(message.clientId);
      window.cleanupPeerConnection(message.clientId);
      if (window.remoteAudios.has(message.clientId)) {
        const audio = window.remoteAudios.get(message.clientId);
        audio.remove();
        window.remoteAudios.delete(message.clientId);
        if (window.remoteAudios.size === 0) {
          document.getElementById('remoteAudioContainer').classList.add('hidden');
        }
      }
      window.updateMaxClientsUI();
      updateDots();
      if (window.totalClients <= 1) {
        window.inputContainer.classList.add('hidden');
        window.messages.classList.add('waiting');
      }
      return;
    }
    if (message.type === 'max-clients') {
      window.maxClients = Math.min(message.maxClients, 10);
      console.log(`Max clients updated to ${window.maxClients} for code: ${window.code}`);
      window.updateMaxClientsUI();
      updateDots();
      return;
    }
    if (message.type === 'offer' && message.clientId !== window.clientId) {
      console.log(`Received offer from ${message.clientId} for code: ${window.code}`);
      window.handleOffer(message.offer, message.clientId);
      return;
    }
    if (message.type === 'answer' && message.clientId !== window.clientId) {
      console.log(`Received answer from ${message.clientId} for code: ${window.code}`);
      window.handleAnswer(message.answer, message.clientId);
      return;
    }
    if (message.type === 'candidate' && message.clientId !== window.clientId) {
      console.log(`Received ICE candidate from ${message.clientId} for code: ${window.code}`);
      window.handleCandidate(message.candidate, message.clientId);
      return;
    }
    if (message.type === 'public-key' && window.isInitiator) {
      try {
        window.clientPublicKeys.set(message.clientId, message.publicKey);
        const joinerPublic = await window.importPublicKey(message.publicKey);
        const sharedKey = await window.deriveSharedKey(window.keyPair.privateKey, joinerPublic);
        const payload = {
          roomMaster: window.arrayBufferToBase64(window.roomMaster),
          signingSalt: window.arrayBufferToBase64(window.signingSalt),
          messageSalt: window.arrayBufferToBase64(window.messageSalt)
        };
        const payloadStr = JSON.stringify(payload);
        const { encrypted, iv } = await window.encryptRaw(sharedKey, payloadStr);
        const myPublic = await window.exportPublicKey(window.keyPair.publicKey);
        window.socket.send(JSON.stringify({
          type: 'encrypted-room-key',
          encryptedKey: encrypted,
          iv,
          publicKey: myPublic,
          targetId: message.clientId,
          code: window.code,
          clientId: window.clientId,
          token: window.token
        }));
        await window.triggerRatchet();
      } catch (error) {
        console.error('Error handling public-key:', error);
        window.showStatusMessage('Key exchange failed.');
      }
      return;
    }
    if (message.type === 'encrypted-room-key') {
      try {
        window.initiatorPublic = message.publicKey;
        const initiatorPublicImported = await window.importPublicKey(window.initiatorPublic);
        const sharedKey = await window.deriveSharedKey(window.keyPair.privateKey, initiatorPublicImported);
        const decryptedStr = await window.decryptRaw(sharedKey, message.encryptedKey, message.iv);
        const payload = JSON.parse(decryptedStr);
        window.roomMaster = window.base64ToArrayBuffer(payload.roomMaster);
        window.signingSalt = window.base64ToArrayBuffer(payload.signingSalt);
        window.messageSalt = window.base64ToArrayBuffer(payload.messageSalt);
        window.signingKey = await window.deriveSigningKey();
        console.log('Room master, salts successfully imported.');
        if (window.useRelay) {
          window.isConnected = true;
          const privacyStatus = document.getElementById('privacyStatus');
          if (privacyStatus) {
            privacyStatus.textContent = 'Relay Mode (E2EE)';
            privacyStatus.classList.remove('hidden');
          }
          window.inputContainer.classList.remove('hidden');
          window.messages.classList.remove('waiting');
          window.updateMaxClientsUI();
        }
      } catch (error) {
        console.error('Error handling encrypted-room-key:', error);
        window.showStatusMessage('Failed to receive encryption key.');
      }
      return;
    }
    if (message.type === 'new-room-key' && message.targetId === window.clientId) {
      if (message.version <= window.keyVersion) {
        console.log(`Ignoring outdated key version ${message.version} (current: ${window.keyVersion})`);
        return;
      }
      try {
        const importedInitiatorPublic = await window.importPublicKey(window.initiatorPublic);
        const shared = await window.deriveSharedKey(window.keyPair.privateKey, importedInitiatorPublic);
        const decryptedStr = await window.decryptRaw(shared, message.encrypted, message.iv);
        const payload = JSON.parse(decryptedStr);
        window.roomMaster = window.base64ToArrayBuffer(payload.roomMaster);
        window.signingSalt = window.base64ToArrayBuffer(payload.signingSalt);
        window.messageSalt = window.base64ToArrayBuffer(payload.messageSalt);
        window.signingKey = await window.deriveSigningKey();
        window.keyVersion = message.version;
        console.log(`New room master and salts received and set for PFS (version ${window.keyVersion}).`);
      } catch (error) {
        console.error('Error handling new-room-key:', error);
        window.showStatusMessage('Failed to update encryption key for PFS.');
      }
      return;
    }
    if (message.type === 'message' || message.type === 'image' || message.type === 'voice' || message.type === 'file') {
      if (window.processedMessageIds.has(message.messageId)) return;
      window.processedMessageIds.add(message.messageId);
      console.log('Received relay message:', message);
      const payload = {
        messageId: message.messageId,
        username: message.username,
        content: message.content,
        encryptedContent: message.encryptedContent,
        data: message.data,
        encryptedData: message.encryptedData,
        filename: message.filename,
        timestamp: Number(message.timestamp) || Date.now(),
        iv: message.iv,
        signature: message.signature
      };
      if (!payload.username || ((!payload.content && !payload.encryptedContent) && (!payload.data && !payload.encryptedData)) || isNaN(payload.timestamp)) {
        console.error('Invalid payload in relay message:', payload);
        window.showStatusMessage('Invalid message received.');
        return;
      }
      const senderUsername = payload.username;
      const messages = document.getElementById('messages');
      const isSelf = senderUsername === window.username;
      const messageDiv = document.createElement('div');
      messageDiv.className = `message-bubble ${isSelf ? 'self' : 'other'}`;
      const timeSpan = document.createElement('span');
      timeSpan.className = 'timestamp';
      timeSpan.textContent = new Date(payload.timestamp).toLocaleTimeString();
      messageDiv.appendChild(timeSpan);
      messageDiv.appendChild(document.createTextNode(`${senderUsername}: `));
      let contentOrData = payload.content || payload.data;
      if (payload.encryptedContent || payload.encryptedData) {
        try {
          const messageKey = await window.deriveMessageKey();
          const encrypted = payload.encryptedContent || payload.encryptedData;
          const iv = payload.iv;
          contentOrData = await window.decryptRaw(messageKey, encrypted, iv);
          const toVerify = contentOrData + payload.timestamp;
          const valid = await window.verifyMessage(window.signingKey, payload.signature, toVerify);
          if (!valid) {
            console.warn(`Invalid signature for relay message`);
            window.showStatusMessage('Invalid message signature detected.');
            return;
          }
        } catch (error) {
          console.error(`Decryption/verification failed for relay message:`, error);
          window.showStatusMessage('Failed to decrypt/verify message.');
          return;
        }
      }
      if (message.type === 'image') {
        const img = document.createElement('img');
        img.src = contentOrData;
        img.style.maxWidth = '100%';
        img.style.borderRadius = '0.5rem';
        img.style.cursor = 'pointer';
        img.setAttribute('alt', 'Received image');
        img.addEventListener('click', () => window.createImageModal(contentOrData, 'messageInput'));
        messageDiv.appendChild(img);
      } else if (message.type === 'voice') {
        const audio = document.createElement('audio');
        audio.src = contentOrData;
        audio.controls = true;
        audio.setAttribute('alt', 'Received voice message');
        audio.addEventListener('click', () => window.createAudioModal(contentOrData, 'messageInput'));
        messageDiv.appendChild(audio);
      } else if (message.type === 'file') {
        const link = document.createElement('a');
        link.href = contentOrData;
        link.download = payload.filename || 'file';
        link.textContent = `Download ${payload.filename || 'file'}`;
        link.setAttribute('alt', 'Received file');
        messageDiv.appendChild(link);
      } else {
        messageDiv.appendChild(document.createTextNode(window.sanitizeMessage(contentOrData)));
      }
      messages.prepend(messageDiv);
      messages.scrollTop = 0;
      return;
    }
    if (message.type === 'features-update') {
      window.features = message;
      console.log('Received features update:', window.features);
      setTimeout(window.updateFeaturesUI, 0);
      if (!window.features.enableService) {
        window.showStatusMessage(`Service disabled by admin. Disconnecting...`);
        window.socket.close();
      }
      return;
    }
    if (message.type === 'username-registered') {
      const claimSuccess = document.getElementById('claimSuccess');
      claimSuccess.textContent = `Username claimed successfully: ${message.username}`;
      window.isLoggedIn = true;
      localStorage.setItem('username', message.username);
      setTimeout(() => {
        claimSuccess.textContent = '';
        document.getElementById('claimUsernameModal').classList.remove('active');
        window.initialContainer.classList.remove('hidden');
        window.usernameContainer.classList.add('hidden');
        window.connectContainer.classList.add('hidden');
        window.chatContainer.classList.add('hidden');
        window.codeDisplayElement.classList.add('hidden');
        window.copyCodeButton.classList.add('hidden');
        window.statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'login-success') {
      window.username = message.username;
      localStorage.setItem('username', window.username);
      window.isLoggedIn = true;
      const loginSuccess = document.getElementById('loginSuccess');
      loginSuccess.textContent = `Logged in as ${window.username}`;
      if (message.offlineMessages && message.offlineMessages.length > 0) {
        for (const msg of message.offlineMessages) {
          console.log('Processing offline msg:', msg);
          if (msg.type === 'message' && msg.encrypted && msg.iv && msg.ephemeral_public) {
            (async () => {
              try {
                const privateKey = await window.crypto.subtle.importKey('jwk', JSON.parse(window.userPrivateKey), { name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveKey', 'deriveBits']);
                const ephemeralPublicImported = await window.importPublicKey(msg.ephemeral_public);
                const shared = await window.deriveSharedKey(privateKey, ephemeralPublicImported);
                const decrypted = await window.decryptRaw(shared, msg.encrypted, msg.iv);
                const messageDiv = document.createElement('div');
                messageDiv.className = 'message-bubble other';
                messageDiv.textContent = `Offline message from ${msg.from}: ${decrypted}`;
                window.messages.prepend(messageDiv);
              } catch (error) {
                console.error('Failed to decrypt offline message:', error);
                window.showStatusMessage('Failed to decrypt an offline message.');
              }
            })();
          } else if (msg.type === 'connection-request') {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message-bubble other';
            messageDiv.textContent = `Offline request from ${msg.from}: code ${msg.code}`;
            window.messages.prepend(messageDiv);
          }
        }
        window.showStatusMessage('Pending offline messages loaded.');
      }
      setTimeout(() => {
        loginSuccess.textContent = '';
        document.getElementById('loginModal').classList.remove('active');
        window.initialContainer.classList.remove('hidden');
        window.usernameContainer.classList.add('hidden');
        window.connectContainer.classList.add('hidden');
        window.chatContainer.classList.add('hidden');
        window.codeDisplayElement.classList.add('hidden');
        window.copyCodeButton.classList.add('hidden');
        window.statusElement.textContent = 'Start a new chat or connect to an existing one';
        updateLogoutButtonVisibility();
      }, 5000);
      return;
    }
    if (message.type === 'user-found') {
      const searchedUsername = document.getElementById('searchUsernameInput').value.trim();
      const searchResult = document.getElementById('searchResult');
      searchResult.innerHTML = `User ${searchedUsername} is ${message.status}. Code: `;
      const codeLink = document.createElement('a');
      codeLink.href = '#';
      codeLink.textContent = message.code;
      codeLink.onclick = (e) => {
        e.preventDefault();
        window.autoConnect(message.code);
        document.getElementById('searchUserModal').classList.remove('active');
      };
      searchResult.appendChild(codeLink);
      if (message.status === 'offline' && message.public_key) {
        window.userPublicKey = message.public_key;
        const offlineMsgContainer = document.createElement('div');
        const textarea = document.createElement('textarea');
        textarea.placeholder = 'Send offline message...';
        const sendBtn = document.createElement('button');
        sendBtn.textContent = 'Send';
        console.log('Setting up offline send button for', searchedUsername);
        sendBtn.onclick = () => {
          const msgText = textarea.value.trim();
          console.log('Offline send button clicked, text:', msgText, 'to:', searchedUsername);
          if (msgText) {
            window.sendOfflineMessage(searchedUsername, msgText).then(() => {
              console.log('Offline message sent successfully');
              textarea.value = '';
            }).catch(error => {
              console.error('Offline send error:', error);
              window.showStatusMessage('Failed to send offline message.');
            });
          } else {
            console.log('No message text, not sending');
          }
        };
        offlineMsgContainer.appendChild(textarea);
        offlineMsgContainer.appendChild(sendBtn);
        searchResult.appendChild(offlineMsgContainer);
      }
      return;
    }
    if (message.type === 'incoming-connection') {
      const fromUser = message.from === window.username ? 'Someone' : message.from;
      document.getElementById('incomingMessage').textContent = `${fromUser} wants to connect. Accept?`;
      document.getElementById('acceptButton').onclick = () => {
        window.socket.send(JSON.stringify({ type: 'connection-accepted', code: message.code, clientId: window.clientId, token: window.token }));
        window.autoConnect(message.code);
        document.getElementById('incomingConnectionModal').classList.remove('active');
      };
      document.getElementById('denyButton').onclick = () => {
        window.socket.send(JSON.stringify({ type: 'connection-denied', code: message.code, clientId: window.clientId, token: window.token }));
        document.getElementById('incomingConnectionModal').classList.remove('active');
      };
      document.getElementById('incomingConnectionModal').classList.add('active');
      return;
    }
    if (message.type === 'connection-denied') {
      window.showStatusMessage(`Connection request denied by ${message.from}`);
      return;
    }
    if (message.type === 'user-not-found') {
      document.getElementById('searchError').textContent = 'User not found.';
      setTimeout(() => {
        document.getElementById('searchError').textContent = '';
      }, 5000);
      return;
    }
    if (message.type === 'offline-message-sent') {
      window.showStatusMessage('Offline message sent successfully.');
      return;
    }
  } catch (error) {
    console.error('Error parsing message:', error, 'Raw data:', event.data);
  }
};