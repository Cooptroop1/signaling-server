// events.js - All event listeners and handlers for Anonomoose Chat

// Function definitions first for hoisting safety

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

function generateCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const randomBytes = window.crypto.getRandomValues(new Uint8Array(16));
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars[randomBytes[i] % chars.length];
    if (i % 4 === 3 && i < 15) result += '-';
  }
  return result;
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

function updateDots() {
  const userDots = document.getElementById('userDots');
  if (!userDots) return;
  userDots.innerHTML = '';
  const greenCount = totalClients;
  const redCount = maxClients - greenCount;
  const otherClientIds = Array.from(connectedClients).filter(id => id !== clientId);
  // Add self dot (no menu)
  const selfDot = document.createElement('div');
  selfDot.className = 'user-dot online';
  userDots.appendChild(selfDot);
  // Add other users' dots with menu if initiator
  otherClientIds.forEach((targetId) => {
    const dot = document.createElement('div');
    dot.className = 'user-dot online';
    dot.dataset.targetId = targetId;
    if (isInitiator) {
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
  // Add offline (red) dots
  for (let i = 0; i < redCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'user-dot offline';
    userDots.appendChild(dot);
  }
}

async function kickUser(targetId) {
  if (!isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for kick:', targetId);
    showStatusMessage('Invalid target user for kick.');
    return;
  }
  console.log('Kicking user', targetId);
  const toSign = targetId + 'kick' + code;
  const signature = await signMessage(signingKey, toSign);
  const message = { type: 'kick', targetId, code, clientId, token, signature };
  console.log('Sending kick message:', message);
  socket.send(JSON.stringify(message));
  showStatusMessage(`Kicked user ${usernames.get(targetId) || targetId}`);
}

async function banUser(targetId) {
  if (!isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for ban:', targetId);
    showStatusMessage('Invalid target user for ban.');
    return;
  }
  console.log('Banning user', targetId);
  const toSign = targetId + 'ban' + code;
  const signature = await signMessage(signingKey, toSign);
  const message = { type: 'ban', targetId, code, clientId, token, signature };
  console.log('Sending ban message:', message);
  socket.send(JSON.stringify(message));
  showStatusMessage(`Banned user ${usernames.get(targetId) || targetId}`);
}

function setupWaitingForJoin(codeParam) {
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
      };
    }
  } else {
    console.log('Invalid code, showing initial container');
    initialContainer.classList.remove('hidden');
    usernameContainer.classList.add('hidden');
    chatContainer.classList.add('hidden');
    showStatusMessage('Invalid code format. Please enter a valid code.');
    document.getElementById('connectCodeButton')?.focus();
  }
}

function setupLazyObserver() {
  lazyObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const elem = entry.target;
        if (elem.dataset.src) {
          elem.src = elem.dataset.src;
          delete elem.dataset.src;
          lazyObserver.unobserve(elem);
        }
        if (elem.dataset.fullSrc) {
          elem.src = elem.dataset.fullSrc;
          delete elem.dataset.fullSrc;
          lazyObserver.unobserve(elem);
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
      button.onclick = () => autoConnect(recentCode);
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

// Claim username
document.getElementById('claimUsernameButton').addEventListener('click', () => {
  document.getElementById('claimError').classList.add('hidden');
  document.getElementById('claimUsernameModal').classList.add('active');
});

document.getElementById('claimSubmitButton').onclick = async () => {
  const name = document.getElementById('claimUsernameInput').value.trim();
  const pass = document.getElementById('claimPasswordInput').value;
  if (name && pass) {
    socket.send(JSON.stringify({ type: 'register-username', username: name, password: pass, clientId, token }));
  }
};

document.getElementById('claimCancelButton').onclick = () => {
  document.getElementById('claimUsernameModal').classList.remove('active');
};

// Cleanup old nonces every 5min
setInterval(() => {
  const now = Date.now();
  for (const [nonce, ts] of processedNonces) {
    if (now - ts > 3600000) { // 1hr
      processedNonces.delete(nonce);
    }
  }
  console.log(`Cleaned processedNonces, remaining: ${processedNonces.size}`);
}, 300000);

// Start chat toggle (legacy? integrate if needed)
document.getElementById('startChatToggleButton').onclick = () => {
  console.log('Start chat toggle clicked');
  initialContainer.classList.add('hidden');
  usernameContainer.classList.remove('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  statusElement.textContent = 'Enter a username to start a chat';
  document.getElementById('usernameInput').value = username || '';
  document.getElementById('usernameInput')?.focus();
};

// Connect toggle (legacy? integrate if needed)
document.getElementById('connectToggleButton').onclick = () => {
  console.log('Connect toggle clicked');
  initialContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.remove('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  statusElement.textContent = 'Enter a username and code to join a chat';
  document.getElementById('usernameConnectInput').value = username || '';
  document.getElementById('usernameConnectInput')?.focus();
};

// Start 2FA
document.getElementById('start2FAChatButton').onclick = () => {
  document.getElementById('totpOptionsModal').classList.add('active');
  document.getElementById('totpUsernameInput').value = username || '';
  document.getElementById('totpUsernameInput')?.focus();
  document.getElementById('customTotpSecretContainer').classList.add('hidden');
  document.querySelector('input[name="totpType"][value="server"]').checked = true;
};

// Connect 2FA
document.getElementById('connect2FAChatButton').onclick = () => {
  initialContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.remove('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  statusElement.textContent = 'Enter a username and code to join a 2FA chat';
  document.getElementById('usernameConnectInput').value = username || '';
  document.getElementById('usernameConnectInput')?.focus();
  const connectButton = document.getElementById('connectButton');
  connectButton.onclick = () => {
    const usernameInput = document.getElementById('usernameConnectInput').value.trim();
    const inputCode = document.getElementById('codeInput').value.trim();
    if (!validateUsername(usernameInput)) {
      showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
      document.getElementById('usernameConnectInput')?.focus();
      return;
    }
    if (!validateCode(inputCode)) {
      showStatusMessage('Invalid code format: xxxx-xxxx-xxxx-xxxx.');
      document.getElementById('codeInput')?.focus();
      return;
    }
    username = usernameInput;
    localStorage.setItem('username', username);
    code = inputCode;
    showTotpInputModal(code);
  };
};

// TOTP type change
document.querySelectorAll('input[name="totpType"]').forEach(radio => {
  radio.addEventListener('change', () => {
    document.getElementById('customTotpSecretContainer').classList.toggle('hidden', radio.value !== 'custom');
  });
});

// Create TOTP room
document.getElementById('createTotpRoomButton').onclick = () => {
  const serverGenerated = document.querySelector('input[name="totpType"]:checked').value === 'server';
  startTotpRoom(serverGenerated);
};

// Cancel TOTP
document.getElementById('cancelTotpButton').onclick = () => {
  document.getElementById('totpOptionsModal').classList.remove('active');
  initialContainer.classList.remove('hidden');
};

// Close TOTP secret
document.getElementById('closeTotpSecretButton').onclick = () => {
  document.getElementById('totpSecretModal').classList.remove('active');
};

// Submit TOTP code
document.getElementById('submitTotpCodeButton').onclick = () => {
  const totpCode = document.getElementById('totpCodeInput').value.trim();
  const codeParam = document.getElementById('totpInputModal').dataset.code;
  if (totpCode.length !== 6 || isNaN(totpCode)) {
    showStatusMessage('Invalid 2FA code: 6 digits required.');
    return;
  }
  joinWithTotp(codeParam, totpCode);
  document.getElementById('totpInputModal').classList.remove('active');
};

// Cancel TOTP input
document.getElementById('cancelTotpInputButton').onclick = () => {
  document.getElementById('totpInputModal').classList.remove('active');
  initialContainer.classList.remove('hidden');
};

// Join with username
document.getElementById('joinWithUsernameButton').onclick = () => {
  const usernameInput = document.getElementById('usernameInput').value.trim();
  if (!validateUsername(usernameInput)) {
    showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
    document.getElementById('usernameInput')?.focus();
    return;
  }
  username = usernameInput;
  localStorage.setItem('username', username);
  console.log('Username set in localStorage:', username);
  code = generateCode();
  codeDisplayElement.textContent = `Your code: ${code}`;
  codeDisplayElement.classList.remove('hidden');
  copyCodeButton.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  initialContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for connection...';
  if (socket.readyState === WebSocket.OPEN && token) {
    console.log('Sending join message for new chat');
    socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  } else {
    pendingJoin = { code, clientId, username };
    if (socket.readyState !== WebSocket.OPEN) {
      socket.addEventListener('open', () => {
        console.log('WebSocket opened, sending join for new chat');
        if (token) {
          socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
          pendingJoin = null;
        }
      }, { once: true });
    }
  }
  document.getElementById('messageInput')?.focus();
};

// Connect button
document.getElementById('connectButton').onclick = () => {
  const usernameInput = document.getElementById('usernameConnectInput').value.trim();
  const inputCode = document.getElementById('codeInput').value.trim();
  if (!validateUsername(usernameInput)) {
    showStatusMessage('Invalid username: 1-16 alphanumeric characters.');
    document.getElementById('usernameConnectInput')?.focus();
    return;
  }
  if (!validateCode(inputCode)) {
    showStatusMessage('Invalid code format: xxxx-xxxx-xxxx-xxxx.');
    document.getElementById('codeInput')?.focus();
    return;
  }
  username = usernameInput;
  localStorage.setItem('username', username);
  console.log('Username set in localStorage:', username);
  code = inputCode;
  codeDisplayElement.textContent = `Using code: ${code}`;
  codeDisplayElement.classList.remove('hidden');
  copyCodeButton.classList.remove('hidden');
  initialContainer.classList.add('hidden');
  usernameContainer.classList.add('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.remove('hidden');
  messages.classList.add('waiting');
  statusElement.textContent = 'Waiting for connection...';
  if (socket.readyState === WebSocket.OPEN && token) {
    console.log('Sending join message for existing chat');
    socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
  } else {
    pendingJoin = { code, clientId, username };
    if (socket.readyState !== WebSocket.OPEN) {
      socket.addEventListener('open', () => {
        console.log('WebSocket opened, sending join for existing chat');
        if (token) {
          socket.send(JSON.stringify({ type: 'join', code, clientId, username, token }));
          pendingJoin = null;
        }
      }, { once: true });
    }
  }
  document.getElementById('messageInput')?.focus();
};

document.getElementById('backButton').onclick = () => {
  console.log('Back button clicked from usernameContainer');
  usernameContainer.classList.add('hidden');
  initialContainer.classList.remove('hidden');
  connectContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  messages.classList.remove('waiting');
  document.getElementById('startAnonChatButton')?.focus();
};

document.getElementById('backButtonConnect').onclick = () => {
  console.log('Back button clicked from connectContainer');
  connectContainer.classList.add('hidden');
  initialContainer.classList.remove('hidden');
  usernameContainer.classList.add('hidden');
  chatContainer.classList.add('hidden');
  codeDisplayElement.classList.add('hidden');
  copyCodeButton.classList.add('hidden');
  statusElement.textContent = 'Start a new chat or connect to an existing one';
  messages.classList.remove('waiting');
  document.getElementById('connectCodeButton')?.focus();
};

document.getElementById('sendButton').onclick = () => {
  const messageInput = document.getElementById('messageInput');
  const message = messageInput.value.trim();
  if (message) {
    sendMessage(message);
  }
};

document.getElementById('messageInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value.trim();
    if (message) {
      sendMessage(message);
    }
  }
});

document.getElementById('imageButton').onclick = () => {
  document.getElementById('imageInput')?.click();
};

document.getElementById('imageInput').onchange = (event) => {
  const file = event.target.files[0];
  if (file) {
    const type = file.type.startsWith('image/') ? 'image' : 'file';
    sendMedia(file, type);
    event.target.value = '';
  }
};

document.getElementById('voiceButton').onclick = () => {
  if (!mediaRecorder || mediaRecorder.state !== 'recording') {
    startVoiceRecording();
  } else {
    stopVoiceRecording();
  }
};

document.getElementById('voiceCallButton').onclick = () => {
  toggleVoiceCall();
};

document.getElementById('audioOutputButton').onclick = () => {
  toggleAudioOutput();
};

document.getElementById('grokButton').onclick = () => {
  toggleGrokBot();
};

document.getElementById('saveGrokKey').onclick = () => {
  saveGrokKey();
};

document.getElementById('newSessionButton').onclick = () => {
  console.log('New session button clicked');
  window.location.href = 'https://anonomoose.com';
};

document.getElementById('usernameInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    document.getElementById('joinWithUsernameButton')?.click();
  }
});

document.getElementById('usernameConnectInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    document.getElementById('codeInput')?.focus();
  }
});

document.getElementById('codeInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault();
    document.getElementById('connectButton')?.click();
  }
});

document.getElementById('copyCodeButton').onclick = () => {
  const codeText = codeDisplayElement.textContent.replace('Your code: ', '').replace('Using code: ', '');
  navigator.clipboard.writeText(codeText).then(() => {
    copyCodeButton.textContent = 'Copied!';
    setTimeout(() => {
      copyCodeButton.textContent = 'Copy Code';
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy text: ', err);
    showStatusMessage('Failed to copy code.');
  });
  copyCodeButton?.focus();
};

document.getElementById('button1').onclick = () => {
  if (isInitiator && socket.readyState === WebSocket.OPEN && code && totalClients < maxClients && token) {
    socket.send(JSON.stringify({ type: 'submit-random', code, clientId, token }));
    showStatusMessage(`Sent code ${code} to random board.`);
    codeSentToRandom = true;
    button2.disabled = true;
  } else {
    showStatusMessage('Cannot send: Not initiator, no code, no token, or room is full.');
  }
  document.getElementById('button1')?.focus();
};

document.getElementById('button2').onclick = () => {
  if (!button2.disabled) {
    window.location.href = 'https://anonomoose.com/random.html';
  }
  document.getElementById('button2')?.focus();
};

cornerLogo.addEventListener('click', () => {
  document.getElementById('messages').innerHTML = '';
  processedMessageIds.clear();
  showStatusMessage('Chat history cleared locally.');
});

function updateDots() {
  const userDots = document.getElementById('userDots');
  if (!userDots) return;
  userDots.innerHTML = '';
  const greenCount = totalClients;
  const redCount = maxClients - greenCount;
  const otherClientIds = Array.from(connectedClients).filter(id => id !== clientId);
  // Add self dot (no menu)
  const selfDot = document.createElement('div');
  selfDot.className = 'user-dot online';
  userDots.appendChild(selfDot);
  // Add other users' dots with menu if initiator
  otherClientIds.forEach((targetId, index) => {
    const dot = document.createElement('div');
    dot.className = 'user-dot online';
    dot.dataset.targetId = targetId;
    if (isInitiator) {
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
  // Add offline (red) dots
  for (let i = 0; i < redCount; i++) {
    const dot = document.createElement('div');
    dot.className = 'user-dot offline';
    userDots.appendChild(dot);
  }
}

async function kickUser(targetId) {
  if (!isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for kick:', targetId);
    showStatusMessage('Invalid target user for kick.');
    return;
  }
  console.log('Kicking user', targetId);
  const toSign = targetId + 'kick' + code;
  const signature = await signMessage(signingKey, toSign);
  const message = { type: 'kick', targetId, code, clientId, token, signature };
  console.log('Sending kick message:', message);
  socket.send(JSON.stringify(message));
  showStatusMessage(`Kicked user ${usernames.get(targetId) || targetId}`);
}

async function banUser(targetId) {
  if (!isInitiator) return;
  if (!targetId || typeof targetId !== 'string') {
    console.error('Invalid targetId for ban:', targetId);
    showStatusMessage('Invalid target user for ban.');
    return;
  }
  console.log('Banning user', targetId);
  const toSign = targetId + 'ban' + code;
  const signature = await signMessage(signingKey, toSign);
  const message = { type: 'ban', targetId, code, clientId, token, signature };
  console.log('Sending ban message:', message);
  socket.send(JSON.stringify(message));
  showStatusMessage(`Banned user ${usernames.get(targetId) || targetId}`);
}

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

document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam && validateCode(codeParam)) {
    setupWaitingForJoin(codeParam);
  }
  // Auto-format code input
  const codeInput = document.getElementById('codeInput');
  if (codeInput) {
    codeInput.addEventListener('input', (e) => {
      let val = e.target.value.replace(/[^a-zA-Z0-9]/gi, ''); // Remove non-alphanum, case insensitive
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
      // Toggle menu if needed; already in CSS hover, but for touch/mobile, add click toggle
      e.target.classList.toggle('active'); // Add .active to show menu on click
    }
  });
  // Toggle recent chats
  const toggleRecent = document.getElementById('toggleRecent');
  const recentCodesList = document.getElementById('recentCodesList');
  toggleRecent.addEventListener('click', () => {
    const isHidden = recentCodesList.classList.toggle('hidden');
    toggleRecent.textContent = isHidden ? 'Show' : 'Hide';
  });
});

// Cleanup old nonces every 5min
setInterval(() => {
  const now = Date.now();
  for (const [nonce, ts] of processedNonces) {
    if (now - ts > 3600000) { // 1hr = 3600000ms
      processedNonces.delete(nonce);
    }
  }
  console.log(`Cleaned processedNonces, remaining: ${processedNonces.size}`);
}, 300000); // 5min
