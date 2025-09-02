const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const crypto = require('crypto');
const otplib = require('otplib');
const UAParser = require('ua-parser-js');
const shared = require('./server1').shared;
function connectionHandler(ws, req) {
  const origin = req.headers.origin;
  if (!shared.ALLOWED_ORIGINS.includes(origin)) {
    console.warn(`Rejected connection from invalid origin: ${origin}`);
    ws.close(1008, 'Invalid origin');
    return;
  }
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress;
  const userAgent = req.headers['user-agent'] || 'unknown';
  ws.userAgent = userAgent;
  const hashedIp = shared.hashIp(clientIp);
  const hashedUa = shared.hashUa(userAgent);
  const compositeKey = hashedIp + ':' + hashedUa;
  if (shared.ipBans.has(compositeKey) && shared.ipBans.get(compositeKey).expiry > Date.now()) {
    ws.send(JSON.stringify({ type: 'error', message: 'IP temporarily banned due to excessive failures. Try again later.' }));
    return;
  }
  let clientId, code, username;
  let isAdmin = false;
  ws.on('message', async (message) => {
    if (!shared.restrictRate(ws)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }
    try {
      const data = JSON.parse(message);
      const loggedData = { ...data };
      if (loggedData.secret) {
        loggedData.secret = '[REDACTED]';
      }
      console.log('Received:', loggedData);
      const validation = shared.validateMessage(data);
      if (!validation.valid) {
        ws.send(JSON.stringify({ type: 'error', message: validation.error }));
        shared.incrementFailure(clientIp, ws.userAgent);
        return;
      }
      // Skip escaping for specific fields that should remain untouched
      const skipEscapeFields = [
        data.type === 'public-key' && 'publicKey',
        data.type === 'encrypted-room-key' && 'publicKey',
        data.type === 'encrypted-room-key' && 'encryptedKey',
        data.type === 'encrypted-room-key' && 'iv',
        data.type === 'new-room-key' && 'encrypted',
        data.type === 'new-room-key' && 'iv',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'content',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'data',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'encryptedContent',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'encryptedData',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'iv',
        (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-message') && 'signature',
        data.type === 'send-offline-message' && 'encrypted',
        data.type === 'send-offline-message' && 'iv',
        data.type === 'send-offline-message' && 'ephemeral_public'
      ];
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string' && !skipEscapeFields.includes(key)) {
          data[key] = validator.escape(validator.trim(data[key]));
        }
      });
      if ((data.type === 'public-key' || data.type === 'encrypted-room-key') && data.publicKey) {
        if (!shared.isValidBase64(data.publicKey) || data.publicKey.length < 128 || data.publicKey.length > 132) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format or length' }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
      }
      if (data.type === 'get-stats' || data.type === 'get-features' || data.type === 'toggle-feature') {
        if (data.secret === shared.ADMIN_SECRET) {
          isAdmin = true;
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
          return;
        }
      }
      if (!shared.features.enableService && !isAdmin && data.type !== 'connect') {
        ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
        ws.close();
        return;
      }
      if (data.type !== 'connect' && data.type !== 'refresh-token') {
        if (!data.token) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing authentication token' }));
          return;
        }
        try {
          let decoded = shared.jwt.verify(data.token, shared.JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
            return;
          }
          if (shared.revokedTokens.has(data.token)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
            return;
          }
        } catch (err) {
          if (fs.existsSync(shared.previousSecretFile)) {
            const previousSecret = fs.readFileSync(shared.previousSecretFile, 'utf8').trim();
            try {
              let decoded = shared.jwt.verify(data.token, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
                return;
              }
              if (shared.revokedTokens.has(data.token)) {
                ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
                return;
              }
            } catch (previousErr) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
              return;
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
            return;
          }
        }
      }
      if (data.type === 'connect') {
        clientId = data.clientId || shared.uuidv4();
        ws.clientId = clientId;
        shared.logStats({ clientId, event: 'connect' });
        const accessToken = shared.jwt.sign({ clientId }, shared.JWT_SECRET, { expiresIn: '10m' });
        const refreshToken = shared.jwt.sign({ clientId }, shared.JWT_SECRET, { expiresIn: '1h' });
        shared.clientTokens.set(clientId, { accessToken, refreshToken });
        ws.send(JSON.stringify({ type: 'connected', clientId, accessToken, refreshToken }));
        await shared.dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [clientId]);
        return;
      }
      if (data.type === 'refresh-token') {
        if (!data.refreshToken) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing refresh token' }));
          return;
        }
        try {
          const decoded = shared.jwt.verify(data.refreshToken, shared.JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
            return;
          }
          if (shared.revokedTokens.has(data.refreshToken)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
            return;
          }
          const oldRefreshExpiry = decoded.exp * 1000;
          shared.revokedTokens.set(data.refreshToken, oldRefreshExpiry);
          const newAccessToken = shared.jwt.sign({ clientId: data.clientId }, shared.JWT_SECRET, { expiresIn: '10m' });
          const newRefreshToken = shared.jwt.sign({ clientId: data.clientId }, shared.JWT_SECRET, { expiresIn: '1h' });
          shared.clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
          ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
        } catch (err) {
          if (fs.existsSync(shared.previousSecretFile)) {
            const previousSecret = fs.readFileSync(shared.previousSecretFile, 'utf8').trim();
            try {
              const decoded = shared.jwt.verify(data.refreshToken, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
                return;
              }
              if (shared.revokedTokens.has(data.refreshToken)) {
                ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
                return;
              }
              const oldRefreshExpiry = decoded.exp * 1000;
              shared.revokedTokens.set(data.refreshToken, oldRefreshExpiry);
              const newAccessToken = shared.jwt.sign({ clientId: data.clientId }, shared.JWT_SECRET, { expiresIn: '10m' });
              const newRefreshToken = shared.jwt.sign({ clientId: data.clientId }, shared.JWT_SECRET, { expiresIn: '1h' });
              shared.clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
              ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
            } catch (previousErr) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
              return;
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
            return;
          }
        }
        return;
      }
      if (data.type === 'public-key') {
        if (shared.rooms.has(data.code)) {
          const room = shared.rooms.get(data.code);
          const initiatorWs = room.clients.get(room.initiator)?.ws;
          if (initiatorWs && initiatorWs.readyState === WebSocket.OPEN) {
            initiatorWs.send(JSON.stringify({ type: 'public-key', publicKey: data.publicKey, clientId: data.clientId, code: data.code }));
            console.log(`Forwarded public-key from ${data.clientId} to initiator ${room.initiator} for code: ${data.code}`);
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Initiator offline, cannot exchange keys', code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'encrypted-room-key') {
        if (shared.rooms.has(data.code)) {
          const room = shared.rooms.get(data.code);
          const targetWs = room.clients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, publicKey: data.publicKey, clientId: data.clientId, code: data.code }));
            console.log(`Forwarded encrypted-room-key from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Target client not found or offline', code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'new-room-key') {
        if (shared.rooms.has(data.code)) {
          const room = shared.rooms.get(data.code);
          const targetWs = room.clients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'new-room-key', encrypted: data.encrypted, iv: data.iv, targetId: data.targetId, clientId: data.clientId, code: data.code }));
            console.log(`Forwarded new-room-key from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Target client not found or offline', code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'join') {
        if (!shared.features.enableService) {
          ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.', code: data.code }));
          return;
        }
        if (!shared.restrictIpRate(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!shared.restrictIpDaily(clientIp, 'join')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        if (!shared.validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!shared.validateCode(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format: xxxx-xxxx-xxxx-xxxx.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const roomTotpSecret = shared.totpSecrets.get(code);
        if (roomTotpSecret && !data.totpCode) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          return;
        }
        if (roomTotpSecret && data.totpCode) {
          const isValid = shared.otplib.authenticator.check(data.totpCode, roomTotpSecret);
          if (!isValid) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid TOTP code.', code: data.code }));
            shared.incrementFailure(clientIp, ws.userAgent);
            return;
          }
        }
        if (!shared.rooms.has(code)) {
          shared.rooms.set(code, { initiator: clientId, clients: new Map(), maxClients: 2 });
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: shared.TURN_USERNAME, turnCredential: shared.TURN_CREDENTIAL, features: shared.features }));
          shared.logStats({ clientId, username, code, event: 'init', totalClients: 1 });
        } else {
          const room = shared.rooms.get(code);
          if (room.clients.size >= room.maxClients) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room is full.', code: data.code }));
            shared.incrementFailure(clientIp, ws.userAgent);
            return;
          }
          if (room.clients.has(clientId)) {
            if (room.clients.get(clientId).username === username) {
              const oldWs = room.clients.get(clientId).ws;
              setTimeout(() => {
                oldWs.close();
              }, 1000);
              room.clients.delete(clientId);
              shared.broadcast(code, {
                type: 'client-disconnected',
                clientId,
                totalClients: room.clients.size,
                isInitiator: clientId === room.initiator
              });
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId.', code: data.code }));
              shared.incrementFailure(clientIp, ws.userAgent);
              return;
            }
          } else if (Array.from(room.clients.values()).some(c => c.username === username)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
            shared.incrementFailure(clientIp, ws.userAgent);
            return;
          }
          if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
            shared.incrementFailure(clientIp, ws.userAgent);
            return;
          }
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false, turnUsername: shared.TURN_USERNAME, turnCredential: shared.TURN_CREDENTIAL, features: shared.features }));
          shared.logStats({ clientId, username, code, event: 'join', totalClients: room.clients.size + 1 });
          if (room.clients.size > 0) {
            room.clients.forEach((_, existingClientId) => {
              if (existingClientId !== clientId) {
                shared.logStats({
                  clientId,
                  targetId: existingClientId,
                  code,
                  event: 'webrtc-connection',
                  totalClients: room.clients.size + 1
                });
              }
            });
          }
        }
        const room = shared.rooms.get(code);
        room.clients.set(clientId, { ws, username });
        ws.code = code;
        ws.username = username;
        shared.broadcast(code, { type: 'join-notify', clientId, username, code, totalClients: room.clients.size });
        return;
      }
      if (data.type === 'check-totp') {
        if (shared.totpSecrets.has(data.code)) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
        } else {
          ws.send(JSON.stringify({ type: 'totp-not-required', code: data.code }));
        }
        return;
      }
      if (data.type === 'set-max-clients') {
        if (shared.rooms.has(data.code) && data.clientId === shared.rooms.get(data.code).initiator) {
          const room = shared.rooms.get(data.code);
          room.maxClients = Math.min(data.maxClients, 10);
          shared.broadcast(data.code, { type: 'max-clients', maxClients: room.maxClients, totalClients: room.clients.size });
          shared.logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients: room.clients.size });
        }
        return;
      }
      if (data.type === 'set-totp') {
        if (shared.rooms.has(data.code) && data.clientId === shared.rooms.get(data.code).initiator) {
          shared.totpSecrets.set(data.code, data.secret);
          shared.broadcast(data.code, { type: 'totp-enabled', code: data.code });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
        }
        return;
      }
      if (data.type === 'offer' || data.type === 'answer' || data.type === 'candidate') {
        if (shared.rooms.has(data.code)) {
          const room = shared.rooms.get(data.code);
          const target = room.clients.get(data.targetId);
          if (target && target.ws.readyState === WebSocket.OPEN) {
            console.log(`Forwarding ${data.type} from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
            target.ws.send(JSON.stringify({ ...data, clientId }));
          } else {
            console.warn(`Target ${data.targetId} not found or not open in room ${data.code}`);
            ws.send(JSON.stringify({ type: 'error', message: `Target ${data.targetId} not found or offline`, code: data.code }));
          }
        }
        return;
      }
      if (data.type === 'submit-random') {
        if (!shared.restrictIpRate(clientIp, 'submit-random')) {
          ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (data.code && !shared.rooms.get(data.code)?.clients.size) {
          ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (shared.rooms.get(data.code)?.initiator === data.clientId) {
          shared.randomCodes.add(data.code);
          shared.broadcastRandomCodes();
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
        }
        return;
      }
      if (data.type === 'get-random-codes') {
        ws.send(JSON.stringify({ type: 'random-codes', codes: Array.from(shared.randomCodes) }));
        return;
      }
      if (data.type === 'remove-random-code') {
        if (shared.randomCodes.has(data.code)) {
          shared.randomCodes.delete(data.code);
          shared.broadcastRandomCodes();
          console.log(`Removed code ${data.code} from randomCodes`);
        }
        return;
      }
      if (data.type === 'relay-message' || data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') {
        if (data.type === 'relay-image' && !shared.features.enableImages) {
          ws.send(JSON.stringify({ type: 'error', message: 'Image messages are disabled.', code: data.code }));
          return;
        }
        if (data.type === 'relay-voice' && !shared.features.enableVoice) {
          ws.send(JSON.stringify({ type: 'error', message: 'Voice messages are disabled.', code: data.code }));
          return;
        }
        const payloadKey = data.content || data.encryptedContent || data.data || data.encryptedData;
        if (payloadKey && (typeof payloadKey !== 'string' || (data.encryptedContent || data.encryptedData || data.type !== 'relay-message') && !shared.isValidBase64(payloadKey))) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid payload format.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const payloadSize = payloadKey ? (payloadKey.length * 3 / 4) : 0;
        if (!shared.restrictClientSize(data.clientId, payloadSize)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Message size limit exceeded (1MB/min total).', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (payloadKey && payloadKey.length > 9333333) {
          ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 5MB).', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!shared.rooms.has(data.code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        const room = shared.rooms.get(data.code);
        const senderId = data.clientId;
        if (!room.clients.has(senderId)) {
          ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
          shared.incrementFailure(clientIp, ws.userAgent);
          return;
        }
        if (!shared.processedMessageIds.has(data.code)) {
          shared.processedMessageIds.set(data.code, new Map());
        }
        const messageSet = shared.processedMessageIds.get(data.code);
        if (messageSet.has(data.nonce)) {
          console.warn(`Duplicate nonce ${data.nonce} in room ${data.code}, ignoring`);
          return;
        }
        const now = Date.now();
        if (Math.abs(now - data.timestamp) > 300000) {
          console.warn(`Invalid timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp} (now: ${now})`);
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid message timestamp.', code: data.code }));
          return;
        }
        if (data.timestamp > now) {
          console.warn(`Future timestamp for nonce ${data.nonce} in room ${data.code}: ${data.timestamp}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Message timestamp in future.', code: data.code }));
          return;
        }
        messageSet.set(data.nonce, data.timestamp);
        room.clients.forEach((client, clientId) => {
          if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify({
              type: data.type.replace('relay-', ''),
              messageId: data.messageId,
              username: data.username,
              content: data.content,
              encryptedContent: data.encryptedContent,
              data: data.data,
              encryptedData: data.encryptedData,
              filename: data.filename,
              timestamp: data.timestamp,
              iv: data.iv,
              signature: data.signature,
              nonce: data.nonce
            }));
            console.log(`Relayed ${data.type} from ${senderId} to ${clientId} in code ${data.code}`);
          }
        });
        console.log(`Relayed ${data.type} from ${senderId} in code ${data.code} to ${room.clients.size - 1} clients`);
        return;
      }
      if (data.type === 'get-stats') {
        if (data.secret === shared.ADMIN_SECRET) {
          const now = new Date();
          const day = now.toISOString().slice(0, 10);
          let totalClients = 0;
          shared.rooms.forEach(room => {
            totalClients += room.clients.size;
          });
          let weekly = shared.computeAggregate(7);
          let monthly = shared.computeAggregate(30);
          let yearly = shared.computeAggregate(365);
          ws.send(JSON.stringify({
            type: 'stats',
            dailyUsers: shared.dailyUsers.get(day)?.size || 0,
            dailyConnections: shared.dailyConnections.get(day)?.size || 0,
            weeklyUsers: weekly.users,
            weeklyConnections: weekly.connections,
            monthlyUsers: monthly.users,
            monthlyConnections: monthly.connections,
            yearlyUsers: yearly.users,
            yearlyConnections: yearly.connections,
            allTimeUsers: shared.allTimeUsers.size,
            activeRooms: shared.rooms.size,
            totalClients: totalClients
          }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'get-features') {
        if (data.secret === shared.ADMIN_SECRET) {
          ws.send(JSON.stringify({ type: 'features', ...shared.features }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'toggle-feature') {
        if (data.secret === shared.ADMIN_SECRET) {
          const featureKey = `enable${data.feature.charAt(0).toUpperCase() + data.feature.slice(1)}`;
          if (shared.features.hasOwnProperty(featureKey)) {
            shared.features[featureKey] = !shared.features[featureKey];
            shared.saveFeatures();
            const timestamp = new Date().toISOString();
            fs.appendFileSync(shared.LOG_FILE, `${timestamp} - Admin toggled ${featureKey} to ${shared.features[featureKey]} by client ${shared.hashIp(clientIp)}\n`);
            ws.send(JSON.stringify({ type: 'feature-toggled', feature: data.feature, enabled: shared.features[featureKey] }));
            shared.wss.clients.forEach(client => {
              if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ type: 'features-update', ...shared.features }));
                if (data.feature === 'service' && !shared.features.enableService && !client.isAdmin) {
                  client.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
                  client.close();
                }
              }
            });
            if (data.feature === 'service' && !shared.features.enableService) {
              shared.clientTokens.forEach((tokens, clientId) => {
                shared.revokedTokens.set(tokens.accessToken, Date.now() + 1000);
                if (tokens.refreshToken) {
                  shared.revokedTokens.set(tokens.refreshToken, Date.now() + 1000);
                }
              });
              shared.clientTokens.clear();
              console.log('All tokens invalidated due to service disable');
              shared.rooms.clear();
              shared.randomCodes.clear();
              shared.totpSecrets.clear();
              shared.processedMessageIds.clear();
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid feature' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'export-stats-csv') {
        if (data.secret === shared.ADMIN_SECRET) {
          const csv = shared.generateStatsCSV();
          ws.send(JSON.stringify({ type: 'export-stats-csv', csv }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'export-logs-csv') {
        if (data.secret === shared.ADMIN_SECRET) {
          const csv = shared.generateLogsCSV();
          ws.send(JSON.stringify({ type: 'export-logs-csv', csv }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
        return;
      }
      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      if (data.type === 'pong') {
        console.log('Received pong from client');
        return;
      }
      if (data.type === 'set-totp') {
        if (shared.rooms.has(data.code) && data.clientId === shared.rooms.get(data.code).initiator) {
          shared.totpSecrets.set(data.code, data.secret);
          shared.broadcast(data.code, { type: 'totp-enabled', code: data.code });
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
        }
        return;
      }
      if (data.type === 'register-username') {
        const { username, password, public_key } = data;
        if (shared.validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          try {
            const checkRes = await shared.dbPool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (checkRes.rows.length > 0) {
              ws.send(JSON.stringify({ type: 'error', message: 'Username taken.' }));
              return;
            }
            const passwordHash = await shared.hashPassword(password);
            await shared.dbPool.query(
              'INSERT INTO users (username, password_hash, client_id, public_key) VALUES ($1, $2, $3, $4)',
              [username, passwordHash, data.clientId, public_key || null]
            );
            ws.send(JSON.stringify({ type: 'username-registered', username }));
            console.log(`Registered username ${username} for clientId ${data.clientId}`);
          } catch (err) {
            console.error('DB error registering username:', err.message, err.stack);
            ws.send(JSON.stringify({ type: 'error', message: 'Failed to register username. Check server logs for details.' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'login-username') {
        const { username, password } = data;
        if (shared.validateUsername(username) && password && typeof password === 'string' && password.length >= 8) {
          try {
            const res = await shared.dbPool.query('SELECT * FROM users WHERE username = $1', [username]);
            if (res.rows.length === 0) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid login credentials.' }));
              return;
            }
            const user = res.rows[0];
            const valid = await shared.validatePassword(password, user.password_hash);
            if (!valid) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid login credentials.' }));
              return;
            }
            await shared.dbPool.query('UPDATE users SET client_id = $1, last_active = CURRENT_TIMESTAMP WHERE id = $2', [data.clientId, user.id]);
            const msgRes = await shared.dbPool.query(`
              SELECT om.id, om.message, u.username AS from_username
              FROM offline_messages om
              JOIN users u ON om.from_user_id = u.id
              WHERE om.to_user_id = $1
            `, [user.id]);
            const offlineMessages = msgRes.rows.map(msg => {
              try {
                const parsedMessage = JSON.parse(msg.message);
                return {
                  id: msg.id, // Include message ID for confirmation
                  from: msg.from_username,
                  code: parsedMessage.code || null,
                  type: parsedMessage.type || 'connection-request',
                  encrypted: parsedMessage.encrypted || null,
                  iv: parsedMessage.iv || null,
                  ephemeral_public: parsedMessage.ephemeral_public || null
                };
              } catch (err) {
                console.error(`Failed to parse offline message for user ${user.id}:`, err.message);
                return null;
              }
            }).filter(msg => msg !== null);
            console.log(`Fetched ${offlineMessages.length} offline messages for user ${username} (id: ${user.id})`);
            ws.send(JSON.stringify({ type: 'login-success', username, offlineMessages }));
            console.log(`User ${username} logged in with clientId ${data.clientId}`);
          } catch (err) {
            console.error('DB error during login:', err.message, err.stack);
            ws.send(JSON.stringify({ type: 'error', message: 'Failed to login. Check server logs.' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username or password (min 8 chars).' }));
        }
        return;
      }
      if (data.type === 'find-user') {
        const { username, from_username } = data;
        try {
          const from_res = await shared.dbPool.query('SELECT id, username FROM users WHERE client_id = $1', [data.clientId]);
          if (from_res.rows.length === 0) {
            console.warn(`Find-user failed: No user found for clientId ${data.clientId}`);
            ws.send(JSON.stringify({ type: 'error', message: 'Must be logged in to search users.' }));
            return;
          }
          const from_user_id = from_res.rows[0].id;
          const from_username = from_res.rows[0].username;
          const res = await shared.dbPool.query('SELECT * FROM users WHERE username = $1', [username]);
          if (res.rows.length === 0) {
            ws.send(JSON.stringify({ type: 'user-not-found' }));
            return;
          }
          const user = res.rows[0];
          const dynamicCode = shared.uuidv4().replace(/-/g, '').substring(0, 16).match(/.{1,4}/g).join('-');
          const ownerWs = [...shared.wss.clients].find(client => client.clientId === user.client_id);
          if (ownerWs) {
            ownerWs.send(JSON.stringify({ type: 'incoming-connection', from: from_username, code: dynamicCode }));
          } else {
            await shared.dbPool.query(
              'INSERT INTO offline_messages (from_user_id, to_user_id, message) VALUES ($1, $2, $3)',
              [from_user_id, user.id, JSON.stringify({ type: 'connection-request', code: dynamicCode })]
            );
          }
          const lastActive = user.last_active ? new Date(user.last_active).getTime() : 0;
          const isOnline = ownerWs || (Date.now() - lastActive < 5 * 60 * 1000);
          ws.send(JSON.stringify({ type: 'user-found', status: isOnline ? 'online' : 'offline', code: dynamicCode, public_key: user.public_key }));
          console.log(`User ${username} found for clientId ${data.clientId}, status: ${isOnline ? 'online' : 'offline'}, code: ${dynamicCode}`);
        } catch (err) {
          console.error('DB error finding user:', err.message, err.stack);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to find user. Check server logs for details.' }));
        }
        return;
      }
      if (data.type === 'send-offline-message') {
        const { to_username, encrypted, iv, ephemeral_public, messageId } = data;
        try {
          const res = await shared.dbPool.query('SELECT id FROM users WHERE username = $1', [to_username]);
          if (res.rows.length === 0) {
            ws.send(JSON.stringify({ type: 'error', message: 'Recipient not found.' }));
            return;
          }
          const to_user_id = res.rows[0].id;
          const from_res = await shared.dbPool.query('SELECT id FROM users WHERE client_id = $1', [data.clientId]);
          if (from_res.rows.length === 0) {
            console.warn(`Send-offline-message failed: No user found for clientId ${data.clientId}`);
            ws.send(JSON.stringify({ type: 'error', message: 'Sender not logged in with a username.' }));
            return;
          }
          const from_user_id = from_res.rows[0].id;
          await shared.dbPool.query(
            'INSERT INTO offline_messages (from_user_id, to_user_id, message) VALUES ($1, $2, $3)',
            [from_user_id, to_user_id, JSON.stringify({ type: 'message', encrypted, iv, ephemeral_public, messageId })]
          );
          ws.send(JSON.stringify({ type: 'offline-message-sent', messageId }));
          console.log(`Offline message ${messageId} sent from clientId ${data.clientId} (user_id: ${from_user_id}) to ${to_username} (user_id: ${to_user_id})`);
        } catch (err) {
          console.error('DB error sending offline message:', err.message, err.stack);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to send offline message.' }));
        }
        return;
      }
      if (data.type === 'confirm-offline-message') {
        try {
          await shared.dbPool.query('DELETE FROM offline_messages WHERE id = $1', [data.messageId]);
          console.log(`Confirmed and deleted offline message ${data.messageId} for clientId ${data.clientId}`);
          ws.send(JSON.stringify({ type: 'confirm-offline-message-ack', messageId: data.messageId }));
        } catch (err) {
          console.error('DB error confirming offline message:', err.message, err.stack);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to confirm offline message.' }));
        }
        return;
      }
      if (data.type === 'logout') {
        if (shared.clientTokens.has(data.clientId)) {
          const tokens = shared.clientTokens.get(data.clientId);
          shared.revokedTokens.set(tokens.accessToken, Date.now() + 1000);
          if (tokens.refreshToken) {
            shared.revokedTokens.set(tokens.refreshToken, Date.now() + 1000);
          }
          shared.clientTokens.delete(data.clientId);
          console.log(`Client ${data.clientId} logged out, tokens revoked`);
        }
        if (ws.code && shared.rooms.has(ws.code)) {
          const room = shared.rooms.get(ws.code);
          const isInitiator = ws.clientId === room.initiator;
          room.clients.delete(ws.clientId);
          shared.logStats({ clientId: ws.clientId, code: ws.code, event: 'logout', totalClients: room.clients.size, isInitiator });
          if (room.clients.size === 0 || isInitiator) {
            shared.rooms.delete(ws.code);
            shared.randomCodes.delete(ws.code);
            shared.totpSecrets.delete(ws.code);
            shared.processedMessageIds.delete(ws.code);
            shared.broadcast(ws.code, {
              type: 'client-disconnected',
              clientId: ws.clientId,
              totalClients: 0,
              isInitiator
            });
          } else {
            if (isInitiator) {
              const newInitiator = room.clients.keys().next().value;
              if (newInitiator) {
                room.initiator = newInitiator;
                shared.broadcast(ws.code, {
                  type: 'initiator-changed',
                  newInitiator,
                  totalClients: room.clients.size
                });
              }
            }
            shared.broadcast(ws.code, {
              type: 'client-disconnected',
              clientId: ws.clientId,
              totalClients: room.clients.size,
              isInitiator
            });
          }
        }
        ws.send(JSON.stringify({ type: 'logout-success' }));
        return;
      }
    } catch (error) {
      console.error('Error processing message:', error.message, error.stack);
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again. Check server logs.' }));
      shared.incrementFailure(clientIp, ws.userAgent);
    }
  });
  ws.on('close', async () => {
    if (ws.clientId) {
      const tokens = shared.clientTokens.get(ws.clientId);
      if (tokens) {
        try {
          const decoded = shared.jwt.verify(tokens.accessToken, shared.JWT_SECRET, { ignoreExpiration: true });
          shared.revokedTokens.set(tokens.accessToken, decoded.exp * 1000);
          if (tokens.refreshToken) {
            const decodedRefresh = shared.jwt.verify(tokens.refreshToken, shared.JWT_SECRET, { ignoreExpiration: true });
            shared.revokedTokens.set(tokens.refreshToken, decodedRefresh.exp * 1000);
          }
          shared.clientTokens.delete(ws.clientId);
          console.log(`Revoked tokens for client ${ws.clientId} on disconnect`);
        } catch (err) {
          console.warn(`Failed to revoke tokens for client ${ws.clientId}: ${err.message}`);
        }
      }
    }
    if (ws.code && shared.rooms.has(ws.code)) {
      const room = shared.rooms.get(ws.code);
      const isInitiator = ws.clientId === room.initiator;
      room.clients.delete(ws.clientId);
      shared.rateLimits.delete(ws.clientId);
      shared.logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients: room.clients.size, isInitiator });
      if (room.clients.size === 0 || isInitiator) {
        shared.rooms.delete(ws.code);
        shared.randomCodes.delete(ws.code);
        shared.totpSecrets.delete(ws.code);
        shared.processedMessageIds.delete(ws.code);
        shared.broadcast(ws.code, {
          type: 'client-disconnected',
          clientId: ws.clientId,
          totalClients: 0,
          isInitiator
        });
      } else {
        if (isInitiator) {
          const newInitiator = room.clients.keys().next().value;
          if (newInitiator) {
            room.initiator = newInitiator;
            shared.broadcast(ws.code, {
              type: 'initiator-changed',
              newInitiator,
              totalClients: room.clients.size
            });
          }
        }
        shared.broadcast(ws.code, {
          type: 'client-disconnected',
          clientId: ws.clientId,
          totalClients: room.clients.size,
          isInitiator
        });
      }
    }
    await shared.dbPool.query('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE client_id = $1', [ws.clientId]);
  });
}
module.exports = { connectionHandler };
