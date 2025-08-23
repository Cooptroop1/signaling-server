const fs = require('fs');
const crypto = require('crypto');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const otplib = require('otplib');

module.exports = function(shared) {
  const {
    wss,
    rooms,
    dailyUsers,
    dailyConnections,
    LOG_FILE,
    FEATURES_FILE,
    STATS_FILE,
    UPDATE_INTERVAL,
    randomCodes,
    rateLimits,
    allTimeUsers,
    ipRateLimits,
    ipDailyLimits,
    ipFailureCounts,
    ipBans,
    revokedTokens,
    clientTokens,
    totpSecrets,
    processedMessageIds,
    ADMIN_SECRET,
    ALLOWED_ORIGINS,
    JWT_SECRET,
    TURN_USERNAME,
    TURN_CREDENTIAL,
    IP_SALT,
    features,
    aggregatedStats,
    pingInterval,
    validateMessage,
    isValidBase32,
    isValidBase64,
    saveFeatures,
    saveAggregatedStats
  } = shared;

  function restrictRate(ws) {
    if (ws.isAdmin) return true;
    if (!ws.clientId) return true;
    const now = Date.now();
    const rateLimit = rateLimits.get(ws.clientId) || { count: 0, startTime: now };
    if (now - rateLimit.startTime >= 60000) {
      rateLimit.count = 0;
      rateLimit.startTime = now;
    }
    rateLimit.count += 1;
    rateLimits.set(ws.clientId, rateLimit);
    if (rateLimit.count > 50) {
      console.warn(`Rate limit exceeded for client ${ws.clientId}: ${rateLimit.count} messages in 60s`);
      fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - Rate limit exceeded for client ${ws.clientId}: ${rateLimit.count} messages\n`);
      return false;
    }
    return true;
  }

  function restrictIpRate(ip, action) {
    const hashedIp = hashIp(ip);
    const now = Date.now();
    const key = `${hashedIp}:${action}`;
    const rateLimit = ipRateLimits.get(key) || { count: 0, startTime: now };
    if (now - rateLimit.startTime >= 60000) {
      rateLimit.count = 0;
      rateLimit.startTime = now;
    }
    rateLimit.count += 1;
    ipRateLimits.set(key, rateLimit);
    if (rateLimit.count > 5) {
      console.warn(`IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${rateLimit.count} in 60s`);
      fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${rateLimit.count}\n`);
      return false;
    }
    return true;
  }

  function restrictIpDaily(ip, action) {
    const hashedIp = hashIp(ip);
    const day = new Date().toISOString().slice(0, 10);
    const key = `${hashedIp}:${action}:${day}`;
    const dailyLimit = ipDailyLimits.get(key) || { count: 0 };
    dailyLimit.count += 1;
    ipDailyLimits.set(key, dailyLimit);
    if (dailyLimit.count > 100) {
      console.warn(`Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${dailyLimit.count} in day ${day}`);
      fs.appendFileSync(LOG_FILE, `${new Date().toISOString()} - Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${dailyLimit.count}\n`);
      return false;
    }
    return true;
  }

  function incrementFailure(ip) {
    const hashedIp = hashIp(ip);
    const failure = ipFailureCounts.get(hashedIp) || { count: 0, banLevel: 0 };
    failure.count += 1;
    ipFailureCounts.set(hashedIp, failure);
    if (failure.count % 5 === 0) {
      console.warn(`High failure rate for hashed IP ${hashedIp}: ${failure.count} failures`);
    }
    if (failure.count >= 10) {
      const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];
      failure.banLevel = Math.min(failure.banLevel + 1, 2);
      const duration = banDurations[failure.banLevel];
      const expiry = Date.now() + duration;
      ipBans.set(hashedIp, { expiry, banLevel: failure.banLevel });
      const timestamp = new Date().toISOString();
      const banLogEntry = `${timestamp} - Hashed IP Banned: ${hashedIp}, Duration: ${duration / 60000} minutes, Ban Level: ${failure.banLevel}\n`;
      fs.appendFileSync(LOG_FILE, banLogEntry, (err) => {
        if (err) {
          console.error('Error appending ban log:', err);
        } else {
          console.warn(`Hashed IP ${hashedIp} banned until ${new Date(expiry).toISOString()} at ban level ${failure.banLevel} (${duration / 60000} minutes)`);
        }
      });
      ipFailureCounts.delete(hashedIp);
    }
  }

  function validateUsername(username) {
    const regex = /^[a-zA-Z0-9]{1,16}$/;
    return username && regex.test(username);
  }

  function validateCode(code) {
    const regex = /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/;
    return code && regex.test(code);
  }

  function logStats(data) {
    const timestamp = new Date().toISOString();
    const day = timestamp.slice(0, 10);
    const stats = {
      clientId: data.clientId,
      username: data.username ? crypto.createHmac('sha256', IP_SALT).update(data.username).digest('hex') : '',
      targetId: data.targetId || '',
      code: data.code || '',
      event: data.event || '',
      totalClients: data.totalClients || 0,
      isInitiator: data.isInitiator || false,
      timestamp,
      day
    };
    if (data.event === 'connect' || data.event === 'join' || data.event === 'webrtc-connection') {
      if (!dailyUsers.has(day)) {
        dailyUsers.set(day, new Set());
      }
      if (!dailyConnections.has(day)) {
        dailyConnections.set(day, new Set());
      }
      dailyUsers.get(day).add(data.clientId);
      allTimeUsers.add(data.clientId);
      if (data.event === 'webrtc-connection' && data.targetId) {
        dailyUsers.get(day).add(data.targetId);
        allTimeUsers.add(data.targetId);
        const connectionKey = `${data.clientId}-${data.targetId}-${data.code}`;
        dailyConnections.get(day).add(connectionKey);
      }
    }
    const logEntry = `${timestamp} - Client: ${stats.clientId}, Event: ${stats.event}, Code: ${stats.code}, Username: ${stats.username}, TotalClients: ${stats.totalClients}, IsInitiator: ${stats.isInitiator}\n`;
    fs.appendFileSync(LOG_FILE, logEntry, (err) => {
      if (err) {
        console.error('Error appending to log file:', err);
      }
    });
  }

  function updateLogFile() {
    const now = new Date();
    const day = now.toISOString().slice(0, 10);
    const userCount = dailyUsers.get(day)?.size || 0;
    const connectionCount = dailyConnections.get(day)?.size || 0;
    const allTimeUserCount = allTimeUsers.size;
    const logEntry = `${now.toISOString()} - Day: ${day}, Unique Users: ${userCount}, WebRTC Connections: ${connectionCount}, All-Time Unique Users: ${allTimeUserCount}\n`;
    fs.appendFileSync(LOG_FILE, logEntry, (err) => {
      if (err) {
        console.error('Error writing to log file:', err);
      } else {
        console.log(`Updated ${LOG_FILE} with ${userCount} unique users, ${connectionCount} WebRTC connections, and ${allTimeUserCount} all-time unique users for ${day}`);
      }
    });
    if (!aggregatedStats.daily) aggregatedStats.daily = {};
    aggregatedStats.daily[day] = { users: userCount, connections: connectionCount };
    saveAggregatedStats();
  }

  function computeAggregate(days) {
    const now = new Date();
    let users = 0, connections = 0;
    for (let i = 0; i < days; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const key = date.toISOString().slice(0, 10);
      if (aggregatedStats.daily[key]) {
        users += aggregatedStats.daily[key].users;
        connections += aggregatedStats.daily[key].connections;
      }
    }
    return { users, connections };
  }

  function broadcast(code, message) {
    const room = rooms.get(code);
    if (room) {
      room.clients.forEach(client => {
        if (client.ws.readyState === WebSocket.OPEN) {
          client.ws.send(JSON.stringify(message));
        }
      });
      console.log(`Broadcasted ${message.type} to ${room.clients.size} clients in code ${code}`);
    } else {
      console.warn(`Cannot broadcast: Room ${code} not found`);
    }
  }

  function broadcastRandomCodes() {
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
      }
    });
    console.log(`Broadcasted random codes to all clients: ${Array.from(randomCodes)}`);
  }

  function hashIp(ip) {
    return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
  }

  fs.writeFileSync(LOG_FILE, '', (err) => {
    if (err) console.error('Error creating log file:', err);
    else {
      updateLogFile();
      setInterval(updateLogFile, UPDATE_INTERVAL);
    }
  });

  wss.on('connection', (ws, req) => {
    const origin = req.headers.origin;
    if (!ALLOWED_ORIGINS.includes(origin)) {
      console.warn(`Rejected connection from invalid origin: ${origin}`);
      ws.close(1008, 'Invalid origin');
      return;
    }
    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });
    const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress;
    const hashedIp = hashIp(clientIp);
    if (ipBans.has(hashedIp) && ipBans.get(hashedIp).expiry > Date.now()) {
      ws.send(JSON.stringify({ type: 'error', message: 'IP temporarily banned due to excessive failures. Try again later.' }));
      return;
    }
    let clientId, code, username;
    let isAdmin = false;
    ws.on('message', async (message) => {
      if (!restrictRate(ws)) {
        ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
        return;
      }
      let data;
      try {
        data = JSON.parse(message);
        const loggedData = { ...data };
        if (loggedData.secret) {
          loggedData.secret = '[REDACTED]';
        }
        console.log('Received:', loggedData);
        const validation = validateMessage(data);
        if (!validation.valid) {
          ws.send(JSON.stringify({ type: 'error', message: validation.error }));
          incrementFailure(clientIp);
          return;
        }
        const skipEscapeFields = [
          data.type === 'public-key' && 'publicKey',
          data.type === 'encrypted-room-key' && 'publicKey',
          data.type === 'encrypted-room-key' && 'encryptedKey',
          data.type === 'encrypted-room-key' && 'iv',
          data.type === 'new-room-key' && 'encrypted',
          data.type === 'new-room-key' && 'iv',
          data.type === 'new-room-key' && 'ephemPub',
          (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') && 'data',
          data.type === 'relay-message' && 'encryptedContent',
          (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') && 'encryptedData',
          data.type === 'relay-message' && 'iv',
          (data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') && 'iv'
        ];
        Object.keys(data).forEach(key => {
          if (typeof data[key] === 'string' && !skipEscapeFields.includes(key)) {
            data[key] = validator.escape(validator.trim(data[key]));
          }
        });
        if ((data.type === 'public-key' || data.type === 'encrypted-room-key') && data.publicKey) {
          if (!isValidBase64(data.publicKey) || data.publicKey.length < 128 || data.publicKey.length > 132) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format or length' }));
            incrementFailure(clientIp);
            return;
          }
        }
        if (data.type === 'get-stats' || data.type === 'get-features' || data.type === 'toggle-feature') {
          if (data.secret === ADMIN_SECRET) {
            isAdmin = true;
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
            return;
          }
        }
        if (!features.enableService && !isAdmin && data.type !== 'connect') {
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
            let decoded = jwt.verify(data.token, JWT_SECRET);
            if (decoded.clientId !== data.clientId) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
              return;
            }
            if (revokedTokens.has(data.token)) {
              ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
              return;
            }
          } catch (err) {
            if (fs.existsSync(previousSecretFile)) {
              const previousSecret = fs.readFileSync(previousSecretFile, 'utf8').trim();
              try {
                let decoded = jwt.verify(data.token, previousSecret);
                if (decoded.clientId !== data.clientId) {
                  ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
                  return;
                }
                if (revokedTokens.has(data.token)) {
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
          clientId = data.clientId || uuidv4();
          ws.clientId = clientId;
          logStats({ clientId, event: 'connect' });
          const accessToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '10m' });
          const refreshToken = jwt.sign({ clientId }, JWT_SECRET, { expiresIn: '1h' });
          clientTokens.set(clientId, { accessToken, refreshToken });
          ws.send(JSON.stringify({ type: 'connected', clientId, accessToken, refreshToken }));
          return;
        }
        if (data.type === 'refresh-token') {
          if (!data.refreshToken) {
            ws.send(JSON.stringify({ type: 'error', message: 'Missing refresh token' }));
            return;
          }
          try {
            const decoded = jwt.verify(data.refreshToken, JWT_SECRET);
            if (decoded.clientId !== data.clientId) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
              return;
            }
            if (revokedTokens.has(data.refreshToken)) {
              ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
              return;
            }
            const oldRefreshExpiry = decoded.exp * 1000;
            revokedTokens.set(data.refreshToken, oldRefreshExpiry);
            const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '10m' });
            const newRefreshToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '1h' });
            clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
            ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
          } catch (err) {
            if (fs.existsSync(previousSecretFile)) {
              const previousSecret = fs.readFileSync(previousSecretFile, 'utf8').trim();
              try {
                const decoded = jwt.verify(data.refreshToken, previousSecret);
                if (decoded.clientId !== data.clientId) {
                  ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
                  return;
                }
                if (revokedTokens.has(data.refreshToken)) {
                  ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
                  return;
                }
                const oldRefreshExpiry = decoded.exp * 1000;
                revokedTokens.set(data.refreshToken, oldRefreshExpiry);
                const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '10m' });
                const newRefreshToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '1h' });
                clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
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
          if (rooms.has(data.code)) {
            const room = rooms.get(data.code);
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
          if (rooms.has(data.code)) {
            const room = rooms.get(data.code);
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
          if (rooms.has(data.code)) {
            const room = rooms.get(data.code);
            const targetWs = room.clients.get(data.targetId)?.ws;
            if (targetWs && targetWs.readyState === WebSocket.OPEN) {
              targetWs.send(JSON.stringify({ type: 'new-room-key', encrypted: data.encrypted, iv: data.iv, ephemPub: data.ephemPub, targetId: data.targetId, clientId: data.clientId, code: data.code }));
              console.log(`Forwarded new-room-key from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Target client not found or offline', code: data.code }));
            }
          }
          return;
        }
        if (data.type === 'join') {
          if (!features.enableService) {
            ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.', code: data.code }));
            return;
          }
          if (!restrictIpRate(clientIp, 'join')) {
            ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (!restrictIpDaily(clientIp, 'join')) {
            ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          code = data.code;
          clientId = data.clientId;
          username = data.username;
          if (!validateUsername(username)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (!validateCode(code)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format: xxxx-xxxx-xxxx-xxxx.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          const roomTotpSecret = totpSecrets.get(code);
          if (roomTotpSecret && !data.totpCode) {
            ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
            return;
          }
          if (roomTotpSecret && data.totpCode) {
            const isValid = otplib.authenticator.check(data.totpCode, roomTotpSecret);
            if (!isValid) {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid TOTP code.', code: data.code }));
              incrementFailure(clientIp);
              return;
            }
          }
          if (!rooms.has(code)) {
            rooms.set(code, { initiator: clientId, clients: new Map(), maxClients: 2 });
            ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
            logStats({ clientId, username, code, event: 'init', totalClients: 1 });
          } else {
            const room = rooms.get(code);
            if (room.clients.size >= room.maxClients) {
              ws.send(JSON.stringify({ type: 'error', message: 'Chat room is full.', code: data.code }));
              incrementFailure(clientIp);
              return;
            }
            if (room.clients.has(clientId)) {
              if (room.clients.get(clientId).username === username) {
                const oldWs = room.clients.get(clientId).ws;
                setTimeout(() => {
                  oldWs.close();
                }, 1000);
                room.clients.delete(clientId);
                broadcast(code, {
                  type: 'client-disconnected',
                  clientId,
                  totalClients: room.clients.size,
                  isInitiator: clientId === room.initiator
                });
              } else {
                ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId.', code: data.code }));
                incrementFailure(clientIp);
                return;
              }
            } else if (Array.from(room.clients.values()).some(c => c.username === username)) {
              ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
              incrementFailure(clientIp);
              return;
            }
            if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
              ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
              incrementFailure(clientIp);
              return;
            }
            ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
            logStats({ clientId, username, code, event: 'join', totalClients: room.clients.size + 1 });
            if (room.clients.size > 0) {
              room.clients.forEach((_, existingClientId) => {
                if (existingClientId !== clientId) {
                  logStats({
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
          const room = rooms.get(code);
          room.clients.set(clientId, { ws, username });
          ws.code = code;
          ws.username = username;
          broadcast(code, { type: 'join-notify', clientId, username, code, totalClients: room.clients.size });
          return;
        }
        if (data.type === 'check-totp') {
          if (totpSecrets.has(data.code)) {
            ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          } else {
            ws.send(JSON.stringify({ type: 'totp-not-required', code: data.code }));
          }
          return;
        }
        if (data.type === 'set-max-clients') {
          if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
            const room = rooms.get(data.code);
            room.maxClients = Math.min(data.maxClients, 10);
            broadcast(data.code, { type: 'max-clients', maxClients: room.maxClients, totalClients: room.clients.size });
            logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients: room.clients.size });
          }
          return;
        }
        if (data.type === 'set-totp') {
          if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
            totpSecrets.set(data.code, data.secret);
            broadcast(data.code, { type: 'totp-enabled', code: data.code });
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
          }
          return;
        }
        if (data.type === 'offer' || data.type === 'answer' || data.type === 'candidate') {
          if (rooms.has(data.code)) {
            const room = rooms.get(data.code);
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
          if (!restrictIpRate(clientIp, 'submit-random')) {
            ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (data.code && !rooms.get(data.code)?.clients.size) {
            ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (rooms.get(data.code)?.initiator === data.clientId) {
            randomCodes.add(data.code);
            broadcastRandomCodes();
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
            incrementFailure(clientIp);
          }
          return;
        }
        if (data.type === 'get-random-codes') {
          ws.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
          return;
        }
        if (data.type === 'remove-random-code') {
          if (randomCodes.has(data.code)) {
            randomCodes.delete(data.code);
            broadcastRandomCodes();
            console.log(`Removed code ${data.code} from randomCodes`);
          }
          return;
        }
        if (data.type === 'relay-typing') {
          if (!rooms.has(data.code)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          const room = rooms.get(data.code);
          const senderId = data.clientId;
          if (!room.clients.has(senderId)) {
            ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          room.clients.forEach((client, clientId) => {
            if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
              client.ws.send(JSON.stringify({
                type: 'typing',
                username: data.username,
                clientId: senderId
              }));
            }
          });
          return;
        }
        if (data.type === 'relay-message' || data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file') {
          if (data.type === 'relay-image' && !features.enableImages) {
            ws.send(JSON.stringify({ type: 'error', message: 'Image messages are disabled.', code: data.code }));
            return;
          }
          if (data.type === 'relay-voice' && !features.enableVoice) {
            ws.send(JSON.stringify({ type: 'error', message: 'Voice messages are disabled.', code: data.code }));
            return;
          }
          const payloadField = data.type === 'relay-message' ? 'content' : 'data';
          const encryptedField = data.type === 'relay-message' ? 'encryptedContent' : 'encryptedData';
          let payload = data[payloadField] || data[encryptedField];
          if (payload && (typeof payload !== 'string' || (data.type !== 'relay-message' && !isValidBase64(payload)))) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid payload format.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (payload && payload.length > 9333333) {
            ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 5MB).', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (!rooms.has(data.code)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          const room = rooms.get(data.code);
          const senderId = data.clientId;
          if (!room.clients.has(senderId)) {
            ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
            incrementFailure(clientIp);
            return;
          }
          if (!processedMessageIds.has(data.code)) {
            processedMessageIds.set(data.code, new Map());
          }
          const messageSet = processedMessageIds.get(data.code);
          if (messageSet.has(data.messageId)) {
            console.warn(`Duplicate messageId ${data.messageId} in room ${data.code}, ignoring`);
            return;
          }
          messageSet.set(data.messageId, Date.now());
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
                index: data.index,
                clientId: senderId
              }));
              console.log(`Relayed ${data.type} from ${senderId} to ${clientId} in code ${data.code}`);
            }
          });
          console.log(`Relayed ${data.type} from ${senderId} in code ${data.code} to ${room.clients.size - 1} clients`);
          return;
        }
        if (data.type === 'get-stats') {
          if (data.secret === ADMIN_SECRET) {
            const now = new Date();
            const day = now.toISOString().slice(0, 10);
            let totalClients = 0;
            rooms.forEach(room => {
              totalClients += room.clients.size;
            });
            const weekly = computeAggregate(7);
            const monthly = computeAggregate(30);
            const yearly = computeAggregate(365);
            ws.send(JSON.stringify({
              type: 'stats',
              dailyUsers: dailyUsers.get(day)?.size || 0,
              dailyConnections: dailyConnections.get(day)?.size || 0,
              weeklyUsers: weekly.users,
              weeklyConnections: weekly.connections,
              monthlyUsers: monthly.users,
              monthlyConnections: monthly.connections,
              yearlyUsers: yearly.users,
              yearlyConnections: yearly.connections,
              allTimeUsers: allTimeUsers.size,
              activeRooms: rooms.size,
              totalClients: totalClients
            }));
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
          }
          return;
        }
        if (data.type === 'get-features') {
          if (data.secret === ADMIN_SECRET) {
            ws.send(JSON.stringify({ type: 'features', ...features }));
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
          }
          return;
        }
        if (data.type === 'toggle-feature') {
          if (data.secret === ADMIN_SECRET) {
            const featureKey = `enable${data.feature.charAt(0).toUpperCase() + data.feature.slice(1)}`;
            if (features.hasOwnProperty(featureKey)) {
              features[featureKey] = !features[featureKey];
              saveFeatures();
              const timestamp = new Date().toISOString();
              fs.appendFileSync(LOG_FILE, `${timestamp} - Admin toggled ${featureKey} to ${features[featureKey]} by client ${hashIp(clientIp)}\n`);
              ws.send(JSON.stringify({ type: 'feature-toggled', feature: data.feature, enabled: features[featureKey] }));
              wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                  client.send(JSON.stringify({ type: 'features-update', ...features }));
                  if (data.feature === 'service' && !features.enableService && !client.isAdmin) {
                    client.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
                    client.close();
                  }
                }
              });
              if (data.feature === 'service' && !features.enableService) {
                rooms.clear();
                randomCodes.clear();
                totpSecrets.clear();
                processedMessageIds.clear();
              }
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Invalid feature' }));
            }
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
      } catch (error) {
        console.error('Error processing message:', error);
        ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.', code: data?.code }));
        incrementFailure(clientIp);
      }
    });
    ws.on('close', () => {
      if (ws.clientId) {
        const tokens = clientTokens.get(ws.clientId);
        if (tokens) {
          try {
            const decodedAccess = jwt.verify(tokens.accessToken, JWT_SECRET, { ignoreExpiration: true });
            revokedTokens.set(tokens.accessToken, decodedAccess.exp * 1000);
            if (tokens.refreshToken) {
              const decodedRefresh = jwt.verify(tokens.refreshToken, JWT_SECRET, { ignoreExpiration: true });
              revokedTokens.set(tokens.refreshToken, decodedRefresh.exp * 1000);
            }
            clientTokens.delete(ws.clientId);
            console.log(`Revoked tokens for client ${ws.clientId} on disconnect`);
          } catch (err) {
            console.warn(`Failed to revoke tokens for client ${ws.clientId}: ${err.message}`);
          }
        }
      }
      if (ws.code && rooms.has(ws.code)) {
        const room = rooms.get(ws.code);
        const isInitiator = ws.clientId === room.initiator;
        room.clients.delete(ws.clientId);
        rateLimits.delete(ws.clientId);
        logStats({ clientId: ws.clientId, code: ws.code, event: 'close', totalClients: room.clients.size, isInitiator });
        if (room.clients.size === 0 || isInitiator) {
          rooms.delete(ws.code);
          randomCodes.delete(ws.code);
          totpSecrets.delete(ws.code);
          processedMessageIds.delete(ws.code);
          broadcast(ws.code, {
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
              broadcast(ws.code, {
                type: 'initiator-changed',
                newInitiator,
                totalClients: room.clients.size
              });
            }
          }
          broadcast(ws.code, {
            type: 'client-disconnected',
            clientId: ws.clientId,
            totalClients: room.clients.size,
            isInitiator
          });
        }
      }
    });
  });
};
