const jwt = require('jsonwebtoken');
const validator = require('validator');
const otplib = require('otplib');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');
const validation = require('./validation');
const statsLogger = require('./statsLogger');
const featuresManager = require('./features');

const rateLimits = new Map();
const ipRateLimits = new Map();
const ipDailyLimits = new Map();
const ipFailureCounts = new Map();
const ipBans = new Map();
const revokedTokens = new Map();
const clientTokens = new Map();

function localBroadcast(code, msg, localRooms, excludeClientId = null) {
  const room = localRooms.get(code);
  if (room) {
    room.myClients.forEach(clientId => {
      if (clientId !== excludeClientId) {
        const ws = localClients.get(clientId)?.ws;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify(msg));
        }
      }
    });
  }
}

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
    fs.appendFileSync(config.LOG_FILE, `${new Date().toISOString()} - Rate limit exceeded for client ${ws.clientId}: ${rateLimit.count}\n`);
    return false;
  }
  return true;
}

async function restrictIpRate(ip, action, redis) {
  const hashedIp = statsLogger.hashIp(ip);
  const key = `iprate:${hashedIp}:${action}`;
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, 60);
  }
  if (count > 5) {
    console.warn(`IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${count} in 60s`);
    fs.appendFileSync(config.LOG_FILE, `${new Date().toISOString()} - IP rate limit exceeded for ${action} from hashed IP ${hashedIp}: ${count}\n`);
    return false;
  }
  return true;
}

async function restrictIpDaily(ip, action, redis) {
  const hashedIp = statsLogger.hashIp(ip);
  const day = new Date().toISOString().slice(0, 10);
  const key = `ipdaily:${hashedIp}:${action}:${day}`;
  const count = await redis.incr(key);
  if (count > 100) {
    console.warn(`Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${count} in day ${day}`);
    fs.appendFileSync(config.LOG_FILE, `${new Date().toISOString()} - Daily IP limit exceeded for ${action} from hashed IP ${hashedIp}: ${count}\n`);
    return false;
  }
  return true;
}

async function incrementFailure(ip, redis, LOG_FILE) {
  const hashedIp = statsLogger.hashIp(ip);
  const failureKey = `ipfailure:${hashedIp}`;
  const count = await redis.incr(failureKey);
  if (count === 1) {
    await redis.expire(failureKey, 300);
  }
  if (count % 5 === 0) {
    console.warn(`High failure rate for hashed IP ${hashedIp}: ${count} failures`);
  }
  if (count >= 10) {
    const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];
    let banLevel = await redis.get(`banlevel:${hashedIp}`) || 0;
    banLevel = Math.min(parseInt(banLevel) + 1, 2);
    await redis.set(`banlevel:${hashedIp}`, banLevel, 'EX', 3600);
    const duration = banDurations[banLevel];
    const expiry = Date.now() + duration;
    await redis.set(`ban:${hashedIp}`, expiry);
    const timestamp = new Date().toISOString();
    const banLogEntry = `${timestamp} - Hashed IP Banned: ${hashedIp}, Duration: ${duration / 60000} minutes, Ban Level: ${banLevel}\n`;
    fs.appendFileSync(LOG_FILE, banLogEntry);
    console.warn(`Hashed IP ${hashedIp} banned until ${new Date(expiry).toISOString()} at ban level ${banLevel} (${duration / 60000} minutes)`);
    await redis.del(failureKey);
  }
}

function handleConnection(ws, req, features, localClients, localRooms, redis, pub, instanceId, validation, statsLogger, config) {
  const origin = req.headers.origin;
  if (!config.ALLOWED_ORIGINS.includes(origin)) {
    console.warn(`Rejected connection from invalid origin: ${origin}`);
    ws.close(1008, 'Invalid origin');
    return;
  }
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress;
  const hashedIp = statsLogger.hashIp(clientIp);

  (async () => {
    try {
      const banTime = await redis.get(`ban:${hashedIp}`);
      if (banTime && parseInt(banTime) > Date.now()) {
        ws.send(JSON.stringify({ type: 'error', message: 'IP temporarily banned due to excessive failures. Try again later.' }));
        ws.close();
        return;
      }
    } catch (err) {
      console.error('Error checking ban:', err);
    }
  })();

  let clientId, code, username, publicKey;
  let isAdmin = false;

  ws.on('message', async (message) => {
    if (!restrictRate(ws)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded, please slow down.' }));
      return;
    }
    let data;
    try {
      data = JSON.parse(message);
    } catch (err) {
      console.error('Invalid JSON in message:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format.' }));
      await incrementFailure(clientIp, redis, config.LOG_FILE);
      return;
    }
    try {
      const val = validation.validateMessage(data);
      if (!val.valid) {
        ws.send(JSON.stringify({ type: 'error', message: val.error }));
        await incrementFailure(clientIp, redis, config.LOG_FILE);
        return;
      }
      Object.keys(data).forEach(key => {
        if (typeof data[key] === 'string' && !(data.type === 'public-key' && key === 'publicKey')) {
          data[key] = validator.escape(validator.trim(data[key]));
        }
      });
      if (data.type === 'public-key' || data.type === 'public-key-response') {
        if (!validation.isValidBase64(data.publicKey)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format' }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
      }
      if (data.type === 'get-stats' || data.type === 'get-features' || data.type === 'toggle-feature') {
        if (data.secret === config.ADMIN_SECRET) {
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
        let decoded;
        try {
          decoded = jwt.verify(data.token, config.JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
            return;
          }
          const revoked = await redis.get(`revoked:${data.token}`);
          if (revoked) {
            ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
            return;
          }
        } catch (err) {
          if (fs.existsSync(config.previousSecretFile)) {
            const previousSecret = fs.readFileSync(config.previousSecretFile, 'utf8').trim();
            try {
              decoded = jwt.verify(data.token, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
                return;
              }
              const revoked = await redis.get(`revoked:${data.token}`);
              if (revoked) {
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
        localClients.set(clientId, { ws, username: '', code: '' });
        statsLogger.logStats({ clientId, event: 'connect' }, redis, config.LOG_FILE);
        const accessToken = jwt.sign({ clientId }, config.JWT_SECRET, { expiresIn: '10m' });
        const refreshToken = jwt.sign({ clientId }, config.JWT_SECRET, { expiresIn: '1h' });
        clientTokens.set(clientId, { accessToken, refreshToken });
        ws.send(JSON.stringify({ type: 'connected', clientId, accessToken, refreshToken }));
        return;
      }
      if (data.type === 'refresh-token') {
        if (!data.refreshToken) {
          ws.send(JSON.stringify({ type: 'error', message: 'Missing refresh token' }));
          return;
        }
        let decoded;
        try {
          decoded = jwt.verify(data.refreshToken, config.JWT_SECRET);
          if (decoded.clientId !== data.clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
            return;
          }
          const revoked = await redis.get(`revoked:${data.refreshToken}`);
          if (revoked) {
            ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
            return;
          }
          const oldRefreshExpiry = decoded.exp * 1000 - Date.now();
          await redis.set(`revoked:${data.refreshToken}`, 1, 'PX', oldRefreshExpiry);
          const newAccessToken = jwt.sign({ clientId: data.clientId }, config.JWT_SECRET, { expiresIn: '10m' });
          const newRefreshToken = jwt.sign({ clientId: data.clientId }, config.JWT_SECRET, { expiresIn: '1h' });
          clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
          ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
        } catch (err) {
          if (fs.existsSync(config.previousSecretFile)) {
            const previousSecret = fs.readFileSync(config.previousSecretFile, 'utf8').trim();
            try {
              decoded = jwt.verify(data.refreshToken, previousSecret);
              if (decoded.clientId !== data.clientId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid refresh token: clientId mismatch' }));
                return;
              }
              const revoked = await redis.get(`revoked:${data.refreshToken}`);
              if (revoked) {
                ws.send(JSON.stringify({ type: 'error', message: 'Refresh token revoked' }));
                return;
              }
              const oldRefreshExpiry = decoded.exp * 1000 - Date.now();
              await redis.set(`revoked:${data.refreshToken}`, 1, 'PX', oldRefreshExpiry);
              const newAccessToken = jwt.sign({ clientId: data.clientId }, config.JWT_SECRET, { expiresIn: '10m' });
              const newRefreshToken = jwt.sign({ clientId: data.clientId }, config.JWT_SECRET, { expiresIn: '1h' });
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
      if (data.type === 'public-key' || data.type === 'public-key-response') {
        const targetInstance = await redis.hget(`client:${data.clientId}`, 'instance');
        if (targetInstance === instanceId) {
          // Forward local if needed
        } else {
          pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
        }
        return;
      }
      if (data.type === 'request-public-key') {
        const targetInstance = await redis.hget(`client:${data.targetId}`, 'instance');
        if (targetInstance === instanceId) {
          const targetWs = localClients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'request-public-key', targetId: data.clientId, code: data.code, clientId: data.targetId }));
          }
        } else {
          pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
        }
        return;
      }
      if (data.type === 'encrypted-room-key') {
        const targetInstance = await redis.hget(`client:${data.targetId}`, 'instance');
        if (targetInstance === instanceId) {
          const targetWs = localClients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, publicKey: data.publicKey, clientId: data.clientId, code: data.code }));
          }
        } else {
          pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
        }
        return;
      }
      if (data.type === 'new-room-key') {
        const targetInstance = await redis.hget(`client:${data.targetId}`, 'instance');
        if (targetInstance === instanceId) {
          const targetWs = localClients.get(data.targetId)?.ws;
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(JSON.stringify({ type: 'new-room-key', encrypted: data.encrypted, iv: data.iv, targetId: data.targetId, clientId: data.clientId, code: data.code }));
          }
        } else {
          pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
        }
        return;
      }
      if (data.type === 'join') {
        if (!features.enableService) {
          ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.', code: data.code }));
          return;
        }
        if (!await restrictIpRate(clientIp, 'join', redis)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.', code: data.code }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
        if (!await restrictIpDaily(clientIp, 'join', redis)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.', code: data.code }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
        code = data.code;
        clientId = data.clientId;
        username = data.username;
        publicKey = data.publicKey;
        if (!validation.validateUsername(username)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid username: 1-16 alphanumeric characters.', code: data.code }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
        if (!validation.validateCode(code)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format: xxxx-xxxx-xxxx-xxxx.', code: data.code }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
        const totpKey = `totp:${code}`;
        const roomTotpSecret = await redis.get(totpKey);
        if (roomTotpSecret && !data.totpCode) {
          ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          return;
        }
        if (roomTotpSecret && data.totpCode) {
          const isValid = otplib.authenticator.check(data.totpCode, roomTotpSecret);
          if (!isValid) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid TOTP code.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
            return;
          }
        }
        const roomKey = `room:${code}`;
        let roomStr = await redis.get(roomKey);
        let room;
        let isNewRoom = false;
        if (!roomStr) {
          isNewRoom = true;
          room = { initiator: clientId, maxClients: 2 };
          await redis.set(roomKey, JSON.stringify(room));
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: config.TURN_USERNAME, turnCredential: config.TURN_CREDENTIAL, features }));
          statsLogger.logStats({ clientId, username, code, event: 'init', totalClients: 1 }, redis, config.LOG_FILE);
        } else {
          room = JSON.parse(roomStr);
          const clientsKey = `room_clients:${code}`;
          const currentCount = await redis.scard(clientsKey);
          if (currentCount >= room.maxClients) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room is full.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
            return;
          }
          const members = await redis.smembers(clientsKey);
          const clientData = await redis.hgetall(`client:${clientId}`);
          if (members.includes(clientId)) {
            if (clientData.username === username) {
              // Reconnect, update instance
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId.', code: data.code }));
              await incrementFailure(clientIp, redis, config.LOG_FILE);
              return;
            }
          } else {
            let usernameTaken = false;
            for (const id of members) {
              const memberUsername = await redis.hget(`client:${id}`, 'username');
              if (memberUsername === username) {
                usernameTaken = true;
                break;
              }
            }
            if (usernameTaken) {
              ws.send(JSON.stringify({ type: 'error', message: 'Username already taken in this room.', code: data.code }));
              await incrementFailure(clientIp, redis, config.LOG_FILE);
              return;
            }
          }
          const initiatorInstance = await redis.hget(`client:${room.initiator}`, 'instance');
          if (!initiatorInstance && room.initiator !== clientId) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room initiator is offline.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
            return;
          }
          ws.send(JSON.stringify({ type: 'init', clientId, maxClients: room.maxClients, isInitiator: false, turnUsername: config.TURN_USERNAME, turnCredential: config.TURN_CREDENTIAL, features }));
          statsLogger.logStats({ clientId, username, code, event: 'join', totalClients: currentCount + 1 }, redis, config.LOG_FILE);
          if (currentCount > 0) {
            for (const existing of members) {
              if (existing !== clientId) {
                statsLogger.logStats({ clientId, targetId: existing, code, event: 'webrtc-connection', totalClients: currentCount + 1 }, redis, config.LOG_FILE);
              }
            }
          }
        }
        const clientsKey = `room_clients:${code}`;
        await redis.sadd(clientsKey, clientId);
        await redis.hset(`client:${clientId}`, 'instance', instanceId, 'username', username, 'publicKey', publicKey || '');
        localClients.get(clientId).username = username;
        localClients.get(clientId).code = code;
        if (!localRooms.has(code)) {
          localRooms.set(code, { totalClients: 0, myClients: new Set(), initiator: room.initiator, maxClients: room.maxClients });
        }
        localRooms.get(code).myClients.add(clientId);
        const total = await redis.scard(clientsKey);
        localRooms.get(code).totalClients = total;
        pub.publish('signaling', JSON.stringify({ type: 'join', code, clientId, username, totalClients: total, publicKey }));
        if (total > 1 && await redis.sismember('randomCodes', code)) {
          await redis.srem('randomCodes', code);
        }
      }
      if (data.type === 'check-totp') {
        const totpKey = `totp:${data.code}`;
        try {
          if (await redis.exists(totpKey)) {
            ws.send(JSON.stringify({ type: 'totp-required', code: data.code }));
          } else {
            ws.send(JSON.stringify({ type: 'totp-not-required', code: data.code }));
          }
        } catch (err) {
          console.error('Error in check-totp:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error in TOTP check.' }));
        }
        return;
      }
      if (data.type === 'set-max-clients') {
        const roomKey = `room:${data.code}`;
        try {
          const roomStr = await redis.get(roomKey);
          if (roomStr) {
            const room = JSON.parse(roomStr);
            if (data.clientId === room.initiator) {
              room.maxClients = Math.min(data.maxClients, 10);
              await redis.set(roomKey, JSON.stringify(room));
              const total = await redis.scard(`room_clients:${data.code}`);
              pub.publish('signaling', JSON.stringify({ type: 'max-clients', code: data.code, maxClients: room.maxClients, totalClients: total }));
              statsLogger.logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients: total }, redis, config.LOG_FILE);
            }
          }
        } catch (err) {
          console.error('Error in set-max-clients:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error setting max clients.' }));
        }
      }
      if (data.type === 'set-totp') {
        const roomKey = `room:${data.code}`;
        try {
          const roomStr = await redis.get(roomKey);
          if (roomStr) {
            const room = JSON.parse(roomStr);
            if (data.clientId === room.initiator) {
              await redis.set(`totp:${data.code}`, data.secret);
              pub.publish('signaling', JSON.stringify({ type: 'totp-enabled', code: data.code }));
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can set TOTP secret.', code: data.code }));
            }
          }
        } catch (err) {
          console.error('Error in set-totp:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error setting TOTP.' }));
        }
      }
      if (data.type === 'offer' || data.type === 'answer' || data.type === 'candidate') {
        try {
          const targetInstance = await redis.hget(`client:${data.targetId}`, 'instance');
          if (targetInstance) {
            if (targetInstance === instanceId) {
              const target = localClients.get(data.targetId);
              if (target && target.ws.readyState === WebSocket.OPEN) {
                console.log(`Forwarding ${data.type} from ${data.clientId} to ${data.targetId} for code: ${data.code}`);
                target.ws.send(JSON.stringify({ ...data, clientId: data.clientId }));
              } else {
                console.warn(`Target ${data.targetId} not found or not open in room ${data.code}`);
              }
            } else {
              pub.publish(`signal:${targetInstance}`, JSON.stringify(data));
            }
          }
        } catch (err) {
          console.error(`Error forwarding ${data.type}:`, err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error in signaling.' }));
        }
      }
      if (data.type === 'submit-random') {
        if (!await restrictIpRate(clientIp, 'submit-random', redis)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.', code: data.code }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
        const roomKey = `room:${data.code}`;
        try {
          const roomStr = await redis.get(roomKey);
          if (roomStr) {
            const room = JSON.parse(roomStr);
            if (room.initiator === data.clientId) {
              await redis.sadd('randomCodes', data.code);
              ws.send(JSON.stringify({ type: 'random-submitted', code: data.code }));
            } else {
              ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board.', code: data.code }));
              await incrementFailure(clientIp, redis, config.LOG_FILE);
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
          }
        } catch (err) {
          console.error('Error in submit-random:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error submitting to random board.' }));
        }
      }
      if (data.type === 'get-random-codes') {
        try {
          const codes = await redis.smembers('randomCodes');
          ws.send(JSON.stringify({ type: 'random-codes', codes }));
        } catch (err) {
          console.error('Error getting random codes:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error fetching random codes.' }));
        }
      }
      if (data.type === 'remove-random-code') {
        try {
          await redis.srem('randomCodes', data.code);
          console.log(`Removed code ${data.code} from randomCodes`);
        } catch (err) {
          console.error('Error removing random code:', err);
        }
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
        const payload = data.type === 'relay-message' ? data.encryptedContent : data.encryptedData;
        if (payload && payload.length > 9333333) {
          ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 5MB).', code: data.code }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
        if (payload && !validation.isValidBase64(payload)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid base64 format in payload.', code: data.code }));
          await incrementFailure(clientIp, redis, config.LOG_FILE);
          return;
        }
        const roomKey = `room:${data.code}`;
        try {
          if (!await redis.exists(roomKey)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
            return;
          }
        } catch (err) {
          console.error('Error checking room existence:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error checking room.' }));
          return;
        }
        const senderId = data.clientId;
        const clientsKey = `room_clients:${data.code}`;
        try {
          if (!await redis.sismember(clientsKey, senderId)) {
            ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
            return;
          }
        } catch (err) {
          console.error('Error checking membership:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error checking membership.' }));
          return;
        }
        pub.publish('signaling', JSON.stringify(data));
        console.log(`Relayed ${data.type} from ${senderId} in code ${data.code} (content not logged for privacy)`);
      }
      if (data.type === 'relay-chunk') {
        const roomKey = `room:${data.code}`;
        try {
          if (!await redis.exists(roomKey)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Chat room not found.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
            return;
          }
          if (!await redis.sismember(`room_clients:${data.code}`, data.clientId)) {
            ws.send(JSON.stringify({ type: 'error', message: 'You are not in this chat room.', code: data.code }));
            await incrementFailure(clientIp, redis, config.LOG_FILE);
            return;
          }
          pub.publish('signaling', JSON.stringify(data));
          console.log(`Relayed chunk ${data.index}/${data.total} for message ${data.messageId} from ${data.clientId} in code ${data.code}`);
        } catch (err) {
          console.error('Error processing relay-chunk:', err);
          ws.send(JSON.stringify({ type: 'error', message: 'Server error processing chunk.' }));
          return;
        }
      }
      if (data.type === 'get-stats') {
        if (data.secret === config.ADMIN_SECRET) {
          const now = new Date();
          const day = now.toISOString().slice(0, 10);
          try {
            const roomKeys = await redis.keys('room:*');
            let activeRooms = roomKeys.length;
            let totalClients = 0;
            for (const key of roomKeys) {
              totalClients += await redis.scard(key.replace('room', 'room_clients'));
            }
            const weekly = await statsLogger.computeAggregate(7, redis);
            const monthly = await statsLogger.computeAggregate(30, redis);
            const yearly = await statsLogger.computeAggregate(365, redis);
            const allTimeUsersCount = await redis.pfcount('allTimeUsers');
            ws.send(JSON.stringify({ type: 'stats', dailyUsers: await redis.scard(`dailyUsers:${day}`) || 0, dailyConnections: await redis.scard(`dailyConnections:${day}`) || 0, weeklyUsers: weekly.users, weeklyConnections: weekly.connections, monthlyUsers: monthly.users, monthlyConnections: monthly.connections, yearlyUsers: yearly.users, yearlyConnections: yearly.connections, allTimeUsers: allTimeUsersCount, activeRooms, totalClients }));
          } catch (err) {
            console.error('Error fetching stats:', err);
            ws.send(JSON.stringify({ type: 'error', message: 'Server error fetching stats.' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
      }
      if (data.type === 'get-features') {
        if (data.secret === config.ADMIN_SECRET) {
          ws.send(JSON.stringify({ type: 'features', ...features }));
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
      }
      if (data.type === 'toggle-feature') {
        if (data.secret === config.ADMIN_SECRET) {
          const featureKey = `enable${data.feature.charAt(0).toUpperCase() + data.feature.slice(1)}`;
          if (features.hasOwnProperty(featureKey)) {
            features[featureKey] = !features[featureKey];
            try {
              await redis.set('features', JSON.stringify(features));
              featuresManager.saveFeatures(features);
              const timestamp = new Date().toISOString();
              fs.appendFileSync(config.LOG_FILE, `${timestamp} - Admin toggled ${featureKey} to ${features[featureKey]} by client ${statsLogger.hashIp(clientIp)}\n`);
              ws.send(JSON.stringify({ type: 'feature-toggled', feature: data.feature, enabled: features[featureKey] }));
              pub.publish('signaling', JSON.stringify({ type: 'features-update', ...features }));
              if (data.feature === 'service' && !features.enableService) {
                const roomKeys = await redis.keys('room:*');
                for (const key of roomKeys) {
                  await redis.del(key);
                  await redis.del(key.replace('room', 'room_clients'));
                  await redis.del(key.replace('room', 'totp'));
                }
                const clientKeys = await redis.keys('client:*');
                for (const key of clientKeys) {
                  await redis.del(key);
                }
                await redis.del('randomCodes');
              }
            } catch (err) {
              console.error('Error toggling feature:', err);
              ws.send(JSON.stringify({ type: 'error', message: 'Server error toggling feature.' }));
            }
          } else {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid feature' }));
          }
        } else {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
        }
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
      ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.', code: data ? data.code : 'unknown' }));
      await incrementFailure(clientIp, redis, config.LOG_FILE);
    }
  });

  ws.on('close', async () => {
    try {
      if (ws.clientId) {
        const tokens = clientTokens.get(ws.clientId);
        if (tokens) {
          try {
            const decodedAccess = jwt.verify(tokens.accessToken, config.JWT_SECRET, { ignoreExpiration: true });
            await redis.set(`revoked:${tokens.accessToken}`, 1, 'PX', decodedAccess.exp * 1000 - Date.now());
            if (tokens.refreshToken) {
              const decodedRefresh = jwt.verify(tokens.refreshToken, config.JWT_SECRET, { ignoreExpiration: true });
              await redis.set(`revoked:${tokens.refreshToken}`, 1, 'PX', decodedRefresh.exp * 1000 - Date.now());
            }
            clientTokens.delete(ws.clientId);
            console.log(`Revoked tokens for client ${ws.clientId} on disconnect`);
          } catch (err) {
            console.warn(`Failed to revoke tokens for client ${ws.clientId}: ${err.message}`);
          }
        }
        const code = localClients.has(ws.clientId) ? localClients.get(ws.clientId).code : null;
        if (code) {
          const clientsKey = `room_clients:${code}`;
          await redis.srem(clientsKey, ws.clientId);
          await redis.del(`client:${ws.clientId}`);
          const remaining = await redis.scard(clientsKey);
          let isInitiatorDisconnect = false;
          const roomKey = `room:${code}`;
          const roomStr = await redis.get(roomKey);
          if (roomStr) {
            const room = JSON.parse(roomStr);
            if (room.initiator === ws.clientId) {
              isInitiatorDisconnect = true;
              const members = await redis.smembers(clientsKey);
              if (members.length > 0) {
                room.initiator = members[0];
                await redis.set(roomKey, JSON.stringify(room));
                pub.publish('signaling', JSON.stringify({ type: 'initiator-changed', code, newInitiator: room.initiator, totalClients: remaining }));
              } else {
                await redis.del(roomKey);
                await redis.del(`totp:${code}`);
                await redis.srem('randomCodes', code);
              }
            }
          }
          pub.publish('signaling', JSON.stringify({ type: 'disconnect', code, clientId: ws.clientId, totalClients: remaining, isInitiator: isInitiatorDisconnect }));
          if (localRooms.has(code)) {
            localRooms.get(code).myClients.delete(ws.clientId);
            localRooms.get(code).totalClients = remaining;
            if (localRooms.get(code).myClients.size === 0) {
              localRooms.delete(code);
            }
          }
        }
        if (ws.clientId) localClients.delete(ws.clientId);
      }
    } catch (err) {
      console.error('Error in ws close handler:', err);
    }
  });
}

module.exports = { localBroadcast, restrictRate, restrictIpRate, restrictIpDaily, incrementFailure, handleConnection };
