const jwt = require('jsonwebtoken');
const validator = require('validator');
const otplib = require('otplib');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

function pingClients(wss) {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}

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

function handlePubSub(channel, event, localRooms, localClients, wss, instanceId, features) {
  try {
    const data = JSON.parse(event);
    if (channel === 'signaling') {
      if (data.type === 'join') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).totalClients = data.totalClients;
          localBroadcast(data.code, { type: 'join-notify', clientId: data.clientId, username: data.username, code: data.code, totalClients: data.totalClients, publicKey: data.publicKey }, localRooms);
        }
      } else if (data.type === 'disconnect') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).totalClients = data.totalClients;
          localBroadcast(data.code, { type: 'client-disconnected', clientId: data.clientId, totalClients: data.totalClients, isInitiator: data.isInitiator }, localRooms);
        }
      } else if (data.type === 'max-clients') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).maxClients = data.maxClients;
          localBroadcast(data.code, { type: 'max-clients', maxClients: data.maxClients, totalClients: data.totalClients }, localRooms);
        }
      } else if (data.type === 'totp-enabled') {
        if (localRooms.has(data.code)) {
          localBroadcast(data.code, { type: 'totp-enabled', code: data.code }, localRooms);
        }
      } else if (data.type === 'initiator-changed') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).initiator = data.newInitiator;
          localBroadcast(data.code, { type: 'initiator-changed', newInitiator: data.newInitiator, totalClients: data.totalClients }, localRooms);
        }
      } else if (data.type === 'features-update') {
        features = {
          enableService: data.enableService,
          enableImages: data.enableImages,
          enableVoice: data.enableVoice,
          enableVoiceCalls: data.enableVoiceCalls,
          enableAudioToggle: data.enableAudioToggle,
          enableGrokBot: data.enableGrokBot
        };
        wss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'features-update', ...features }));
          }
        });
        if (!features.enableService) {
          localRooms.clear();
          localClients.clear();
          wss.clients.forEach(ws => ws.close());
        }
      } else if (data.type === 'relay-message' || data.type === 'relay-image' || data.type === 'relay-voice' || data.type === 'relay-file' || data.type === 'relay-chunk') {
        if (localRooms.has(data.code)) {
          localBroadcast(data.code, {
            type: data.type.replace('relay-', ''),
            messageId: data.messageId,
            username: data.username,
            encryptedContent: data.encryptedContent,
            encryptedData: data.encryptedData,
            iv: data.iv,
            salt: data.salt,
            signature: data.signature,
            chunk: data.chunk,
            index: data.index,
            total: data.total,
            relayType: data.relayType
          }, localRooms, data.clientId);
        }
      } else if (data.type === 'request-public-key' || data.type === 'public-key-response') {
        const targetWs = localClients.get(data.targetId)?.ws;
        if (targetWs && targetWs.readyState === WebSocket.OPEN) {
          targetWs.send(JSON.stringify(data));
        }
      }
    } else if (channel === `signal:${instanceId}`) {
      const targetWs = localClients.get(data.targetId)?.ws;
      if (targetWs && targetWs.readyState === WebSocket.OPEN) {
        targetWs.send(JSON.stringify({ ...data, clientId: data.clientId }));
      }
    }
  } catch (error) {
    console.error('Error handling pub/sub event:', error);
  }
}

function restrictRate(ws) {
  // Implement rate limiting logic here (extracted from original)
  // ...
}

async function restrictIpRate(ip, action, redis, hashIp) {
  // Implement IP rate limiting
  // ...
}

async function restrictIpDaily(ip, action, redis, hashIp) {
  // Implement daily IP limiting
  // ...
}

async function incrementFailure(ip, redis, hashIp, LOG_FILE) {
  // Implement failure count and ban logic
  // ...
}

function handleConnection(ws, req, { features, localClients, localRooms, redis, pub, instanceId, validation, statsLogger, featuresManager, config }) {
  const origin = req.headers.origin;
  if (!config.ALLOWED_ORIGINS.includes(origin)) {
    console.warn(`Rejected connection from invalid origin: ${origin}`);
    ws.close(1008, 'Invalid origin');
    return;
  }
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress;
  const hashedIp = statsLogger.hashIp(clientIp, config.IP_SALT);

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
    // Rate limiting, parsing, validation, and message handling logic here
    // Use validation.validateMessage, etc.
    // Call statsLogger.logStats where needed
    // Use featuresManager.saveFeatures for toggles
    // ...
  });

  ws.on('close', async () => {
    // Close handler logic
    // ...
  });
}

module.exports = { pingClients, localBroadcast, handlePubSub, handleConnection };
