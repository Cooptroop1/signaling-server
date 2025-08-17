
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const https = require('https');
const Redis = require('ioredis');

const config = require('./config');
const httpHandler = require('./httpHandler');
const validation = require('./validation');
const redisUtils = require('./redisUtils');
const statsLogger = require('./statsLogger');
const featuresManager = require('./features');
const wsHandlers = require('./wsHandlers');

// Global error handlers to prevent crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

// Server setup
let server;
if (process.env.NODE_ENV === 'production' || !fs.existsSync(config.CERT_KEY_PATH) || !fs.existsSync(config.CERT_PATH)) {
  server = http.createServer();
  console.log('Using HTTP server (production or missing certificates)');
} else {
  server = https.createServer({
    key: fs.readFileSync(config.CERT_KEY_PATH),
    cert: fs.readFileSync(config.CERT_PATH)
  });
  console.log('Using HTTPS server for local development');
}

// Attach HTTP handler
server.on('request', httpHandler.handleRequest);

// WebSocket server
const wss = new WebSocket.Server({ server });

// Redis clients
const redis = new Redis(config.REDIS_URL, config.redisOptions);
const pub = new Redis(config.REDIS_URL, config.redisOptions);
const sub = new Redis(config.REDIS_URL, config.redisOptions);
const instanceId = uuidv4();

[redis, pub, sub].forEach(client => {
  client.on('error', (err) => console.error('Redis Client Error:', err));
  client.on('reconnecting', () => console.log('Redis client reconnecting...'));
  client.on('ready', () => console.log('Redis client ready'));
});

sub.subscribe('signaling', `signal:${instanceId}`);

// Initialize features from Redis
(async () => {
  try {
    let featuresStr = await redis.get('features');
    if (featuresStr) {
      const parsed = JSON.parse(featuresStr);
      features = {
        enableService: parsed.enableService || true,
        enableImages: parsed.enableImages || true,
        enableVoice: parsed.enableVoice || true,
        enableVoiceCalls: parsed.enableVoiceCalls || true,
        enableAudioToggle: parsed.enableAudioToggle || true,
        enableGrokBot: parsed.enableGrokBot || true
      };
    } else {
      features = {
        enableService: true,
        enableImages: true,
        enableVoice: true,
        enableVoiceCalls: true,
        enableAudioToggle: true,
        enableGrokBot: true
      };
      await redis.set('features', JSON.stringify(features));
    }
    console.log('Loaded features:', features);
  } catch (err) {
    console.error('Error loading features from Redis:', err);
  }
})();

// Local state
const localClients = new Map();
const localRooms = new Map();

// Periodic tasks
setInterval(async () => await redisUtils.cleanupRandomCodes(redis), 3600000);
const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 50000);
setInterval(async () => await redisUtils.cleanupRevokedTokens(redis), 3600000);

// Pub/sub handler
sub.on('message', (channel, event) => {
  try {
    const data = JSON.parse(event);
    if (channel === 'signaling') {
      if (data.type === 'join') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).totalClients = data.totalClients;
          wsHandlers.localBroadcast(data.code, { type: 'join-notify', clientId: data.clientId, username: data.username, code: data.code, totalClients: data.totalClients, publicKey: data.publicKey }, localRooms);
        }
      } else if (data.type === 'disconnect') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).totalClients = data.totalClients;
          wsHandlers.localBroadcast(data.code, { type: 'client-disconnected', clientId: data.clientId, totalClients: data.totalClients, isInitiator: data.isInitiator }, localRooms);
        }
      } else if (data.type === 'max-clients') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).maxClients = data.maxClients;
          wsHandlers.localBroadcast(data.code, { type: 'max-clients', maxClients: data.maxClients, totalClients: data.totalClients }, localRooms);
        }
      } else if (data.type === 'totp-enabled') {
        if (localRooms.has(data.code)) {
          wsHandlers.localBroadcast(data.code, { type: 'totp-enabled', code: data.code }, localRooms);
        }
      } else if (data.type === 'initiator-changed') {
        if (localRooms.has(data.code)) {
          localRooms.get(data.code).initiator = data.newInitiator;
          wsHandlers.localBroadcast(data.code, { type: 'initiator-changed', newInitiator: data.newInitiator, totalClients: data.totalClients }, localRooms);
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
          wsHandlers.localBroadcast(data.code, {
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
});

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  wsHandlers.handleConnection(ws, req, features, localClients, localRooms, redis, pub, instanceId, validation, statsLogger, config, wss);
});

// Start server
server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
