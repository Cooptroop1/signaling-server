const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const Redis = require('ioredis');
const { v4: uuidv4 } = require('uuid');

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
let features = {};
(async () => {
  features = await featuresManager.loadFeatures(redis);
})();

// Local state
const localClients = new Map();
const localRooms = new Map();

// Periodic tasks
setInterval(() => redisUtils.cleanupRandomCodes(redis), 3600000);
const pingInterval = setInterval(() => wsHandlers.pingClients(wss), 50000);
setInterval(() => redisUtils.cleanupRevokedTokens(redis), 3600000);

// Pub/sub handler
sub.on('message', (channel, event) => wsHandlers.handlePubSub(channel, event, localRooms, localClients, wss, instanceId, features));

// WebSocket connection handler
wss.on('connection', (ws, req) => wsHandlers.handleConnection(ws, req, {
  features,
  localClients,
  localRooms,
  redis,
  pub,
  instanceId,
  validation,
  statsLogger,
  featuresManager,
  config
}));

// Start server
server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
