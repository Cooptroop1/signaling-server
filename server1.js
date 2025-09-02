const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const otplib = require('otplib');
const UAParser = require('ua-parser-js');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

async function validatePassword(input, hash) {
  return bcrypt.compare(input, hash);
}

const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

dbPool.connect((err) => {
  if (err) {
    console.error('DB connection error:', err.message, err.stack);
  } else {
    console.log('Connected to DB successfully');
  }
});

setInterval(async () => {
  try {
    await dbPool.query('DELETE FROM offline_messages WHERE created_at < NOW() - INTERVAL \'24 hours\'');
    console.log('Cleaned up expired offline messages');
  } catch (err) {
    console.error('Error cleaning up offline messages:', err.message, err.stack);
  }
}, 24 * 60 * 60 * 1000);

const CERT_KEY_PATH = 'path/to/your/private-key.pem';
const CERT_PATH = 'path/to/your/fullchain.pem';

let server;
if (process.env.NODE_ENV === 'production' || !fs.existsSync(CERT_KEY_PATH) || !fs.existsSync(CERT_PATH)) {
  server = http.createServer();
  console.log('Using HTTP server (production or missing certificates)');
} else {
  server = https.createServer({
    key: fs.readFileSync(CERT_KEY_PATH),
    cert: fs.readFileSync(CERT_PATH)
  });
  console.log('Using HTTPS server for local development');
}

server.on('request', (req, res) => {
  const proto = req.headers['x-forwarded-proto'];
  if (proto && proto !== 'https') {
    res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
    res.end();
    return;
  }
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  const fullUrl = new URL(req.url, `http://${req.headers.host}`);
  let filePath = path.join(__dirname, fullUrl.pathname === '/' ? 'index.html' : fullUrl.pathname);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    let contentType = 'text/plain';
    if (filePath.endsWith('.html')) {
      contentType = 'text/html';
      const nonce = crypto.randomBytes(16).toString('base64');
      let updatedCSP = "default-src 'self'; " +
        `script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net 'nonce-${nonce}'; ` +
        `style-src 'self' https://cdn.jsdelivr.net 'nonce-${nonce}'; ` +
        "img-src 'self' data: blob: https://raw.githubusercontent.com https://cdnjs.cloudflare.com; " +
        "media-src 'self' blob: data:; " +
        "connect-src 'self' wss://signaling-server-zc6m.onrender.com https://api.x.ai/v1/chat/completions; " +
        "object-src 'none'; base-uri 'self';";
      data = data.toString().replace(/<meta http-equiv="Content-Security-Policy" content="[^"]*">/,
        `<meta http-equiv="Content-Security-Policy" content="${updatedCSP}">`);
      data = data.toString().replace(/<script(?! src)/g,
        `<script nonce="${nonce}"`);
      data = data.toString().replace(/<style/g,
        `<style nonce="${nonce}"`);
      let clientIdFromCookie;
      const cookies = req.headers.cookie ? req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [name, value] = cookie.trim().split('=');
        acc[name] = value;
        return acc;
      }, {}) : {};
      clientIdFromCookie = cookies['clientId'];
      if (!clientIdFromCookie) {
        clientIdFromCookie = uuidv4();
        res.setHeader('Set-Cookie', `clientId=${clientIdFromCookie}; Secure; HttpOnly; SameSite=Strict; Max-Age=31536000; Path=/`);
      }
    } else if (filePath.endsWith('.js')) {
      contentType = 'application/javascript';
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });
const rooms = new Map();
const dailyUsers = new Map();
const dailyConnections = new Map();
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const AUDIT_FILE_BASE = path.join(__dirname, 'audit');
const FEATURES_FILE = path.join('/data', 'features.json');
const STATS_FILE = path.join('/data', 'stats.json');
const UPDATE_INTERVAL = 30000;
const randomCodes = new Set();
const rateLimits = new Map();
const allTimeUsers = new Set();
const ipRateLimits = new Map();
const ipDailyLimits = new Map();
const ipFailureCounts = new Map();
const ipBans = new Map();
const revokedTokens = new Map();
const clientTokens = new Map();
const totpSecrets = new Map();
const processedMessageIds = new Map();
const clientSizeLimits = new Map();
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
  throw new Error('ADMIN_SECRET environment variable is not set.');
}
const ALLOWED_ORIGINS = ['https://anonomoose.com', 'https://www.anonomoose.com', 'http://localhost:3000', 'https://signaling-server-zc6m.onrender.com'];
const secretFile = path.join('/data', 'jwt_secret.txt');
const previousSecretFile = path.join('/data', 'previous_jwt_secret.txt');
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (fs.existsSync(secretFile)) {
    JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
  } else {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, JWT_SECRET);
    console.log('Generated new JWT secret and saved to disk.');
  }
}
if (fs.existsSync(secretFile)) {
  const stats = fs.statSync(secretFile);
  const mtime = stats.mtime.getTime();
  const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
  if (mtime < thirtyDaysAgo) {
    const previousSecret = JWT_SECRET;
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, JWT_SECRET);
    fs.writeFileSync(previousSecretFile, previousSecret);
    console.log('Rotated JWT secret.');
  }
}
const TURN_USERNAME = process.env.TURN_USERNAME;
if (!TURN_USERNAME) {
  throw new Error('TURN_USERNAME environment variable is not set.');
}
const TURN_CREDENTIAL = process.env.TURN_CREDENTIAL;
if (!TURN_CREDENTIAL) {
  throw new Error('TURN_CREDENTIAL environment variable is not set.');
}
const IP_SALT = process.env.IP_SALT || 'your-random-salt-here';
let features = {
  enableService: true,
  enableImages: true,
  enableVoice: true,
  enableVoiceCalls: true,
  enableAudioToggle: true,
  enableGrokBot: true,
  enableP2P: true,
  enableRelay: true
};
if (fs.existsSync(FEATURES_FILE)) {
  try {
    features = JSON.parse(fs.readFileSync(FEATURES_FILE, 'utf8'));
    console.log('Loaded features:', features);
  } catch (err) {
    console.error('Error loading features file:', err);
  }
} else {
  fs.writeFileSync(FEATURES_FILE, JSON.stringify(features));
}
let aggregatedStats = fs.existsSync(STATS_FILE) ? JSON.parse(fs.readFileSync(STATS_FILE, 'utf8')) : { daily: {} };

function saveFeatures() {
  fs.writeFileSync(FEATURES_FILE, JSON.stringify(features));
  console.log('Saved features:', features);
}

function saveAggregatedStats() {
  fs.writeFileSync(STATS_FILE, JSON.stringify(aggregatedStats));
  console.log('Saved aggregated stats to disk');
}

function isValidBase32(str) {
  return /^[A-Z2-7]+=*$/i.test(str) && str.length >= 16;
}

function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  let sanitized = str.replace(/[^A-Za-z0-9+/=]/g, '');
  const padding = (4 - sanitized.length % 4) % 4;
  sanitized += '='.repeat(padding);
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  const isValid = base64Regex.test(sanitized);
  if (!isValid) console.warn('Invalid base64 detected:', str);
  return isValid;
}

function hashIp(ip) {
  return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
}

function hashUa(ua) {
  if (!ua) return crypto.createHmac('sha256', IP_SALT).update('unknown').digest('hex');
  const parser = new UAParser(ua);
  const result = parser.getResult();
  const normalized = `${result.browser.name || 'unknown'} ${result.browser.major || ''} ${result.os.name || 'unknown'} ${result.os.version ? result.os.version.split('.')[0] : ''}`.trim();
  return crypto.createHmac('sha256', IP_SALT).update(normalized || 'unknown').digest('hex');
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

function generateStatsCSV() {
  let csv = 'Period,Users,Connections\n';
  const now = new Date();
  const day = now.toISOString().slice(0, 10);
  csv += `Daily,${dailyUsers.get(day)?.size || 0},${dailyConnections.get(day)?.size || 0}\n`;
  const weekly = computeAggregate(7);
  csv += `Weekly,${weekly.users},${weekly.connections}\n`;
  const monthly = computeAggregate(30);
  csv += `Monthly,${monthly.users},${monthly.connections}\n`;
  const yearly = computeAggregate(365);
  csv += `Yearly,${yearly.users},${yearly.connections}\n`;
  csv += `All-Time,${allTimeUsers.size},N/A\n`;
  return csv;
}

function generateLogsCSV() {
  let csv = 'Timestamp,Event\n';
  const logContent = fs.readFileSync(LOG_FILE, 'utf8');
  logContent.split('\n').forEach(line => {
    if (line.trim()) csv += `${line}\n`;
  });
  const auditContent = fs.readFileSync(`${AUDIT_FILE_BASE}.log`, 'utf8');
  auditContent.split('\n').forEach(line => {
    if (line.trim()) csv += `${line}\n`;
  });
  return csv;
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

function rotateAuditLog() {
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const currentFile = `${AUDIT_FILE_BASE}.log`;
  const rotatedFile = `${AUDIT_FILE_BASE}-${today}.log`;
  if (fs.existsSync(currentFile)) {
    fs.renameSync(currentFile, rotatedFile);
    console.log(`Rotated audit log to ${rotatedFile}`);
  }
  const files = fs.readdirSync(__dirname).filter(f => f.startsWith('audit-') && f.endsWith('.log'));
  files.forEach(file => {
    const fileDate = file.match(/audit-(\d{4}-\d{2}-\d{2})\.log/)[1];
    const fileTime = new Date(fileDate).getTime();
    if (now.getTime() - fileTime > 7 * 24 * 60 * 60 * 1000) {
      fs.unlinkSync(path.join(__dirname, file));
      console.log(`Deleted old audit log: ${file}`);
    }
  });
  fs.writeFileSync(currentFile, '');
}

function logStats(data) {
  const timestamp = new Date().toISOString();
  const day = timestamp.slice(0, 10);
  const stats = {
    clientId: validator.escape(data.clientId || ''),
    username: data.username ? validator.escape(crypto.createHmac('sha256', IP_SALT).update(data.username).digest('hex')) : '',
    targetId: validator.escape(data.targetId || ''),
    code: validator.escape(data.code || ''),
    event: validator.escape(data.event || ''),
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
    dailyUsers.get(day).add(stats.clientId);
    allTimeUsers.add(stats.clientId);
    if (data.event === 'webrtc-connection' && data.targetId) {
      dailyUsers.get(day).add(stats.targetId);
      allTimeUsers.add(stats.targetId);
      const connectionKey = `${stats.clientId}-${stats.targetId}-${stats.code}`;
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

function validateCode(code) {
  const regex = /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/;
  return code && regex.test(code);
}

function validateUsername(username) {
  const regex = /^[a-zA-Z0-9]{1,16}$/;
  return username && regex.test(username);
}

function incrementFailure(ip, ua) {
  const hashedIp = hashIp(ip);
  const hashedUa = hashUa(ua);
  const key = hashedIp + ':' + hashedUa;
  const failure = ipFailureCounts.get(key) || { count: 0, banLevel: 0 };
  failure.count += 1;
  ipFailureCounts.set(key, failure);
  if (failure.count % 5 === 0) {
    console.warn(`High failure rate for key ${key}: ${failure.count} failures`);
    fs.appendFileSync(AUDIT_FILE_BASE + '.log', `${new Date().toISOString()} - High failure anomaly for key ${key}: ${failure.count} failures\n`);
  }
  if (failure.count >= 10) {
    const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000];
    failure.banLevel = Math.min(failure.banLevel + 1, 2);
    const duration = banDurations[failure.banLevel];
    const expiry = Date.now() + duration;
    ipBans.set(key, { expiry, banLevel: failure.banLevel });
    const timestamp = new Date().toISOString();
    const banLogEntry = `${timestamp} - Key Banned: ${key}, Duration: ${duration / 60000} minutes, Ban Level: ${failure.banLevel}\n`;
    fs.appendFileSync(LOG_FILE, banLogEntry, (err) => {
      if (err) {
        console.error('Error appending ban log:', err);
      } else {
        console.warn(`Key ${key} banned until ${new Date(expiry).toISOString()} at ban level ${failure.banLevel} (${duration / 60000} minutes)`);
      }
    });
    ipFailureCounts.delete(key);
  }
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

function restrictClientSize(clientId, size) {
  const now = Date.now();
  const sizeLimit = clientSizeLimits.get(clientId) || { totalSize: 0, startTime: now };
  if (now - sizeLimit.startTime >= 60000) {
    sizeLimit.totalSize = 0;
    sizeLimit.startTime = now;
  }
  sizeLimit.totalSize += size;
  clientSizeLimits.set(clientId, sizeLimit);
  if (sizeLimit.totalSize > 1048576) {
    console.warn(`Size limit exceeded for client ${clientId}: ${sizeLimit.totalSize} bytes in 60s`);
    fs.appendFileSync(AUDIT_FILE_BASE + '.log', `${new Date().toISOString()} - Size limit anomaly for client ${clientId}: ${sizeLimit.totalSize} bytes\n`);
    return false;
  }
  return true;
}

function restrictRate(ws) {
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

const shared = {
  rooms,
  dailyUsers,
  dailyConnections,
  LOG_FILE,
  AUDIT_FILE_BASE,
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
  clientSizeLimits,
  ADMIN_SECRET,
  ALLOWED_ORIGINS,
  JWT_SECRET,
  TURN_USERNAME,
  TURN_CREDENTIAL,
  IP_SALT,
  features,
  aggregatedStats,
  saveFeatures,
  saveAggregatedStats,
  isValidBase32,
  isValidBase64,
  hashIp,
  hashUa,
  broadcast,
  broadcastRandomCodes,
  generateStatsCSV,
  generateLogsCSV,
  computeAggregate,
  updateLogFile,
  rotateAuditLog,
  logStats,
  validateCode,
  validateUsername,
  incrementFailure,
  restrictIpDaily,
  restrictIpRate,
  restrictClientSize,
  restrictRate,
  wss,
  dbPool
};

module.exports.shared = shared;

if (fs.existsSync(LOG_FILE)) {
  const logContent = fs.readFileSync(LOG_FILE, 'utf8');
  const lines = logContent.split('\n');
  lines.forEach(line => {
    const match = line.match(/Client: (\w+)/);
    if (match) allTimeUsers.add(match[1]);
  });
  console.log(`Loaded ${allTimeUsers.size} all-time unique users from log.`);
}

setInterval(() => {
  randomCodes.forEach(code => {
    if (!rooms.has(code) || rooms.get(code).clients.size === 0) {
      randomCodes.delete(code);
    }
  });
  broadcastRandomCodes();
  console.log('Auto-cleaned random codes.');
}, 3600000);

const pingInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 50000);

setInterval(() => {
  const now = Date.now();
  revokedTokens.forEach((expiry, token) => {
    if (expiry < now) {
      revokedTokens.delete(token);
    }
  });
  processedMessageIds.forEach((messageSet, code) => {
    const now = Date.now();
    messageSet.forEach((timestamp, nonce) => {
      if (now - timestamp > 300000) {
        messageSet.delete(nonce);
      }
    });
    if (messageSet.size === 0) {
      processedMessageIds.delete(code);
    }
  });
  console.log(`Cleaned up expired revoked tokens and message IDs. Tokens: ${revokedTokens.size}, Messages: ${processedMessageIds.size}`);
}, 600000);

const { connectionHandler } = require('./server2');
wss.on('connection', connectionHandler);

fs.writeFileSync(LOG_FILE, '', (err) => {
  if (err) console.error('Error creating log file:', err);
  else {
    updateLogFile();
    setInterval(updateLogFile, UPDATE_INTERVAL);
  }
});

rotateAuditLog();
setInterval(rotateAuditLog, 24 * 60 * 60 * 1000);

server.listen(process.env.PORT || 10000, () => {
  console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
