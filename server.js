const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
// Check for certificate files for local HTTPS
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
const wss = new WebSocket.Server({ server });
const rooms = new Map();
const dailyUsers = new Map();
const dailyConnections = new Map();
const LOG_FILE = path.join(__dirname, 'user_counts.log');
const FEATURES_FILE = path.join(__dirname, 'features.json');
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
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET) {
    throw new Error('ADMIN_SECRET environment variable is not set. Please configure it for security.');
}
const ALLOWED_ORIGINS = ['https://anonomoose.com', 'http://localhost:3000'];
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-fallback';
const TURN_USERNAME = process.env.TURN_USERNAME;
if (!TURN_USERNAME) {
    throw new Error('TURN_USERNAME environment variable is not set. Please configure it.');
}
const TURN_CREDENTIAL = process.env.TURN_CREDENTIAL;
if (!TURN_CREDENTIAL) {
    throw new Error('TURN_CREDENTIAL environment variable is not set. Please configure it.');
}
const IP_SALT = process.env.IP_SALT || 'your-random-salt-here'; // Set in .env for security
let features = {
    enableService: true,
    enableImages: true,
    enableVoice: true,
    enableVoiceCalls: true
};
// Load features from file if exists
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
// Function to save features to file
function saveFeatures() {
    fs.writeFileSync(FEATURES_FILE, JSON.stringify(features));
    console.log('Saved features:', features);
}
function hashIp(ip) {
    return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex');
}
// Validate base64 string
function isValidBase64(str) {
    if (typeof str !== 'string') return false;
    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    return base64Regex.test(str) && str.length % 4 === 0;
}
// Load historical unique users from log on startup
if (fs.existsSync(LOG_FILE)) {
    const logContent = fs.readFileSync(LOG_FILE, 'utf8');
    const lines = logContent.split('\n');
    lines.forEach(line => {
        const match = line.match(/Client: (\w+)/);
        if (match) allTimeUsers.add(match[1]);
    });
    console.log(`Loaded ${allTimeUsers.size} all-time unique users from log.`);
}
// Auto-cleanup for random codes every hour
setInterval(() => {
    randomCodes.forEach(code => {
        if (!rooms.has(code) || rooms.get(code).clients.size === 0) {
            randomCodes.delete(code);
        }
    });
    broadcastRandomCodes();
    console.log('Auto-cleaned random codes.');
}, 3600000);
// Server-side ping to detect dead connections
const pingInterval = setInterval(() => {
    wss.clients.forEach(ws => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);
// Cleanup expired revoked tokens
setInterval(() => {
    const now = Date.now();
    revokedTokens.forEach((expiry, token) => {
        if (expiry < now) {
            revokedTokens.delete(token);
        }
    });
    console.log(`Cleaned up expired revoked tokens. Remaining: ${revokedTokens.size}`);
}, 3600000);
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
    const clientIp = req.headers['x-forwarded-for'] || ws._socket.remoteAddress; // Handle proxies
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
        try {
            const data = JSON.parse(message);
            console.log('Received:', data);
            Object.keys(data).forEach(key => {
                if (typeof data[key] === 'string' && !(data.type === 'public-key' && key === 'publicKey')) {
                    data[key] = validator.escape(validator.trim(data[key]));
                }
            });
            if (data.type === 'public-key' && data.publicKey) {
                if (!isValidBase64(data.publicKey)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid public key format' }));
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
                    const decoded = jwt.verify(data.token, JWT_SECRET);
                    if (decoded.clientId !== data.clientId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Invalid token: clientId mismatch' }));
                        return;
                    }
                    if (revokedTokens.has(data.token)) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Token revoked' }));
                        return;
                    }
                } catch (err) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired token' }));
                    return;
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
                    // Revoke old refresh token
                    const oldRefreshExpiry = decoded.exp * 1000;
                    revokedTokens.set(data.refreshToken, oldRefreshExpiry);
                    // Generate new access and refresh tokens (rotation)
                    const newAccessToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '10m' });
                    const newRefreshToken = jwt.sign({ clientId: data.clientId }, JWT_SECRET, { expiresIn: '1h' });
                    clientTokens.set(data.clientId, { accessToken: newAccessToken, refreshToken: newRefreshToken });
                    ws.send(JSON.stringify({ type: 'token-refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken }));
                } catch (err) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid or expired refresh token' }));
                    return;
                }
                return;
            }
            if (data.type === 'public-key') {
                if (rooms.has(data.code)) {
                    const room = rooms.get(data.code);
                    const initiatorWs = room.clients.get(room.initiator)?.ws;
                    if (initiatorWs && initiatorWs.readyState === WebSocket.OPEN) {
                        initiatorWs.send(JSON.stringify({ type: 'public-key', publicKey: data.publicKey, clientId: data.clientId, code: data.code }));
                    }
                }
                return;
            }
            if (data.type === 'encrypted-room-key') {
                if (rooms.has(data.code)) {
                    const room = rooms.get(data.code);
                    const targetWs = room.clients.get(data.targetId)?.ws;
                    if (targetWs && targetWs.readyState === WebSocket.OPEN) {
                        targetWs.send(JSON.stringify({ type: 'encrypted-room-key', encryptedKey: data.encryptedKey, iv: data.iv, clientId: data.clientId, code: data.code }));
                    }
                }
                return;
            }
            if (data.type === 'join') {
                if (!features.enableService) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Service has been disabled by admin.' }));
                    return;
                }
                if (!restrictIpRate(clientIp, 'join')) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Join rate limit exceeded (5/min). Please wait.' }));
                    incrementFailure(clientIp);
                    return;
                }
                if (!restrictIpDaily(clientIp, 'join')) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Daily join limit exceeded (100/day). Please try again tomorrow.' }));
                    incrementFailure(clientIp);
                    return;
                }
                code = data.code;
                clientId = data.clientId;
                username = data.username;
                if (!validateUsername(username)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid username' }));
                    incrementFailure(clientIp);
                    return;
                }
                if (!validateCode(code)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid code format' }));
                    incrementFailure(clientIp);
                    return;
                }
                if (!rooms.has(code)) {
                    rooms.set(code, { initiator: clientId, clients: new Map(), maxClients: 2 });
                    ws.send(JSON.stringify({ type: 'init', clientId, maxClients: 2, isInitiator: true, turnUsername: TURN_USERNAME, turnCredential: TURN_CREDENTIAL, features }));
                    logStats({ clientId, username, code, event: 'init', totalClients: 1 });
                } else {
                    const room = rooms.get(code);
                    if (room.clients.size >= room.maxClients) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Chat is full' }));
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
                            ws.send(JSON.stringify({ type: 'error', message: 'Username does not match existing clientId' }));
                            incrementFailure(clientIp);
                            return;
                        }
                    } else if (Array.from(room.clients.values()).some(c => c.username === username)) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Username already taken' }));
                        incrementFailure(clientIp);
                        return;
                    }
                    if (!room.clients.has(room.initiator) && room.initiator !== clientId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Initiator offline' }));
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
            }
            if (data.type === 'set-max-clients') {
                if (rooms.has(data.code) && data.clientId === rooms.get(data.code).initiator) {
                    const room = rooms.get(data.code);
                    room.maxClients = Math.min(data.maxClients, 10);
                    broadcast(data.code, { type: 'max-clients', maxClients: room.maxClients, totalClients: room.clients.size });
                    logStats({ clientId: data.clientId, code: data.code, event: 'set-max-clients', totalClients: room.clients.size });
                }
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
                    }
                }
            }
            if (data.type === 'submit-random') {
                if (!restrictIpRate(clientIp, 'submit-random')) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Submit rate limit exceeded (5/min). Please wait.' }));
                    incrementFailure(clientIp);
                    return;
                }
                if (data.code && !rooms.get(data.code)?.clients.size) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Cannot submit empty room code' }));
                    incrementFailure(clientIp);
                    return;
                }
                if (rooms.get(data.code)?.initiator === data.clientId) {
                    randomCodes.add(data.code);
                    broadcastRandomCodes();
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Only initiator can submit to random board' }));
                    incrementFailure(clientIp);
                }
            }
            if (data.type === 'get-random-codes') {
                ws.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
            }
            if (data.type === 'remove-random-code') {
                if (randomCodes.has(data.code)) {
                    randomCodes.delete(data.code);
                    broadcastRandomCodes();
                    console.log(`Removed code ${data.code} from randomCodes`);
                }
            }
            if (data.type === 'relay-message' || data.type === 'relay-image' || data.type === 'relay-voice') {
                if (data.type === 'relay-image' && !features.enableImages) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Image messages are disabled.' }));
                    return;
                }
                if (data.type === 'relay-voice' && !features.enableVoice) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Voice messages are disabled.' }));
                    return;
                }
                const payload = data.type === 'relay-message' ? data.encryptedContent : data.encryptedData;
                if (payload && payload.length > 13653) { // ~10KB base64 = 13653 chars (10*1024*4/3)
                    ws.send(JSON.stringify({ type: 'error', message: 'Payload too large (max 10KB)' }));
                    incrementFailure(clientIp);
                    return;
                }
                if (payload && !isValidBase64(payload)) { // Add base64 format validation
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid base64 format in payload' }));
                    incrementFailure(clientIp);
                    return;
                }
                if (!rooms.has(data.code)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Not in a chat' }));
                    incrementFailure(clientIp);
                    return;
                }
                const room = rooms.get(data.code);
                const senderId = data.clientId;
                if (!room.clients.has(senderId)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Not in a chat' }));
                    incrementFailure(clientIp);
                    return;
                }
                room.clients.forEach((client, clientId) => {
                    if (clientId !== senderId && client.ws.readyState === WebSocket.OPEN) {
                        client.ws.send(JSON.stringify({
                            type: data.type.replace('relay-', ''),
                            messageId: data.messageId,
                            username: data.username,
                            encryptedContent: data.encryptedContent,
                            encryptedData: data.encryptedData,
                            iv: data.iv,
                            salt: data.salt
                        }));
                    }
                });
                console.log(`Relayed ${data.type} from ${senderId} in code ${data.code} (content not logged for privacy)`);
            }
            if (data.type === 'get-stats') {
                if (data.secret === ADMIN_SECRET) {
                    const now = new Date();
                    const day = now.toISOString().slice(0, 10);
                    let totalClients = 0;
                    rooms.forEach(room => {
                        totalClients += room.clients.size;
                    });
                    ws.send(JSON.stringify({
                        type: 'stats',
                        dailyUsers: dailyUsers.get(day)?.size || 0,
                        dailyConnections: dailyConnections.get(day)?.size || 0,
                        allTimeUsers: allTimeUsers.size,
                        activeRooms: rooms.size,
                        totalClients: totalClients
                    }));
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
                }
            }
            if (data.type === 'get-features') {
                if (data.secret === ADMIN_SECRET) {
                    ws.send(JSON.stringify({ type: 'features', ...features }));
                } else {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid admin secret' }));
                }
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
                        // New: Send features-update to all clients, error only to non-admins
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
            }
        } catch (error) {
            console.error('Error processing message:', error);
            ws.send(JSON.stringify({ type: 'error', message: 'Server error, please try again.' }));
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
// Rate limiting function: 50 messages per minute per client (non-admins)
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
// IP rate limiting function: max 5 actions (join/submit) per minute per IP
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
// Daily IP limit for joins (100/day)
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
// Increment failure count and ban IP with exponential duration if threshold reached
function incrementFailure(ip) {
    const hashedIp = hashIp(ip);
    const failure = ipFailureCounts.get(hashedIp) || { count: 0, banLevel: 0 };
    failure.count += 1;
    ipFailureCounts.set(hashedIp, failure);
    if (failure.count % 5 === 0) {
        console.warn(`High failure rate for hashed IP ${hashedIp}: ${failure.count} failures`);
    }
    if (failure.count >= 10) {
        // Exponential ban durations: 5min, 30min, 1hr
        const banDurations = [5 * 60 * 1000, 30 * 60 * 1000, 60 * 60 * 1000]; // 5min, 30min, 1hr
        failure.banLevel = Math.min(failure.banLevel + 1, 2); // Cap at level 2 (1hr)
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
        ipFailureCounts.delete(hashedIp); // Reset failure count after ban
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
        username: data.username || '',
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
}
fs.writeFileSync(LOG_FILE, '', (err) => {
    if (err) console.error('Error creating log file:', err);
    else {
        updateLogFile();
        setInterval(updateLogFile, UPDATE_INTERVAL);
    }
});
function broadcast(code, message) {
    const room = rooms.get(code);
    if (room) {
        room.clients.forEach(client => {
            if (client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify(message));
            }
        });
    }
}
function broadcastRandomCodes() {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'random-codes', codes: Array.from(randomCodes) }));
        }
    });
}
server.listen(process.env.PORT || 10000, () => {
    console.log(`Signaling and relay server running on port ${process.env.PORT || 10000}`);
});
