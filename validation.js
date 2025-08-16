const validator = require('validator');

function isValidBase32(str) {
  return /^[A-Z2-7]+$/i.test(str) && str.length >= 16;
}

function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(str) && str.length % 4 === 0;
}

function validateUsername(username) {
  const regex = /^[a-zA-Z0-9]{1,16}$/;
  return username && regex.test(username);
}

function validateCode(code) {
  const regex = /^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/;
  return code && regex.test(code);
}

function validateMessage(data) {
  if (typeof data !== 'object' || data === null || !data.type) {
    return { valid: false, error: 'Invalid message: must be an object with "type" field' };
  }
  if (data.token && typeof data.token !== 'string') {
    return { valid: false, error: 'Invalid token: must be a string' };
  }
  if (data.clientId && typeof data.clientId !== 'string') {
    return { valid: false, error: 'Invalid clientId: must be a string' };
  }
  if (data.code && !validateCode(data.code)) {
    return { valid: false, error: 'Invalid code format' };
  }
  if (data.username && !validateUsername(data.username)) {
    return { valid: false, error: 'Invalid username: 1-16 alphanumeric characters' };
  }

  switch (data.type) {
    case 'connect':
      if (!data.clientId || typeof data.clientId !== 'string') {
        return { valid: false, error: 'connect: clientId required as string' };
      }
      break;
    case 'refresh-token':
      if (!data.refreshToken || typeof data.refreshToken !== 'string') {
        return { valid: false, error: 'refresh-token: refreshToken required as string' };
      }
      break;
    case 'public-key':
    case 'public-key-response':
      if (!data.publicKey || !isValidBase64(data.publicKey)) {
        return { valid: false, error: `${data.type}: invalid publicKey format` };
      }
      if (!data.code) {
        return { valid: false, error: `${data.type}: code required` };
      }
      break;
    case 'request-public-key':
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'request-public-key: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'request-public-key: code required' };
      }
      break;
    case 'encrypted-room-key':
      if (!data.encryptedKey || !isValidBase64(data.encryptedKey)) {
        return { valid: false, error: 'encrypted-room-key: invalid encryptedKey format' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'encrypted-room-key: invalid iv' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'encrypted-room-key: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'encrypted-room-key: code required' };
      }
      break;
    case 'new-room-key':
      if (!data.encrypted || !isValidBase64(data.encrypted)) {
        return { valid: false, error: 'new-room-key: invalid encrypted' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'new-room-key: invalid iv' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'new-room-key: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'new-room-key: code required' };
      }
      break;
    case 'join':
      if (!data.code) {
        return { valid: false, error: 'join: code required' };
      }
      if (!data.username) {
        return { valid: false, error: 'join: username required' };
      }
      if (data.totpCode && typeof data.totpCode !== 'string') {
        return { valid: false, error: 'join: totpCode must be a string if provided' };
      }
      if (data.publicKey && !isValidBase64(data.publicKey)) {
        return { valid: false, error: 'join: invalid publicKey format' };
      }
      break;
    case 'check-totp':
      if (!data.code) {
        return { valid: false, error: 'check-totp: code required' };
      }
      break;
    case 'set-max-clients':
      if (!data.maxClients || typeof data.maxClients !== 'number' || data.maxClients < 2 || data.maxClients > 10) {
        return { valid: false, error: 'set-max-clients: maxClients must be number between 2 and 10' };
      }
      if (!data.code) {
        return { valid: false, error: 'set-max-clients: code required' };
      }
      break;
    case 'offer':
    case 'answer':
      if (!data.offer && !data.answer) {
        return { valid: false, error: `${data.type}: offer or answer required` };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: `${data.type}: targetId required as string` };
      }
      if (!data.code) {
        return { valid: false, error: `${data.type}: code required` };
      }
      break;
    case 'candidate':
      if (!data.candidate) {
        return { valid: false, error: 'candidate: candidate required' };
      }
      if (!data.targetId || typeof data.targetId !== 'string') {
        return { valid: false, error: 'candidate: targetId required as string' };
      }
      if (!data.code) {
        return { valid: false, error: 'candidate: code required' };
      }
      break;
    case 'submit-random':
      if (!data.code) {
        return { valid: false, error: 'submit-random: code required' };
      }
      break;
    case 'get-random-codes':
      break;
    case 'relay-message':
    case 'relay-image':
    case 'relay-voice':
    case 'relay-file':
      const payloadField = data.type === 'relay-message' ? 'encryptedContent' : 'encryptedData';
      if (!data[payloadField] || !isValidBase64(data[payloadField])) {
        return { valid: false, error: `${data.type}: invalid ${payloadField}` };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: `${data.type}: invalid iv` };
      }
      if (!data.salt || !isValidBase64(data.salt)) {
        return { valid: false, error: `${data.type}: invalid salt` };
      }
      if (!data.signature || !isValidBase64(data.signature)) {
        return { valid: false, error: `${data.type}: invalid signature` };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: `${data.type}: messageId required as string` };
      }
      if (!data.code) {
        return { valid: false, error: `${data.type}: code required` };
      }
      break;
    case 'relay-chunk':
      if (!data.chunk || !isValidBase64(data.chunk)) {
        return { valid: false, error: 'relay-chunk: invalid chunk' };
      }
      if (!data.messageId || typeof data.messageId !== 'string') {
        return { valid: false, error: 'relay-chunk: messageId required as string' };
      }
      if (!data.relayType || !['relay-image', 'relay-voice', 'relay-file'].includes(data.relayType)) {
        return { valid: false, error: 'relay-chunk: invalid relayType' };
      }
      if (typeof data.index !== 'number' || typeof data.total !== 'number' || data.index >= data.total) {
        return { valid: false, error: 'relay-chunk: invalid index or total' };
      }
      if (!data.iv || !isValidBase64(data.iv)) {
        return { valid: false, error: 'relay-chunk: invalid iv' };
      }
      if (!data.salt || !isValidBase64(data.salt)) {
        return { valid: false, error: 'relay-chunk: invalid salt' };
      }
      if (!data.signature || !isValidBase64(data.signature)) {
        return { valid: false, error: 'relay-chunk: invalid signature' };
      }
      if (!data.code) {
        return { valid: false, error: 'relay-chunk: code required' };
      }
      break;
    case 'get-stats':
    case 'get-features':
    case 'toggle-feature':
      if (!data.secret || typeof data.secret !== 'string') {
        return { valid: false, error: `${data.type}: secret required as string` };
      }
      if (data.type === 'toggle-feature' && (!data.feature || typeof data.feature !== 'string')) {
        return { valid: false, error: 'toggle-feature: feature required as string' };
      }
      break;
    case 'ping':
    case 'pong':
      break;
    case 'set-totp':
      if (!data.code) {
        return { valid: false, error: 'set-totp: code required' };
      }
      if (!data.secret || typeof data.secret !== 'string' || !isValidBase32(data.secret)) {
        return { valid: false, error: 'set-totp: valid base32 secret required' };
      }
      break;
    default:
      return { valid: false, error: 'Unknown message type' };
  }
  return { valid: true };
}

module.exports = {
  isValidBase32,
  isValidBase64,
  validateUsername,
  validateCode,
  validateMessage
};
