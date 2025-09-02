// server.test.js
const {
  validateMessage,
  validateUsername,
  validateCode,
  isValidBase32,
  isValidBase64,
  hashPassword,
  validatePassword,
  logStats,
  restrictRate,
  restrictClientSize,
  restrictIpRate,
  restrictIpDaily,
  incrementFailure,
  broadcast,
  broadcastRandomCodes,
  hashIp,
  hashUa,
} = require('./server.js');
const { WebSocketServer } = require('ws');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const otplib = require('otplib');

// Mock external dependencies
jest.mock('ws');
jest.mock('uuid');
jest.mock('jsonwebtoken');
jest.mock('pg');
jest.mock('bcryptjs');
jest.mock('otplib');
jest.mock('fs');
jest.mock('path');
jest.mock('http');
jest.mock('https');
jest.mock('crypto');
jest.mock('ua-parser-js');
jest.mock('validator');

describe('Server Functions', () => {
  let mockWss, mockWs, mockReq, mockServer;

  beforeEach(() => {
    mockWs = {
      isAlive: true,
      ping: jest.fn(),
      send: jest.fn(),
      close: jest.fn(),
      readyState: WebSocket.OPEN,
      on: jest.fn(),
    };
    mockWss = {
      clients: new Set([mockWs]),
      on: jest.fn(),
    };
    mockReq = {
      headers: { origin: 'https://anonomoose.com', 'x-forwarded-for': '127.0.0.1', 'user-agent': 'test-agent' },
    };
    mockServer = {
      on: jest.fn(),
      listen: jest.fn(),
    };
    global.rooms = new Map();
    global.dailyUsers = new Map();
    global.dailyConnections = new Map();
    global.randomCodes = new Set();
    global.rateLimits = new Map();
    global.allTimeUsers = new Set();
    global.ipRateLimits = new Map();
    global.ipDailyLimits = new Map();
    global.ipFailureCounts = new Map();
    global.ipBans = new Map();
    global.revokedTokens = new Map();
    global.clientTokens = new Map();
    global.totpSecrets = new Map();
    global.processedMessageIds = new Map();
    global.clientSizeLimits = new Map();
    global.features = { enableService: true, enableImages: true, enableVoice: true, enableVoiceCalls: true, enableAudioToggle: true, enableGrokBot: true, enableP2P: true, enableRelay: true };
    global.aggregatedStats = { daily: {} };
  });

  test('validateMessage handles valid connect', () => {
    const result = validateMessage({ type: 'connect', clientId: 'test' });
    expect(result.valid).toBe(true);
  });

  test('validateMessage rejects invalid code', () => {
    const result = validateMessage({ type: 'join', code: 'invalid', username: 'test' });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid code format');
  });

  test('validateUsername', () => {
    expect(validateUsername('user123')).toBe(true);
    expect(validateUsername('user_name')).toBe(false);
  });

  test('validateCode', () => {
    expect(validateCode('abcd-efgh-ijkl-mnop')).toBe(true);
    expect(validateCode('invalid')).toBe(false);
  });

  test('isValidBase32', () => {
    expect(isValidBase32('JBSWY3DPEHPK3PXP')).toBe(true);
    expect(isValidBase32('invalid!')).toBe(false);
  });

  test('isValidBase64', () => {
    expect(isValidBase64('dGVzdA==')).toBe(true);
    expect(isValidBase64('invalid!')).toBe(false);
  });

  test('hashPassword and validatePassword', async () => {
    bcrypt.hash.mockResolvedValue('hashed');
    bcrypt.compare.mockResolvedValue(true);
    const hash = await hashPassword('pass');
    expect(hash).toBe('hashed');
    const valid = await validatePassword('pass', 'hashed');
    expect(valid).toBe(true);
  });

  test('logStats appends to file', () => {
    const fs = require('fs');
    fs.appendFileSync = jest.fn();
    logStats({ clientId: 'test', event: 'connect' });
    expect(fs.appendFileSync).toHaveBeenCalled();
  });

  test('restrictRate limits messages', () => {
    global.rateLimits = new Map([['test', { count: 51, startTime: Date.now() }]]);
    expect(restrictRate({ clientId: 'test' })).toBe(false);
  });

  test('restrictClientSize limits size', () => {
    global.clientSizeLimits = new Map([['test', { totalSize: 1048577, startTime: Date.now() }]]);
    expect(restrictClientSize('test', 1)).toBe(false);
  });

  test('restrictIpRate limits actions', () => {
    global.ipRateLimits = new Map([['test:join', { count: 6, startTime: Date.now() }]]);
    expect(restrictIpRate('127.0.0.1', 'join')).toBe(false);
  });

  test('restrictIpDaily limits daily', () => {
    global.ipDailyLimits = new Map([['test:join:2025-09-02', { count: 101 }]]);
    expect(restrictIpDaily('127.0.0.1', 'join')).toBe(false);
  });

  test('incrementFailure bans after threshold', () => {
    global.ipFailureCounts = new Map([['test:key', { count: 9, banLevel: 0 }]]);
    incrementFailure('127.0.0.1', 'test-agent');
    expect(ipBans.has('test:key')).toBe(true);
  });

  test('broadcast sends to clients', () => {
    global.rooms = new Map([['test', { clients: new Map([['c1', { ws: mockWs }]]) }]]);
    broadcast('test', { type: 'test' });
    expect(mockWs.send).toHaveBeenCalled();
  });

  test('broadcastRandomCodes sends codes', () => {
    global.randomCodes = new Set(['code1']);
    broadcastRandomCodes();
    expect(mockWs.send).toHaveBeenCalledWith(expect.stringContaining('random-codes'));
  });

  test('hashIp hashes correctly', () => {
    const hash = hashIp('127.0.0.1');
    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
  });

  test('hashUa hashes correctly', () => {
    const hash = hashUa('test-agent');
    expect(hash).toBeDefined();
    expect(typeof hash).toBe('string');
  });
});
