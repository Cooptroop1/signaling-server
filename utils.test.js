import { showStatusMessage, sanitizeMessage, generateMessageId, validateUsername, validateCode, startKeepAlive, stopKeepAlive, cleanupPeerConnection, initializeMaxClientsUI, updateMaxClientsUI, setMaxClients, log, createImageModal, createAudioModal, generateTotpSecret, generateTotpUri } from './utils.js';

describe('Utils Functions', () => {
  beforeEach(() => {
    // Mock DOM elements
    global.document = {
      getElementById: jest.fn(id => {
        if (id === 'status') return { textContent: '', setAttribute: jest.fn() };
        return null;
      }),
      createElement: jest.fn(() => ({ classList: { add: jest.fn(), remove: jest.fn(), toggle: jest.fn() }, appendChild: jest.fn(), focus: jest.fn(), innerHTML: '' })),
      body: { appendChild: jest.fn() },
      querySelectorAll: jest.fn(() => []),
    };
    global.setTimeout = jest.fn(cb => cb());
    global.clearInterval = jest.fn();
    global.socket = { readyState: WebSocket.OPEN, send: jest.fn() };
    global.clientId = 'test-client';
    global.token = 'test-token';
    global.code = 'test-code';
    global.isInitiator = true;
    global.maxClients = 2;
    global.totalClients = 1;
    global.isConnected = true;
  });

  test('showStatusMessage updates status and resets', () => {
    const statusElement = document.getElementById('status');
    showStatusMessage('Test message', 1000);
    expect(statusElement.textContent).toBe('Test message');
    expect(setTimeout).toHaveBeenCalled();
    // Simulate timeout callback
    setTimeout.mock.calls[0][0]();
    expect(statusElement.textContent).toBe('Connected (1/2 connections)');
  });

  test('sanitizeMessage removes HTML tags', () => {
    const result = sanitizeMessage('<script>alert(1)</script>');
    expect(result).toBe('');
  });

  test('generateMessageId returns 9-char string', () => {
    const id = generateMessageId();
    expect(id.length).toBe(9);
    expect(typeof id).toBe('string');
  });

  test('validateUsername', () => {
    expect(validateUsername('user123')).toBe(true);
    expect(validateUsername('a')).toBe(true);
    expect(validateUsername('user_name')).toBe(false); // No underscores
    expect(validateUsername('toolongusername123')).toBe(false); // >16 chars
    expect(validateUsername('')).toBe(false);
  });

  test('validateCode', () => {
    expect(validateCode('abcd-efgh-ijkl-mnop')).toBe(true);
    expect(validateCode('abc-efgh-ijkl-mnop')).toBe(false); // Too short
    expect(validateCode('abcd-efgh-ijkl-mno')).toBe(false); // Too short
    expect(validateCode('abcd-efgh-ijkl-mnop!')).toBe(false); // Invalid char
    expect(validateCode('')).toBe(false);
  });

  test('startKeepAlive and stopKeepAlive', () => {
    startKeepAlive();
    expect(setInterval).toHaveBeenCalled();
    stopKeepAlive();
    expect(clearInterval).toHaveBeenCalled();
  });

  test('cleanupPeerConnection', () => {
    // Mock globals
    global.peerConnections = new Map([['test', { close: jest.fn() }]]);
    global.dataChannels = new Map([['test', { readyState: 'closed', close: jest.fn() }]]);
    global.candidatesQueues = new Map();
    global.connectionTimeouts = new Map([['test', 123]]);
    global.retryCounts = new Map();
    global.messageRateLimits = new Map();
    global.remoteAudios = new Map([['test', { remove: jest.fn() }]]);
    global.document = { getElementById: jest.fn(() => ({ classList: { add: jest.fn() } })) };
    global.dataChannels = new Map();
    global.isConnected = true;

    cleanupPeerConnection('test');
    expect(peerConnections.size).toBe(0);
    expect(dataChannels.size).toBe(0);
    expect(clearTimeout).toHaveBeenCalledWith(123);
  });

  test('initializeMaxClientsUI for initiator', () => {
    global.isInitiator = true;
    global.maxClients = 5;
    global.document = {
      getElementById: jest.fn(id => {
        if (id === 'addUserText') return { classList: { toggle: jest.fn() } };
        if (id === 'addUserModal') return { classList: { toggle: jest.fn() } };
        if (id === 'addUserRadios') return { innerHTML: '', appendChild: jest.fn() };
        return null;
      }),
      createElement: jest.fn(() => ({ textContent: '', setAttribute: jest.fn(), className: '', disabled: false, addEventListener: jest.fn() })),
    };

    initializeMaxClientsUI();
    expect(document.getElementById('addUserRadios').appendChild).toHaveBeenCalledTimes(9); // 2 to 10
  });

  test('updateMaxClientsUI', () => {
    global.statusElement = { textContent: '' };
    global.document = {
      getElementById: jest.fn(id => {
        if (id === 'addUserText') return { classList: { toggle: jest.fn() } };
        if (id === 'messages') return { classList: { add: jest.fn(), remove: jest.fn() } };
        return null;
      }),
      querySelectorAll: jest.fn(() => [{ textContent: '5', classList: { toggle: jest.fn() }, disabled: false }]),
    };

    updateMaxClientsUI();
    expect(statusElement.textContent).toBe('Connected (1/2 connections)');
  });

  test('setMaxClients', () => {
    global.isInitiator = true;
    global.clientId = 'test';
    global.socket = { readyState: WebSocket.OPEN, send: jest.fn() };
    global.code = 'test-code';
    global.token = 'test-token';

    setMaxClients(5);
    expect(socket.send).toHaveBeenCalledWith(expect.stringContaining('"set-max-clients"'));
  });

  test('log outputs correctly', () => {
    const consoleLog = jest.spyOn(console, 'log').mockImplementation();
    const consoleWarn = jest.spyOn(console, 'warn').mockImplementation();
    const consoleError = jest.spyOn(console, 'error').mockImplementation();

    log('info', 'test info');
    expect(consoleLog).toHaveBeenCalled();
    log('warn', 'test warn');
    expect(consoleWarn).toHaveBeenCalled();
    log('error', 'test error');
    expect(consoleError).toHaveBeenCalled();

    consoleLog.mockRestore();
    consoleWarn.mockRestore();
    consoleError.mockRestore();
  });

  test('createImageModal', () => {
    const base64 = 'data:image/png;base64,test';
    createImageModal(base64, 'testId');
    expect(document.createElement).toHaveBeenCalledTimes(3); // modal, img
    expect(document.body.appendChild).toHaveBeenCalled();
  });

  test('createAudioModal', () => {
    const base64 = 'data:audio/mp3;base64,test';
    createAudioModal(base64, 'testId');
    expect(document.createElement).toHaveBeenCalledTimes(3); // modal, audio
    expect(document.body.appendChild).toHaveBeenCalled();
  });

  test('generateTotpSecret returns 32-char base32', () => {
    const secret = generateTotpSecret();
    expect(secret.length).toBe(32);
    expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);
  });

  test('generateTotpUri', () => {
    const uri = generateTotpUri('test-room', 'JBSWY3DPEHPK3PXP');
    expect(uri).toContain('otpauth://totp/Anonomoose%20Chat:test-room?secret=JBSWY3DPEHPK3PXP');
  });
});
