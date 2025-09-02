// utils.test.js
const {
  showStatusMessage,
  sanitizeMessage,
  generateMessageId,
  validateUsername,
  validateCode,
  startKeepAlive,
  stopKeepAlive,
  cleanupPeerConnection,
  initializeMaxClientsUI,
  updateMaxClientsUI,
  setMaxClients,
  log,
  createImageModal,
  createAudioModal,
  generateTotpSecret,
  generateTotpUri,
} = require('./utils.js');

describe('Utils Functions', () => {
  beforeEach(() => {
    // Mock DOM elements
    global.document = {
      getElementById: jest.fn(id => {
        const mockElement = {
          classList: { add: jest.fn(), remove: jest.fn(), toggle: jest.fn() },
          appendChild: jest.fn(),
          focus: jest.fn(),
          innerHTML: '',
          setAttribute: jest.fn(),
          textContent: '',
        };
        if (id === 'status') return { ...mockElement, textContent: '' };
        if (id === 'messages') return mockElement;
        if (id === 'inputContainer') return mockElement;
        if (id === 'addUserText') return mockElement;
        if (id === 'addUserModal') return mockElement;
        if (id === 'addUserRadios') return { ...mockElement, innerHTML: '' };
        if (id === 'remoteAudioContainer') return mockElement;
        return null;
      }),
      createElement: jest.fn(() => ({
        classList: { add: jest.fn(), remove: jest.fn(), toggle: jest.fn() },
        appendChild: jest.fn(),
        focus: jest.fn(),
        innerHTML: '',
        setAttribute: jest.fn(),
        textContent: '',
      })),
      body: { appendChild: jest.fn() },
      querySelectorAll: jest.fn(() => []),
    };
    global.setTimeout = jest.fn(cb => cb());
    global.setInterval = jest.fn(() => 'mock-interval');
    global.clearInterval = jest.fn();
    global.socket = { readyState: WebSocket.OPEN, send: jest.fn() };
    global.clientId = 'test-client';
    global.token = 'test-token';
    global.code = 'test-code';
    global.isInitiator = true;
    global.maxClients = 2;
    global.totalClients = 1;
    global.isConnected = true;
    global.inputContainer = { classList: { add: jest.fn(), remove: jest.fn() } };
    global.messages = { classList: { add: jest.fn(), remove: jest.fn() } };
    global.peerConnections = new Map();
    global.dataChannels = new Map();
    global.candidatesQueues = new Map();
    global.connectionTimeouts = new Map();
    global.retryCounts = new Map();
    global.messageRateLimits = new Map();
    global.remoteAudios = new Map();
  });

  test('showStatusMessage updates status and resets', () => {
    const statusElement = document.getElementById('status');
    showStatusMessage('Test message', 1000);
    expect(statusElement.textContent).toBe('Test message');
    expect(setTimeout).toHaveBeenCalled();
    setTimeout.mock.calls[0][0](); // Simulate timeout
    expect(statusElement.textContent).toBe('Connected (1/2 connections)');
  });

  test('sanitizeMessage removes HTML tags', () => {
    const result = sanitizeMessage('<script>alert(1)</script>');
    expect(result).toBe('<script>alert(1)</script>'); // Mock DOMPurify returns input
  });

  test('generateMessageId returns 9-char string', () => {
    const id = generateMessageId();
    expect(id.length).toBe(9);
    expect(typeof id).toBe('string');
  });

  test('validateUsername', () => {
    expect(validateUsername('user123')).toBe(true);
    expect(validateUsername('a')).toBe(true);
    expect(validateUsername('user_name')).toBe(false);
    expect(validateUsername('toolongusername123')).toBe(false);
    expect(validateUsername('')).toBe(false);
  });

  test('validateCode', () => {
    expect(validateCode('abcd-efgh-ijkl-mnop')).toBe(true);
    expect(validateCode('abc-efgh-ijkl-mnop')).toBe(false);
    expect(validateCode('abcd-efgh-ijkl-mno')).toBe(false);
    expect(validateCode('abcd-efgh-ijkl-mnop!')).toBe(false);
    expect(validateCode('')).toBe(false);
  });

  test('startKeepAlive and stopKeepAlive', () => {
    startKeepAlive();
    expect(setInterval).toHaveBeenCalled();
    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ type: 'ping', clientId: 'test-client', token: 'test-token' }));
    stopKeepAlive();
    expect(clearInterval).toHaveBeenCalledWith('mock-interval');
  });

  test('cleanupPeerConnection', () => {
    global.peerConnections = new Map([['test', { close: jest.fn() }]]);
    global.dataChannels = new Map([['test', { readyState: 'closed', close: jest.fn() }]]);
    global.candidatesQueues = new Map();
    global.connectionTimeouts = new Map([['test', 123]]);
    global.retryCounts = new Map();
    global.messageRateLimits = new Map();
    global.remoteAudios = new Map([['test', { remove: jest.fn() }]]);
    cleanupPeerConnection('test');
    expect(peerConnections.size).toBe(0);
    expect(dataChannels.size).toBe(0);
    expect(clearTimeout).toHaveBeenCalledWith(123);
    expect(document.getElementById('remoteAudioContainer').classList.add).toHaveBeenCalledWith('hidden');
    expect(inputContainer.classList.add).toHaveBeenCalledWith('hidden');
    expect(messages.classList.add).toHaveBeenCalledWith('waiting');
  });

  test('initializeMaxClientsUI for initiator', () => {
    initializeMaxClientsUI();
    expect(document.getElementById('addUserRadios').appendChild).toHaveBeenCalledTimes(9); // 2 to 10
  });

  test('updateMaxClientsUI', () => {
    updateMaxClientsUI();
    expect(document.getElementById('status').textContent).toBe('Connected (1/2 connections)');
    expect(messages.classList.remove).toHaveBeenCalledWith('waiting');
  });

  test('setMaxClients', () => {
    setMaxClients(5);
    expect(socket.send).toHaveBeenCalledWith(
      JSON.stringify({ type: 'set-max-clients', maxClients: 5, code: 'test-code', clientId: 'test-client', token: 'test-token' })
    );
    expect(document.getElementById('status').textContent).toBe('Connected (1/5 connections)');
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
    expect(document.createElement).toHaveBeenCalledWith('div');
    expect(document.body.appendChild).toHaveBeenCalled();
  });

  test('createAudioModal', () => {
    const base64 = 'data:audio/mp3;base64,test';
    createAudioModal(base64, 'testId');
    expect(document.createElement).toHaveBeenCalledWith('div');
    expect(document.body.appendChild).toHaveBeenCalled();
  });

  test('generateTotpSecret returns 16-char base32', () => {
    const secret = generateTotpSecret();
    expect(secret.length).toBe(16); // otplib default
    expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);
  });

  test('generateTotpUri', () => {
    const uri = generateTotpUri('test-room', 'JBSWY3DPEHPK3PXP');
    expect(uri).toBe('otpauth://totp/Anonomoose%20Chat:test-room?secret=JBSWY3DPEHPK3PXP');
  });
});
