// setupTests.js
global.window = global;
global.window.crypto = {
  subtle: {
    generateKey: jest.fn(),
    importKey: jest.fn(),
    exportKey: jest.fn(),
    deriveKey: jest.fn(),
    deriveBits: jest.fn(),
    encrypt: jest.fn(),
    decrypt: jest.fn(),
    sign: jest.fn(),
    verify: jest.fn(),
  },
  getRandomValues: jest.fn(arr => arr),
  randomUUID: jest.fn(() => 'mock-uuid'),
};
global.TextEncoder = class {
  encode(str) {
    return new Uint8Array(str.split('').map(c => c.charCodeAt(0)));
  }
};
global.TextDecoder = class {
  decode(arr) {
    return String.fromCharCode(...new Uint8Array(arr));
  }
};
global.WebSocket = class {
  static OPEN = 1;
  constructor() {
    this.readyState = WebSocket.OPEN;
    this.send = jest.fn();
    this.close = jest.fn();
  }
};
global.RTCPeerConnection = jest.fn(() => ({
  createOffer: jest.fn(() => Promise.resolve({})),
  setLocalDescription: jest.fn(() => Promise.resolve()),
  setRemoteDescription: jest.fn(() => Promise.resolve()),
  createAnswer: jest.fn(() => Promise.resolve({ type: 'answer' })),
  addIceCandidate: jest.fn(),
  createDataChannel: jest.fn(),
  onicecandidate: jest.fn(),
  onicecandidateerror: jest.fn(),
  onicegatheringstatechange: jest.fn(),
  onconnectionstatechange: jest.fn(),
  ontrack: jest.fn(),
  ondatachannel: jest.fn(),
  onsignalingstatechange: jest.fn(),
  close: jest.fn(),
}));
global.Image = class {
  constructor() {
    this.onload = null;
    this.src = '';
  }
};
global.MediaRecorder = class {
  constructor() {
    this.state = 'inactive';
    this.start = jest.fn();
    this.stop = jest.fn();
    this.addEventListener = jest.fn();
  }
};
global.document = {
  createElement: jest.fn(() => ({
    classList: { add: jest.fn(), remove: jest.fn(), toggle: jest.fn() },
    appendChild: jest.fn(),
    focus: jest.fn(),
    innerHTML: '',
    setAttribute: jest.fn(),
    textContent: '',
  })),
  getElementById: jest.fn(() => ({
    classList: { add: jest.fn(), remove: jest.fn(), toggle: jest.fn() },
    appendChild: jest.fn(),
    focus: jest.fn(),
    innerHTML: '',
    setAttribute: jest.fn(),
    textContent: '',
  })),
  querySelectorAll: jest.fn(() => []),
  cookie: '',
  body: { appendChild: jest.fn() },
};
global.navigator = {
  mediaDevices: {
    getUserMedia: jest.fn(() => Promise.resolve({ getTracks: () => [{ stop: jest.fn() }] })),
    enumerateDevices: jest.fn(() => Promise.resolve([{ kind: 'audiooutput', deviceId: 'default', label: 'speaker' }])),
  },
  clipboard: { writeText: jest.fn(() => Promise.resolve()) },
};
global.performance = { now: jest.fn(() => Date.now()) };
global.window.location = { reload: jest.fn(), href: '', search: '' };
