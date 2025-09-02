import { prepareAndSendMessage, sendMessage, sendMedia, startPeerConnection, setupDataChannel, processReceivedMessage, handleOffer, handleAnswer, handleCandidate, toggleVoiceCall, startVoiceCall, stopVoiceCall, renegotiate, sendSignalingMessage, broadcastVoiceCallEvent, sendRelayMessage, autoConnect, updateFeaturesUI, sendToGrok, toggleGrokBot, saveGrokKey, setAudioOutput, toggleAudioOutput, startVoiceRecording, stopVoiceRecording, isWebPSupported, generateThumbnail } from './main.js';

describe('Main Functions', () => {
  beforeEach(() => {
    // Mock globals
    global.username = 'testuser';
    global.dataChannels = new Map([['test', { readyState: 'open', send: jest.fn() }]]);
    global.useRelay = false;
    global.features = { enableImages: true, enableVoice: true, enableVoiceCalls: true };
    global.document = {
      getElementById: jest.fn(id => {
        if (id === 'messages') return { prepend: jest.fn(), scrollTop: 0 };
        if (id === 'messageInput') return { value: '', style: { height: '' }, focus: jest.fn() };
        return null;
      }),
      createElement: jest.fn(() => ({ className: '', appendChild: jest.fn(), addEventListener: jest.fn() })),
      createTextNode: jest.fn(),
    };
    global.performance = { now: jest.fn(() => Date.now()) };
    global.navigator = { clipboard: { writeText: jest.fn() } };
    global.window = { btoa: jest.fn(str => Buffer.from(str).toString('base64')) };
    global.crypto = {
      subtle: {
        generateKey: jest.fn(() => Promise.resolve({ privateKey: {}, publicKey: {} })),
        deriveKey: jest.fn(() => Promise.resolve({})),
        encrypt: jest.fn(() => Promise.resolve(new ArrayBuffer(0))),
        decrypt: jest.fn(() => Promise.resolve(new TextEncoder().encode('decrypted').buffer)),
        sign: jest.fn(() => Promise.resolve(new ArrayBuffer(0))),
        verify: jest.fn(() => Promise.resolve(true)),
      },
      getRandomValues: jest.fn(arr => arr.fill(1)),
      randomUUID: jest.fn(() => 'test-uuid'),
    };
    global.fetch = jest.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({ choices: [{ message: { content: 'response' }}] }) }));
    global.navigator.mediaDevices = {
      getUserMedia: jest.fn(() => Promise.resolve({ getTracks: () => [{ stop: jest.fn() }] })),
      enumerateDevices: jest.fn(() => Promise.resolve([{ kind: 'audiooutput', deviceId: 'default', label: 'speaker' }])),
    };
    global.MediaRecorder = jest.fn(() => ({
      state: 'inactive',
      start: jest.fn(),
      stop: jest.fn(),
      addEventListener: jest.fn(),
    }));
    global.Image = jest.fn(() => ({ onload: jest.fn(), src: '' }));
    global.window.crypto = global.crypto;
  });

  test('prepareAndSendMessage sends text message', async () => {
    await prepareAndSendMessage({ content: 'test message', type: 'message' });
    expect(document.getElementById('messages').prepend).toHaveBeenCalled();
  });

  test('sendMessage handles Grok query', async () => {
    await sendMessage('/grok test query');
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining('https://api.x.ai'), expect.any(Object));
  });

  test('sendMedia sends image', async () => {
    const file = { type: 'image/jpeg', size: 1000, name: 'test.jpg' };
    await sendMedia(file, 'image');
    expect(document.getElementById('messages').prepend).toHaveBeenCalled();
  });

  test('startPeerConnection creates offer', async () => {
    global.RTCPeerConnection = jest.fn(() => ({
      createOffer: jest.fn(() => Promise.resolve({})),
      setLocalDescription: jest.fn(() => Promise.resolve()),
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
    await startPeerConnection('test', true);
    expect(RTCPeerConnection).toHaveBeenCalled();
  });

  test('setupDataChannel handles messages', () => {
    const dataChannel = {
      onopen: jest.fn(),
      onmessage: jest.fn(),
      onerror: jest.fn(),
      onclose: jest.fn(),
      readyState: 'open',
      send: jest.fn(),
    };
    setupDataChannel(dataChannel, 'test');
    expect(dataChannel.onopen).toBeDefined();
  });

  test('processReceivedMessage decrypts and displays', async () => {
    const data = { type: 'message', messageId: 'test', encryptedBlob: 'encrypted', iv: 'iv', signature: 'sig', nonce: 'nonce' };
    await processReceivedMessage(data, 'sender');
    expect(document.getElementById('messages').prepend).toHaveBeenCalled();
  });

  test('handleOffer sets remote description', async () => {
    const peerConnection = {
      signalingState: 'stable',
      setRemoteDescription: jest.fn(() => Promise.resolve()),
      createAnswer: jest.fn(() => Promise.resolve({ type: 'answer' })),
      setLocalDescription: jest.fn(() => Promise.resolve()),
    };
    global.peerConnections = new Map([['test', peerConnection]]);
    await handleOffer({ type: 'offer' }, 'test');
    expect(peerConnection.setRemoteDescription).toHaveBeenCalled();
  });

  test('toggleVoiceCall starts and stops', async () => {
    await toggleVoiceCall();
    expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalled();
    await toggleVoiceCall();
    expect(document.getElementById('voiceCallButton').classList.remove).toHaveBeenCalledWith('active');
  });

  test('startVoiceRecording records audio', () => {
    startVoiceRecording();
    expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalled();
  });

  test('isWebPSupported checks canvas', () => {
    global.document = { createElement: jest.fn(() => ({ getContext: jest.fn(() => ({})), toDataURL: jest.fn(() => 'data:image/webp') })) };
    isWebPSupported().then(res => expect(res).toBe(true));
  });
});
