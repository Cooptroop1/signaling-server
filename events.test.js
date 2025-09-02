import { getCookie, setCookie, processSignalingQueue, generateCode, updateLogoutButtonVisibility, logout } from './events.js';

describe('Events Functions', () => {
  beforeEach(() => {
    global.document = {
      cookie: '',
      getElementById: jest.fn(id => {
        if (id === 'logoutButton') return { classList: { toggle: jest.fn() } };
        return { classList: { add: jest.fn(), remove: jest.fn() }, textContent: '', innerHTML: '', focus: jest.fn(), value: '' };
      }),
    };
    global.localStorage = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
    };
    global.window = {
      location: { reload: jest.fn(), href: '', search: '' },
      crypto: { getRandomValues: jest.fn(arr => arr.fill(1)) },
    };
    global.socket = { close: jest.fn(), send: jest.fn(), readyState: WebSocket.OPEN };
    global.token = 'test-token';
    global.clientId = 'test-client';
    global.username = 'testuser';
    global.isLoggedIn = false;
  });

  test('getCookie retrieves value', () => {
    document.cookie = 'clientId=test;';
    expect(getCookie('clientId')).toBe('test');
  });

  test('setCookie sets value', () => {
    setCookie('clientId', 'test', 1);
    expect(document.cookie).toContain('clientId=test');
  });

  test('processSignalingQueue sends queued messages', () => {
    global.signalingQueue = new Map([['global', [{ type: 'test', additionalData: {} }]]]);
    global.sendSignalingMessage = jest.fn();
    global.sendRelayMessage = jest.fn();
    processSignalingQueue();
    expect(sendSignalingMessage).toHaveBeenCalled();
  });

  test('generateCode returns valid format', () => {
    const code = generateCode();
    expect(code).toMatch(/^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/);
  });

  test('updateLogoutButtonVisibility toggles hidden', () => {
    global.isLoggedIn = true;
    updateLogoutButtonVisibility();
    expect(document.getElementById('logoutButton').classList.toggle).toHaveBeenCalledWith('hidden', false);
  });

  test('logout clears state', () => {
    logout();
    expect(socket.close).toHaveBeenCalled();
    expect(localStorage.removeItem).toHaveBeenCalledWith('username');
    expect(window.location.reload).not.toHaveBeenCalled(); // Since it's not reloading in the function
  });
});
