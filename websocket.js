class WebSocketManager {
  constructor(url, clientId, onMessage, onOpen, onError, onClose) {
    this.url = url;
    this.clientId = clientId;
    this.onMessage = onMessage;
    this.onOpen = onOpen;
    this.onError = onError;
    this.onClose = onClose;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.socket = null;
    this.connect();
  }

  connect() {
    this.socket = new WebSocket(this.url);
    this.socket.onopen = () => {
      console.log('WebSocket opened');
      this.reconnectAttempts = 0;
      this.socket.send(JSON.stringify({ type: 'connect', clientId: this.clientId }));
      if (this.onOpen) this.onOpen();
    };
    this.socket.onmessage = (event) => {
      if (this.onMessage) this.onMessage(event);
    };
    this.socket.onerror = (error) => {
      console.error('WebSocket error:', error);
      showStatusMessage('Connection error, please try again later.');
      if (this.onError) this.onError(error);
    };
    this.socket.onclose = () => {
      console.log('WebSocket closed');
      stopKeepAlive();
      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        showStatusMessage('Max reconnect attempts reached. Please refresh the page.', 10000);
        if (this.onClose) this.onClose();
        return;
      }
      const delay = Math.min(30000, 5000 * Math.pow(2, this.reconnectAttempts));
      this.reconnectAttempts++;
      setTimeout(() => this.connect(), delay);
      if (this.onClose) this.onClose();
    };
  }

  send(message) {
    if (this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(message);
    } else {
      console.log('Socket not open, cannot send message');
    }
  }

  close() {
    this.socket.close();
  }

  get readyState() {
    return this.socket.readyState;
  }
}
