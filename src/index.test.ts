import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { EnclaveBridgeClient, DEFAULT_SOCKET_PATH, DEFAULT_TIMEOUT, createClient } from './index.js';
import type { ConnectionState } from './types.js';

// Create a mock socket class
class MockSocket extends EventEmitter {
  encoding: string | null = null;
  written: string[] = [];
  destroyed = false;
  ended = false;

  setEncoding(encoding: string) {
    this.encoding = encoding;
  }

  write(data: string) {
    this.written.push(data);
    return true;
  }

  end() {
    this.ended = true;
    setTimeout(() => this.emit('close'), 0);
  }

  destroy() {
    this.destroyed = true;
  }
}

// Mock the net module
let mockSocket: MockSocket;
let connectCallback: (() => void) | null = null;

vi.mock('node:net', () => ({
  Socket: vi.fn(() => mockSocket),
  createConnection: vi.fn((path: string, callback: () => void) => {
    connectCallback = callback;
    return mockSocket;
  }),
}));

describe('EnclaveBridgeClient', () => {
  beforeEach(() => {
    mockSocket = new MockSocket();
    connectCallback = null;
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should use default socket path', () => {
      const client = new EnclaveBridgeClient();
      const info = client.getConnectionInfo();
      expect(info.socketPath).toBe(DEFAULT_SOCKET_PATH);
    });

    it('should accept custom socket path', () => {
      const customPath = '/custom/socket.sock';
      const client = new EnclaveBridgeClient({ socketPath: customPath });
      expect(client.getConnectionInfo().socketPath).toBe(customPath);
    });

    it('should accept custom timeout', () => {
      const client = new EnclaveBridgeClient({ timeout: 5000 });
      expect(client).toBeInstanceOf(EnclaveBridgeClient);
    });

    it('should extend EventEmitter', () => {
      const client = new EnclaveBridgeClient();
      expect(client).toBeInstanceOf(EventEmitter);
    });
  });

  describe('connection state', () => {
    it('should start disconnected', () => {
      const client = new EnclaveBridgeClient();
      expect(client.connectionState).toBe('disconnected');
      expect(client.isConnected).toBe(false);
    });

    it('should transition to connecting when connect() is called', async () => {
      const client = new EnclaveBridgeClient();
      const states: ConnectionState[] = [];
      client.on('stateChange', (state: ConnectionState) => states.push(state));

      const connectPromise = client.connect();
      expect(client.connectionState).toBe('connecting');

      // Simulate successful connection
      connectCallback?.();
      await connectPromise;

      expect(states).toContain('connecting');
      expect(states).toContain('connected');
      expect(client.isConnected).toBe(true);
    });

    it('should emit connect event on successful connection', async () => {
      const client = new EnclaveBridgeClient();
      const connectSpy = vi.fn();
      client.on('connect', connectSpy);

      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      expect(connectSpy).toHaveBeenCalledOnce();
    });

    it('should throw when already connected', async () => {
      const client = new EnclaveBridgeClient();
      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      await expect(client.connect()).rejects.toThrow('Already connected');
    });
  });

  describe('disconnect', () => {
    it('should disconnect gracefully', async () => {
      const client = new EnclaveBridgeClient();
      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      const disconnectPromise = client.disconnect();
      mockSocket.emit('close');
      await disconnectPromise;

      expect(client.isConnected).toBe(false);
      expect(mockSocket.ended).toBe(true);
    });

    it('should do nothing if not connected', async () => {
      const client = new EnclaveBridgeClient();
      await client.disconnect(); // Should not throw
      expect(client.isConnected).toBe(false);
    });

    it('should emit disconnect event', async () => {
      const client = new EnclaveBridgeClient();
      const disconnectSpy = vi.fn();
      client.on('disconnect', disconnectSpy);

      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      const disconnectPromise = client.disconnect();
      mockSocket.emit('close');
      await disconnectPromise;

      expect(disconnectSpy).toHaveBeenCalledOnce();
    });
  });

  describe('getConnectionInfo', () => {
    it('should return connection info when disconnected', () => {
      const client = new EnclaveBridgeClient();
      const info = client.getConnectionInfo();
      expect(info).toEqual({
        socketPath: DEFAULT_SOCKET_PATH,
        state: 'disconnected',
        isConnected: false,
      });
    });

    it('should return connection info when connected', async () => {
      const client = new EnclaveBridgeClient();
      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      const info = client.getConnectionInfo();
      expect(info).toEqual({
        socketPath: DEFAULT_SOCKET_PATH,
        state: 'connected',
        isConnected: true,
      });
    });
  });

  describe('command methods (not connected)', () => {
    it('getPublicKey should throw when not connected', async () => {
      const client = new EnclaveBridgeClient();
      await expect(client.getPublicKey()).rejects.toThrow('Not connected');
    });

    it('getEnclavePublicKey should throw when not connected', async () => {
      const client = new EnclaveBridgeClient();
      await expect(client.getEnclavePublicKey()).rejects.toThrow('Not connected');
    });

    it('setPeerPublicKey should throw when not connected', async () => {
      const client = new EnclaveBridgeClient();
      await expect(client.setPeerPublicKey('test')).rejects.toThrow('Not connected');
    });

    it('enclaveSign should throw when not connected', async () => {
      const client = new EnclaveBridgeClient();
      await expect(client.enclaveSign('test')).rejects.toThrow('Not connected');
    });

    it('decrypt should throw when not connected', async () => {
      const client = new EnclaveBridgeClient();
      await expect(client.decrypt(Buffer.from('test'))).rejects.toThrow('Not connected');
    });

    it('enclaveGenerateKey should throw when not connected', async () => {
      const client = new EnclaveBridgeClient();
      await expect(client.enclaveGenerateKey()).rejects.toThrow('Not connected');
    });
  });

  describe('command methods (connected)', () => {
    let client: EnclaveBridgeClient;

    beforeEach(async () => {
      client = new EnclaveBridgeClient();
      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;
    });

    it('getPublicKey should send command and parse response', async () => {
      const testKey = Buffer.from('03' + 'ab'.repeat(32), 'hex'); // Compressed pubkey
      const responsePromise = client.getPublicKey();

      // Simulate JSON response (matching Swift server protocol)
      mockSocket.emit('data', JSON.stringify({ publicKey: testKey.toString('base64') }));
      const result = await responsePromise;

      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'GET_PUBLIC_KEY' }));
      expect(result.buffer).toEqual(testKey);
      expect(result.hex).toBe(testKey.toString('hex'));
      expect(result.base64).toBe(testKey.toString('base64'));
      expect(result.compressed).toBe(true);
    });

    it('getEnclavePublicKey should send command and parse response', async () => {
      const testKey = Buffer.from('04' + 'cd'.repeat(64), 'hex'); // Uncompressed pubkey
      const responsePromise = client.getEnclavePublicKey();

      mockSocket.emit('data', JSON.stringify({ publicKey: testKey.toString('base64') }));
      const result = await responsePromise;

      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'GET_ENCLAVE_PUBLIC_KEY' }));
      expect(result.buffer).toEqual(testKey);
      expect(result.compressed).toBe(false);
    });

    it('setPeerPublicKey should send command with base64 payload', async () => {
      const testKey = Buffer.from('03' + 'ef'.repeat(32), 'hex');
      const responsePromise = client.setPeerPublicKey(testKey);

      mockSocket.emit('data', JSON.stringify({ ok: true }));
      await responsePromise;

      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'SET_PEER_PUBLIC_KEY', publicKey: testKey.toString('base64') }));
    });

    it('setPeerPublicKey should accept hex string', async () => {
      const testKeyHex = '03' + 'ef'.repeat(32);
      const responsePromise = client.setPeerPublicKey(testKeyHex);

      mockSocket.emit('data', JSON.stringify({ ok: true }));
      await responsePromise;

      const expectedPayload = Buffer.from(testKeyHex, 'hex').toString('base64');
      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'SET_PEER_PUBLIC_KEY', publicKey: expectedPayload }));
    });

    it('enclaveSign should send command and parse signature', async () => {
      const testData = Buffer.from('test message');
      const testSig = Buffer.from('signature_data');
      const responsePromise = client.enclaveSign(testData);

      mockSocket.emit('data', JSON.stringify({ signature: testSig.toString('base64') }));
      const result = await responsePromise;

      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'ENCLAVE_SIGN', data: testData.toString('base64') }));
      expect(result.buffer).toEqual(testSig);
      expect(result.format).toBe('der');
    });

    it('enclaveSign should accept string input', async () => {
      const testMessage = 'test message';
      const testSig = Buffer.from('signature_data');
      const responsePromise = client.enclaveSign(testMessage);

      mockSocket.emit('data', JSON.stringify({ signature: testSig.toString('base64') }));
      await responsePromise;

      const expectedPayload = Buffer.from(testMessage).toString('base64');
      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'ENCLAVE_SIGN', data: expectedPayload }));
    });

    it('decrypt should send command and parse plaintext', async () => {
      const encryptedData = Buffer.from('encrypted_data');
      const plaintext = Buffer.from('hello world');
      const responsePromise = client.decrypt(encryptedData);

      mockSocket.emit('data', JSON.stringify({ plaintext: plaintext.toString('base64') }));
      const result = await responsePromise;

      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'ENCLAVE_DECRYPT', data: encryptedData.toString('base64') }));
      expect(result.buffer).toEqual(plaintext);
      expect(result.text).toBe('hello world');
    });

    it('enclaveDecrypt should be alias for decrypt', async () => {
      const encryptedData = Buffer.from('encrypted_data');
      const plaintext = Buffer.from('hello world');
      const responsePromise = client.enclaveDecrypt(encryptedData);

      mockSocket.emit('data', JSON.stringify({ plaintext: plaintext.toString('base64') }));
      const result = await responsePromise;

      expect(result.text).toBe('hello world');
    });

    it('enclaveGenerateKey should send command and parse key', async () => {
      const newKey = Buffer.from('03' + 'ab'.repeat(32), 'hex');
      const responsePromise = client.enclaveGenerateKey();

      mockSocket.emit('data', JSON.stringify({ publicKey: newKey.toString('base64') }));
      const result = await responsePromise;

      expect(mockSocket.written[0]).toBe(JSON.stringify({ cmd: 'ENCLAVE_GENERATE_KEY' }));
      expect(result.publicKey.buffer).toEqual(newKey);
    });

    it('should throw on error response', async () => {
      const responsePromise = client.getPublicKey();
      mockSocket.emit('data', JSON.stringify({ error: 'Key not found' }));

      await expect(responsePromise).rejects.toThrow('Key not found');
    });

    it('should throw on missing publicKey field', async () => {
      const responsePromise = client.getPublicKey();
      mockSocket.emit('data', JSON.stringify({ ok: true }));

      await expect(responsePromise).rejects.toThrow('missing publicKey');
    });
  });

  describe('ping', () => {
    it('should return true when connected and server responds', async () => {
      const client = new EnclaveBridgeClient();
      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      const pingPromise = client.ping();
      const testKey = Buffer.from('03' + 'ab'.repeat(32), 'hex');
      mockSocket.emit('data', JSON.stringify({ publicKey: testKey.toString('base64') }));

      expect(await pingPromise).toBe(true);
    });

    it('should return false when not connected', async () => {
      const client = new EnclaveBridgeClient();
      expect(await client.ping()).toBe(false);
    });
  });

  describe('error handling', () => {
    it('should emit error event on socket error', async () => {
      const client = new EnclaveBridgeClient();
      const errorSpy = vi.fn();
      client.on('error', errorSpy);

      const connectPromise = client.connect();
      const testError = new Error('Connection refused');
      mockSocket.emit('error', testError);

      await expect(connectPromise).rejects.toThrow('Connection refused');
      expect(errorSpy).toHaveBeenCalledWith(testError);
    });

    it('should reject pending request on socket close', async () => {
      const client = new EnclaveBridgeClient();
      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      const requestPromise = client.getPublicKey();
      mockSocket.emit('close');

      await expect(requestPromise).rejects.toThrow('Connection closed');
    });

    it('should throw when another request is pending', async () => {
      const client = new EnclaveBridgeClient();
      const connectPromise = client.connect();
      connectCallback?.();
      await connectPromise;

      // Start first request (don't respond)
      client.getPublicKey();

      // Second request should fail
      await expect(client.getEnclavePublicKey()).rejects.toThrow('Another request is pending');
    });
  });

  describe('exports', () => {
    it('should export DEFAULT_SOCKET_PATH', () => {
      expect(DEFAULT_SOCKET_PATH).toBe('/tmp/enclave-bridge.sock');
    });

    it('should export DEFAULT_TIMEOUT', () => {
      expect(DEFAULT_TIMEOUT).toBe(30000);
    });

    it('should export createClient helper', () => {
      expect(typeof createClient).toBe('function');
    });
  });
});

describe('createClient', () => {
  beforeEach(() => {
    mockSocket = new MockSocket();
    connectCallback = null;
    vi.clearAllMocks();
  });

  it('should create and connect a client', async () => {
    const clientPromise = createClient();

    // Simulate connection
    setTimeout(() => connectCallback?.(), 0);

    const client = await clientPromise;
    expect(client).toBeInstanceOf(EnclaveBridgeClient);
    expect(client.isConnected).toBe(true);
  });

  it('should pass options to client', async () => {
    const customPath = '/custom/path.sock';
    const clientPromise = createClient({ socketPath: customPath });

    setTimeout(() => connectCallback?.(), 0);

    const client = await clientPromise;
    expect(client.getConnectionInfo().socketPath).toBe(customPath);
  });
});
