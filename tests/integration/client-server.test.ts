/**
 * Integration tests for EnclaveBridge Client
 *
 * These tests use a mock socket server to test the client's behavior
 * in a more realistic environment.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createServer, Server, Socket } from 'node:net';
import { EnclaveBridgeClient, createClient } from '../../src/index.js';
import { ECIESEncryptionType } from '../../src/types.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Create a unique socket path for each test
const getTestSocketPath = () =>
  path.join(os.tmpdir(), `enclave-test-${Date.now()}-${Math.random().toString(36).slice(2)}.sock`);

describe('Integration: Client-Server Communication', () => {
  let server: Server;
  let socketPath: string;
  let clients: Socket[] = [];

  beforeEach(() => {
    socketPath = getTestSocketPath();
    clients = [];
  });

  afterEach(async () => {
    // Clean up clients
    for (const client of clients) {
      client.destroy();
    }

    // Clean up server
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }

    // Remove socket file
    try {
      fs.unlinkSync(socketPath);
    } catch {
      // Ignore
    }
  });

  /**
   * Start a mock server that speaks the JSON protocol matching the Swift server.
   * The Swift server parses JSON by looking for '}' characters.
   */
  const startServer = (handler: (socket: Socket, request: Record<string, unknown>) => void): Promise<void> => {
    return new Promise((resolve) => {
      server = createServer((socket) => {
        clients.push(socket);
        socket.setEncoding('utf8');

        let buffer = '';
        socket.on('data', (data) => {
          buffer += data;
          
          // Parse JSON by finding complete objects (matching Swift server behavior)
          let braceCount = 0;
          let inString = false;
          let escaped = false;
          let jsonStart = -1;
          
          for (let i = 0; i < buffer.length; i++) {
            const char = buffer[i];
            
            if (escaped) {
              escaped = false;
              continue;
            }
            
            if (char === '\\' && inString) {
              escaped = true;
              continue;
            }
            
            if (char === '"') {
              inString = !inString;
              continue;
            }
            
            if (!inString) {
              if (char === '{') {
                if (braceCount === 0) jsonStart = i;
                braceCount++;
              } else if (char === '}') {
                braceCount--;
                if (braceCount === 0 && jsonStart !== -1) {
                  const jsonStr = buffer.substring(jsonStart, i + 1);
                  buffer = buffer.substring(i + 1);
                  i = -1; // Reset loop for remaining buffer
                  jsonStart = -1;
                  
                  try {
                    const request = JSON.parse(jsonStr) as Record<string, unknown>;
                    handler(socket, request);
                  } catch {
                    socket.write(JSON.stringify({ error: 'Invalid JSON' }));
                  }
                }
              }
            }
          }
        });
      });

      server.listen(socketPath, () => resolve());
    });
  };

  describe('Connection handling', () => {
    it('should connect to a real socket server', async () => {
      await startServer(() => {});

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      expect(client.isConnected).toBe(true);
      await client.disconnect();
    });

    it('should handle connection refused', async () => {
      const client = new EnclaveBridgeClient({ socketPath: '/nonexistent/path.sock' });

      // Add error listener to prevent uncaught exception
      client.on('error', () => {});

      await expect(client.connect()).rejects.toThrow();
      expect(client.isConnected).toBe(false);
    });

    it('should handle server disconnect', async () => {
      await startServer(() => {});

      const client = new EnclaveBridgeClient({ socketPath });
      
      // Add error listener to handle potential errors
      client.on('error', () => {});
      
      await client.connect();
      expect(client.isConnected).toBe(true);
      
      // Set up disconnect listener before closing
      const disconnectPromise = new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Disconnect timeout')), 2000);
        client.on('disconnect', () => {
          clearTimeout(timeout);
          resolve();
        });
      });

      // Destroy all connected clients (server-side sockets tracked in `clients` array)
      clients.forEach(s => s.destroy());

      // Wait for disconnect
      await disconnectPromise;

      expect(client.isConnected).toBe(false);
    });
  });

  describe('Command-response flow (JSON protocol)', () => {
    it('should send and receive GET_PUBLIC_KEY', async () => {
      const testKey = Buffer.from('03' + 'ab'.repeat(32), 'hex');

      await startServer((socket, request) => {
        if (request.cmd === 'GET_PUBLIC_KEY') {
          socket.write(JSON.stringify({ publicKey: testKey.toString('base64') }));
        }
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      const result = await client.getPublicKey();

      expect(result.buffer).toEqual(testKey);
      expect(result.compressed).toBe(true);

      await client.disconnect();
    });

    it('should send and receive GET_ENCLAVE_PUBLIC_KEY', async () => {
      const testKey = Buffer.from('04' + 'cd'.repeat(64), 'hex');

      await startServer((socket, request) => {
        if (request.cmd === 'GET_ENCLAVE_PUBLIC_KEY') {
          socket.write(JSON.stringify({ publicKey: testKey.toString('base64') }));
        }
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      const result = await client.getEnclavePublicKey();

      expect(result.buffer).toEqual(testKey);
      expect(result.compressed).toBe(false);

      await client.disconnect();
    });

    it('should send SET_PEER_PUBLIC_KEY with publicKey in JSON', async () => {
      const peerKey = Buffer.from('03' + 'ef'.repeat(32), 'hex');
      let receivedRequest: Record<string, unknown> | null = null;

      await startServer((socket, request) => {
        receivedRequest = request;
        socket.write(JSON.stringify({ ok: true }));
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      await client.setPeerPublicKey(peerKey);

      expect(receivedRequest).toEqual({
        cmd: 'SET_PEER_PUBLIC_KEY',
        publicKey: peerKey.toString('base64'),
      });

      await client.disconnect();
    });

    it('should send ENCLAVE_SIGN and receive signature', async () => {
      const testMessage = Buffer.from('message to sign');
      const testSignature = Buffer.from('mock_signature_bytes');
      let receivedRequest: Record<string, unknown> | null = null;

      await startServer((socket, request) => {
        if (request.cmd === 'ENCLAVE_SIGN') {
          receivedRequest = request;
          socket.write(JSON.stringify({ signature: testSignature.toString('base64') }));
        }
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      const result = await client.enclaveSign(testMessage);

      expect(receivedRequest).toEqual({
        cmd: 'ENCLAVE_SIGN',
        data: testMessage.toString('base64'),
      });
      expect(result.buffer).toEqual(testSignature);
      expect(result.format).toBe('der');

      await client.disconnect();
    });

    it('should send ENCLAVE_DECRYPT and receive plaintext', async () => {
      const encrypted = Buffer.from('encrypted_data');
      const plaintext = Buffer.from('decrypted message');
      let receivedRequest: Record<string, unknown> | null = null;

      await startServer((socket, request) => {
        if (request.cmd === 'ENCLAVE_DECRYPT') {
          receivedRequest = request;
          socket.write(JSON.stringify({ plaintext: plaintext.toString('base64') }));
        }
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      const result = await client.decrypt(encrypted);

      expect(receivedRequest).toEqual({
        cmd: 'ENCLAVE_DECRYPT',
        data: encrypted.toString('base64'),
      });
      expect(result.buffer).toEqual(plaintext);
      expect(result.text).toBe('decrypted message');

      await client.disconnect();
    });

    it('should send ENCLAVE_GENERATE_KEY and receive new key', async () => {
      const newKey = Buffer.from('03' + '11'.repeat(32), 'hex');

      await startServer((socket, request) => {
        if (request.cmd === 'ENCLAVE_GENERATE_KEY') {
          socket.write(JSON.stringify({ publicKey: newKey.toString('base64') }));
        }
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      const result = await client.enclaveGenerateKey();

      expect(result.publicKey.buffer).toEqual(newKey);

      await client.disconnect();
    });
  });

  describe('Error handling', () => {
    it('should handle error responses', async () => {
      await startServer((socket) => {
        socket.write(JSON.stringify({ error: 'Key not found' }));
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      await expect(client.getPublicKey()).rejects.toThrow('Key not found');

      await client.disconnect();
    });

    it('should handle server closing during request', async () => {
      await startServer((socket) => {
        socket.destroy();
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      await expect(client.getPublicKey()).rejects.toThrow('Connection closed');
    });

    it('should handle timeout', async () => {
      await startServer(() => {
        // Never respond
      });

      const client = new EnclaveBridgeClient({ socketPath, timeout: 100 });
      await client.connect();

      await expect(client.getPublicKey()).rejects.toThrow('timeout');

      await client.disconnect();
    });
  });

  describe('Multiple requests', () => {
    it('should handle sequential requests', async () => {
      const key1 = Buffer.from('03' + 'aa'.repeat(32), 'hex');
      const key2 = Buffer.from('04' + 'bb'.repeat(64), 'hex');

      await startServer((socket, request) => {
        if (request.cmd === 'GET_PUBLIC_KEY') {
          socket.write(JSON.stringify({ publicKey: key1.toString('base64') }));
        } else if (request.cmd === 'GET_ENCLAVE_PUBLIC_KEY') {
          socket.write(JSON.stringify({ publicKey: key2.toString('base64') }));
        }
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      const result1 = await client.getPublicKey();
      const result2 = await client.getEnclavePublicKey();

      expect(result1.buffer).toEqual(key1);
      expect(result2.buffer).toEqual(key2);

      await client.disconnect();
    });

    it('should reject concurrent requests', async () => {
      await startServer((socket) => {
        // Delayed response
        setTimeout(() => {
          socket.write(JSON.stringify({ publicKey: 'dGVzdA==' }));
        }, 50);
      });

      const client = new EnclaveBridgeClient({ socketPath });
      await client.connect();

      const promise1 = client.getPublicKey();
      await expect(client.getEnclavePublicKey()).rejects.toThrow('Another request is pending');

      await promise1.catch(() => {}); // Clean up
      await client.disconnect();
    });
  });

  describe('createClient helper', () => {
    it('should create and connect a client', async () => {
      await startServer(() => {});

      const client = await createClient({ socketPath });

      expect(client).toBeInstanceOf(EnclaveBridgeClient);
      expect(client.isConnected).toBe(true);

      await client.disconnect();
    });
  });
});

describe('Integration: ECIES Format Handling', () => {
  let server: Server;
  let socketPath: string;
  let clients: Socket[] = [];

  beforeEach(() => {
    socketPath = getTestSocketPath();
    clients = [];
  });

  afterEach(async () => {
    for (const client of clients) {
      client.destroy();
    }
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
    try {
      fs.unlinkSync(socketPath);
    } catch {
      // Ignore
    }
  });

  /**
   * Start a mock server that speaks the JSON protocol matching the Swift server.
   */
  const startServer = (handler: (socket: Socket, request: Record<string, unknown>) => void): Promise<void> => {
    return new Promise((resolve) => {
      server = createServer((socket) => {
        clients.push(socket);
        socket.setEncoding('utf8');

        let buffer = '';
        socket.on('data', (data) => {
          buffer += data;
          
          // Parse JSON by finding complete objects (matching Swift server behavior)
          let braceCount = 0;
          let inString = false;
          let escaped = false;
          let jsonStart = -1;
          
          for (let i = 0; i < buffer.length; i++) {
            const char = buffer[i];
            
            if (escaped) {
              escaped = false;
              continue;
            }
            
            if (char === '\\' && inString) {
              escaped = true;
              continue;
            }
            
            if (char === '"') {
              inString = !inString;
              continue;
            }
            
            if (!inString) {
              if (char === '{') {
                if (braceCount === 0) jsonStart = i;
                braceCount++;
              } else if (char === '}') {
                braceCount--;
                if (braceCount === 0 && jsonStart !== -1) {
                  const jsonStr = buffer.substring(jsonStart, i + 1);
                  buffer = buffer.substring(i + 1);
                  i = -1;
                  jsonStart = -1;
                  
                  try {
                    const request = JSON.parse(jsonStr) as Record<string, unknown>;
                    handler(socket, request);
                  } catch {
                    socket.write(JSON.stringify({ error: 'Invalid JSON' }));
                  }
                }
              }
            }
          }
        });
      });

      server.listen(socketPath, () => resolve());
    });
  };

  it('should correctly encode and decode ECIES data for decryption', async () => {
    // Create mock ECIES encrypted data
    const ephemeralKey = Buffer.concat([Buffer.from([0x02]), Buffer.alloc(32, 0xab)]);
    const iv = Buffer.alloc(12, 0xcd);
    const authTag = Buffer.alloc(16, 0xef);
    const ciphertext = Buffer.from('encrypted content');

    const eciesData = Buffer.concat([
      Buffer.from([1, 0, ECIESEncryptionType.Basic]), // version, cipherSuite, type
      ephemeralKey,
      iv,
      authTag,
      ciphertext,
    ]);

    const plaintext = Buffer.from('hello world');

    await startServer((socket, request) => {
      if (request.cmd === 'ENCLAVE_DECRYPT') {
        const receivedData = Buffer.from(request.data as string, 'base64');

        // Verify the received data matches what we sent
        expect(receivedData).toEqual(eciesData);

        socket.write(JSON.stringify({ plaintext: plaintext.toString('base64') }));
      }
    });

    const client = new EnclaveBridgeClient({ socketPath });
    await client.connect();

    const result = await client.decrypt(eciesData);

    expect(result.text).toBe('hello world');

    await client.disconnect();
  });
});
