/**
 * Enclave Bridge Client - TypeScript client for Apple Secure Enclave bridge
 *
 * This client communicates with the Enclave Bridge macOS app via Unix domain socket,
 * providing access to:
 * - Secure Enclave P-256 key operations (signing)
 * - secp256k1 key operations (ECIES decryption)
 * - Key management and server status
 *
 * Protocol Format (JSON):
 * - Request: {"cmd": "COMMAND", ...payload}
 * - Response: {"publicKey": "...", ...} or {"error": "message"}
 */

import { Socket, createConnection } from 'node:net';
import { EventEmitter } from 'node:events';
import { platform } from 'node:os';
import { access, constants as fsConstants } from 'node:fs/promises';

// Re-export types and utilities
export * from './types.js';
export * from './ecies.js';
export * from './errors.js';
export * from './crypto.js';
export { ConnectionPool } from './pool.js';
export type { ConnectionPoolOptions } from './pool.js';
export * from './streaming.js';

import type {
  EnclaveBridgeClientOptions,
  ConnectionState,
  PublicKeyInfo,
  SignatureResult,
  DecryptionResult,
  KeyGenerationResult,
  BridgeResponse,
  QueuedRequest,
  PlatformSupport,
  HealthStatus,
  ServerVersion,
  ServerStatus,
  ServerMetrics,
  KeyList,
  HeartbeatResponse,
} from './types.js';

import {
  ConnectionError,
  TimeoutError,
  InvalidOperationError,
  ProtocolError,
  PlatformError,
} from './errors.js';

/**
 * Default socket path for Enclave Bridges
 */
export const DEFAULT_SOCKET_PATH = '/tmp/enclave-bridge.sock';

/**
 * Default connection timeout in milliseconds
 */
export const DEFAULT_TIMEOUT = 30000;

/**
 * Default reconnect delay in milliseconds
 */
export const DEFAULT_RECONNECT_DELAY = 1000;

/**
 * Default maximum reconnect delay in milliseconds
 */
export const DEFAULT_MAX_RECONNECT_DELAY = 30000;

/**
 * Default maximum reconnect attempts
 */
export const DEFAULT_MAX_RECONNECT_ATTEMPTS = 5;

/**
 * Default heartbeat interval in milliseconds
 */
export const DEFAULT_HEARTBEAT_INTERVAL = 30000;

/**
 * Default maximum concurrent requests
 */
export const DEFAULT_MAX_CONCURRENT_REQUESTS = 10;

/**
 * Enclave Bridge Client
 *
 * Provides a complete TypeScript API mirroring the Swift Enclave Bridge protocol.
 *
 * @example
 * ```typescript
 * import { EnclaveBridgeClient } from '@digitaldefiance/enclave-bridge-client';
 *
 * const client = new EnclaveBridgeClient();
 * await client.connect();
 *
 * // Get the secp256k1 public key for ECIES
 * const publicKey = await client.getPublicKey();
 * console.log('Public Key:', publicKey.base64);
 *
 * // Decrypt ECIES-encrypted data
 * const plaintext = await client.decrypt(encryptedBuffer);
 *
 * // Sign with Secure Enclave
 * const signature = await client.enclaveSign(dataBuffer);
 *
 * await client.disconnect();
 * ```
 */
export class EnclaveBridgeClient extends EventEmitter {
  private socket: Socket | null = null;
  private socketPath: string;
  private timeout: number;
  private responseBuffer = '';
  
  // Request queue management
  private requestQueue: QueuedRequest[] = [];
  private activeRequests = 0;
  private maxConcurrentRequests: number;
  
  // Auto-reconnect configuration
  private autoReconnect: boolean;
  private maxReconnectAttempts: number;
  private reconnectDelay: number;
  private maxReconnectDelay: number;
  private reconnectAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  
  // Debug logging
  private debug: boolean;
  private logger?: (level: 'debug' | 'info' | 'warn' | 'error', message: string, meta?: Record<string, unknown>) => void;
  
  // Key caching
  private cacheKeys: boolean;
  private cachedPublicKey: PublicKeyInfo | null = null;
  private cachedEnclavePublicKey: PublicKeyInfo | null = null;
  
  // Heartbeat
  private enableHeartbeat: boolean;
  private heartbeatInterval: number;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private lastHeartbeat: number | null = null;
  
  // Connection tracking
  private _connectionState: ConnectionState = 'disconnected';
  private connectedAt: number | null = null;
  private isManualDisconnect = false;

  /**
   * Creates a new Enclave Bridge client
   *
   * @param options - Client configuration options
   */
  constructor(options: EnclaveBridgeClientOptions = {}) {
    super();
    this.socketPath = options.socketPath ?? DEFAULT_SOCKET_PATH;
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
    this.autoReconnect = options.autoReconnect ?? true;
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? DEFAULT_MAX_RECONNECT_ATTEMPTS;
    this.reconnectDelay = options.reconnectDelay ?? DEFAULT_RECONNECT_DELAY;
    this.maxReconnectDelay = options.maxReconnectDelay ?? DEFAULT_MAX_RECONNECT_DELAY;
    this.debug = options.debug ?? false;
    this.logger = options.logger;
    this.cacheKeys = options.cacheKeys ?? true;
    this.maxConcurrentRequests = options.maxConcurrentRequests ?? DEFAULT_MAX_CONCURRENT_REQUESTS;
    this.enableHeartbeat = options.enableHeartbeat ?? false;
    this.heartbeatInterval = options.heartbeatInterval ?? DEFAULT_HEARTBEAT_INTERVAL;
  }

  /**
   * Current connection state
   */
  get connectionState(): ConnectionState {
    return this._connectionState;
  }

  /**
   * Whether the client is currently connected
   */
  get isConnected(): boolean {
    return this._connectionState === 'connected';
  }

  /**
   * Log a debug message
   */
  private log(level: 'debug' | 'info' | 'warn' | 'error', message: string, meta?: Record<string, unknown>): void {
    if (this.logger) {
      this.logger(level, message, meta);
    } else if (this.debug || level !== 'debug') {
      const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
      console[level === 'debug' ? 'log' : level](`[EnclaveBridge:${level}] ${message}${metaStr}`);
    }
    
    if (this.debug && level === 'debug') {
      this.emit('debug', message, meta);
    }
  }

  /**
   * Check platform support
   */
  static async isSupported(socketPath: string = DEFAULT_SOCKET_PATH): Promise<PlatformSupport> {
    const plat = platform();
    const result: PlatformSupport = {
      supported: false,
      platform: plat,
      socketExists: false,
      socketPath,
    };

    // Check if macOS
    if (plat !== 'darwin') {
      result.reason = 'Enclave Bridge requires macOS';
      return result;
    }

    // Check if socket exists
    try {
      await access(socketPath, fsConstants.F_OK);
      result.socketExists = true;
      result.supported = true;
    } catch {
      result.reason = 'Enclave Bridge socket not found. Is the app running?';
    }

    return result;
  }

  /**
   * Connect to the Enclave socket server
   *
   * @returns Promise that resolves when connected
   * @throws Error if connection fails
   */
  async connect(): Promise<void> {
    if (this.socket) {
      throw new InvalidOperationError('Already connected');
    }

    this.log('info', 'Connecting to Enclave Bridge', { socketPath: this.socketPath });
    this.isManualDisconnect = false;
    this._connectionState = 'connecting';
    this.emit('stateChange', this._connectionState);

    return new Promise((resolve, reject) => {
      const connectionTimer = setTimeout(() => {
        this.socket?.destroy();
        this.socket = null;
        this._connectionState = 'disconnected';
        this.emit('stateChange', this._connectionState);
        reject(new TimeoutError(`Connection timeout after ${this.timeout}ms`, 'connect', this.timeout));
      }, this.timeout);

      this.socket = createConnection(this.socketPath, () => {
        clearTimeout(connectionTimer);
        this._connectionState = 'connected';
        this.connectedAt = Date.now();
        this.reconnectAttempts = 0;
        this.emit('stateChange', this._connectionState);
        this.emit('connect');
        
        this.log('info', 'Connected to Enclave Bridge');
        
        // Start heartbeat if enabled
        if (this.enableHeartbeat) {
          this.startHeartbeat();
        }
        
        resolve();
      });

      this.socket.setEncoding('utf8');

      this.socket.on('data', (data: string) => {
        this.handleData(data);
      });

      this.socket.on('error', (err) => {
        clearTimeout(connectionTimer);
        this.log('error', 'Socket error', { error: err.message });
        this._connectionState = 'error';
        this.emit('stateChange', this._connectionState);
        this.emit('error', new ConnectionError(err.message, { originalError: err }));

        this.rejectAllPendingRequests(err);
        reject(new ConnectionError(err.message, { originalError: err }));
      });

      this.socket.on('close', () => {
        this.log('warn', 'Socket closed');
        this.stopHeartbeat();
        this.socket = null;
        this._connectionState = 'disconnected';
        this.emit('stateChange', this._connectionState);
        this.emit('disconnect');

        this.rejectAllPendingRequests(new ConnectionError('Connection closed'));
        
        // Auto-reconnect if enabled and not manually disconnected
        if (this.autoReconnect && !this.isManualDisconnect) {
          this.scheduleReconnect();
        }
      });
    });
  }

  /**
   * Schedule a reconnection attempt
   */
  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      const error = new ConnectionError(
        `Failed to reconnect after ${this.maxReconnectAttempts} attempts`,
        { reconnectAttempts: this.reconnectAttempts }
      );
      this.log('error', 'Reconnection failed', { attempts: this.reconnectAttempts });
      this.emit('reconnectFailed', error);
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1),
      this.maxReconnectDelay
    );

    this.log('info', 'Scheduling reconnection', { 
      attempt: this.reconnectAttempts, 
      maxAttempts: this.maxReconnectAttempts,
      delay 
    });

    this._connectionState = 'reconnecting';
    this.emit('stateChange', this._connectionState);
    this.emit('reconnecting', this.reconnectAttempts, this.maxReconnectAttempts);

    this.reconnectTimer = setTimeout(async () => {
      try {
        await this.connect();
        this.emit('reconnected');
        this.log('info', 'Reconnected successfully');
      } catch (err) {
        this.log('warn', 'Reconnection attempt failed', { 
          attempt: this.reconnectAttempts,
          error: err instanceof Error ? err.message : String(err)
        });
        this.scheduleReconnect();
      }
    }, delay);
  }

  /**
   * Reject all pending requests with an error
   */
  private rejectAllPendingRequests(error: Error): void {
    for (const request of this.requestQueue) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    this.requestQueue = [];
    this.activeRequests = 0;
  }

  /**
   * Disconnect from the EnclaveBridge socket server
   */
  async disconnect(): Promise<void> {
    if (!this.socket) {
      return;
    }

    this.log('info', 'Disconnecting from Enclave Bridge');
    this.isManualDisconnect = true;
    this.emit('beforeDisconnect');
    
    // Stop heartbeat
    this.stopHeartbeat();
    
    // Clear reconnect timer
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    
    // Clear caches
    this.invalidateCache();

    return new Promise((resolve) => {
      this.socket!.once('close', () => {
        resolve();
      });
      this.socket!.end();
    });
  }

  /**
   * Start heartbeat/keepalive
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(async () => {
      try {
        await this.heartbeat();
        this.lastHeartbeat = Date.now();
        this.log('debug', 'Heartbeat successful');
      } catch (err) {
        this.log('warn', 'Heartbeat failed', { 
          error: err instanceof Error ? err.message : String(err) 
        });
      }
    }, this.heartbeatInterval);
  }

  /**
   * Stop heartbeat
   */
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Invalidate cached keys
   */
  private invalidateCache(): void {
    this.cachedPublicKey = null;
    this.cachedEnclavePublicKey = null;
  }

  /**
   * Handle incoming data from the socket
   *
   * The Swift server sends JSON responses without newlines,
   * so we parse complete JSON objects by tracking braces.
   */
  private handleData(data: string): void {
    this.responseBuffer += data;
    this.log('debug', 'Received data', { length: data.length });

    // Try to parse complete JSON objects
    let startIndex = 0;
    while (startIndex < this.responseBuffer.length) {
      const jsonStart = this.responseBuffer.indexOf('{', startIndex);
      if (jsonStart === -1) {
        this.responseBuffer = this.responseBuffer.substring(startIndex);
        return;
      }

      // Find matching closing brace
      let braceCount = 0;
      let inString = false;
      let escaped = false;
      let jsonEnd = -1;

      for (let i = jsonStart; i < this.responseBuffer.length; i++) {
        const char = this.responseBuffer[i];

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
            braceCount++;
          } else if (char === '}') {
            braceCount--;
            if (braceCount === 0) {
              jsonEnd = i;
              break;
            }
          }
        }
      }

      if (jsonEnd === -1) {
        // Incomplete JSON, wait for more data
        this.responseBuffer = this.responseBuffer.substring(jsonStart);
        return;
      }

      // Extract complete JSON
      const jsonStr = this.responseBuffer.substring(jsonStart, jsonEnd + 1);
      startIndex = jsonEnd + 1;

      this.log('debug', 'Parsed response', { response: jsonStr });
      this.emit('responseReceived', jsonStr);

      // Find the first request that was actually sent (not just queued)
      const sentRequestIndex = this.requestQueue.findIndex((r) => r.sent);
      if (sentRequestIndex !== -1) {
        const request = this.requestQueue[sentRequestIndex];
        clearTimeout(request.timer);
        this.activeRequests--;
        request.resolve(jsonStr);
        
        // Remove the resolved request from queue
        this.requestQueue.splice(sentRequestIndex, 1);
        
        // Process next queued request if any
        this.processQueue();
      }
    }

    this.responseBuffer = this.responseBuffer.substring(startIndex);
  }

  /**
   * Process the next request in the queue
   */
  private processQueue(): void {
    if (this.activeRequests >= this.maxConcurrentRequests || this.requestQueue.length === 0) {
      return;
    }

    // Find the first unsent request
    const request = this.requestQueue.find((r) => !r.sent);
    if (!request) return;

    this.activeRequests++;
    request.sent = true;
    this.sendRequestToSocket(request.command, request.payload);
  }

  /**
   * Send request directly to socket
   */
  private sendRequestToSocket(command: string, payload?: Record<string, string>): void {
    const request: Record<string, string> = { cmd: command, ...payload };
    const message = JSON.stringify(request);
    
    this.log('debug', 'Sending request', { command, payload });
    this.emit('requestSent', command, payload);
    
    this.socket!.write(message);
  }

  /**
   * Send a command to the bridge and wait for response
   *
   * Protocol format: JSON object with "cmd" field and optional data fields
   * Example: {"cmd":"GET_PUBLIC_KEY"}
   * Example: {"cmd":"ENCLAVE_SIGN","data":"base64data"}
   *
   * @param command - The command to send
   * @param payload - Optional payload object to include in the request
   * @returns Promise resolving to the response string (JSON)
   */
  private async sendCommand(command: string, payload?: Record<string, string>): Promise<string> {
    if (!this.socket || !this.isConnected) {
      throw new InvalidOperationError('Not connected to EnclaveBridge');
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.requestQueue.findIndex((r) => r.resolve === resolve);
        if (index !== -1) {
          this.requestQueue.splice(index, 1);
        }
        reject(new TimeoutError(`Request timeout after ${this.timeout}ms`, command, this.timeout));
      }, this.timeout);

      const request: QueuedRequest = {
        command,
        payload,
        resolve,
        reject,
        timer,
        timestamp: Date.now(),
        sent: false,
      };

      this.requestQueue.push(request);
      
      // Try to process immediately if under concurrency limit
      if (this.activeRequests < this.maxConcurrentRequests) {
        this.processQueue();
      }
    });
  }

  /**
   * Parse the bridge response
   *
   * Protocol format: JSON object with either data fields or "error" field
   * Success: {"publicKey":"..."}  or {"ok":true} or {"signature":"..."} etc.
   * Error: {"error":"message"}
   *
   * @param response - Raw JSON response string
   * @returns Parsed response object
   */
  private parseResponse(response: string): BridgeResponse & { json?: Record<string, unknown> } {
    try {
      const json = JSON.parse(response) as Record<string, unknown>;

      if ('error' in json && typeof json.error === 'string') {
        return { success: false, error: json.error };
      }

      return { success: true, json };
    } catch (err) {
      throw new ProtocolError(`Invalid JSON response: ${response}`, { 
        response, 
        parseError: err instanceof Error ? err.message : String(err) 
      });
    }
  }

  // ============================================================================
  // Public Key Operations
  // ============================================================================

  /**
   * Get the secp256k1 public key used for ECIES operations
   *
   * This key is used for ECIES encryption/decryption and is persisted
   * in the macOS Keychain.
   *
   * @param skipCache - Skip cache and fetch fresh key
   * @returns Promise resolving to the public key info
   */
  async getPublicKey(skipCache = false): Promise<PublicKeyInfo> {
    if (this.cacheKeys && !skipCache && this.cachedPublicKey) {
      this.log('debug', 'Returning cached public key');
      return this.cachedPublicKey;
    }

    const response = await this.sendCommand('GET_PUBLIC_KEY');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to get public key: ${parsed.error}`);
    }

    const base64Key = parsed.json.publicKey as string;
    if (!base64Key) {
      throw new ProtocolError('Response missing publicKey field');
    }

    const buffer = Buffer.from(base64Key, 'base64');

    const result: PublicKeyInfo = {
      base64: base64Key,
      buffer,
      hex: buffer.toString('hex'),
      compressed: buffer.length === 33,
    };

    if (this.cacheKeys) {
      this.cachedPublicKey = result;
    }

    return result;
  }

  /**
   * Get the Secure Enclave P-256 public key
   *
   * This key is stored in the Apple Secure Enclave and can only be
   * used for signing operations. The private key never leaves the
   * Secure Enclave.
   *
   * @param skipCache - Skip cache and fetch fresh key
   * @returns Promise resolving to the Secure Enclave public key info
   */
  async getEnclavePublicKey(skipCache = false): Promise<PublicKeyInfo> {
    if (this.cacheKeys && !skipCache && this.cachedEnclavePublicKey) {
      this.log('debug', 'Returning cached Enclave public key');
      return this.cachedEnclavePublicKey;
    }

    const response = await this.sendCommand('GET_ENCLAVE_PUBLIC_KEY');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to get Enclave public key: ${parsed.error}`);
    }

    const base64Key = parsed.json.publicKey as string;
    if (!base64Key) {
      throw new ProtocolError('Response missing publicKey field');
    }

    const buffer = Buffer.from(base64Key, 'base64');

    const result: PublicKeyInfo = {
      base64: base64Key,
      buffer,
      hex: buffer.toString('hex'),
      compressed: buffer.length === 33, // P-256 keys are typically uncompressed (65 bytes)
    };

    if (this.cacheKeys) {
      this.cachedEnclavePublicKey = result;
    }

    return result;
  }

  /**
   * Set the peer's public key for ECDH operations
   *
   * This stores the peer's secp256k1 public key for deriving shared secrets.
   *
   * @param publicKey - The peer's public key (base64, hex, or Buffer)
   */
  async setPeerPublicKey(publicKey: string | Buffer): Promise<void> {
    let keyBuffer: Buffer;

    if (Buffer.isBuffer(publicKey)) {
      keyBuffer = publicKey;
    } else if (typeof publicKey === 'string') {
      // Try to detect format
      if (publicKey.length === 66 || publicKey.length === 130) {
        // Likely hex (33 or 65 bytes)
        keyBuffer = Buffer.from(publicKey, 'hex');
      } else {
        // Assume base64
        keyBuffer = Buffer.from(publicKey, 'base64');
      }
    } else {
      throw new InvalidOperationError('Public key must be a string or Buffer');
    }

    const response = await this.sendCommand('SET_PEER_PUBLIC_KEY', {
      publicKey: keyBuffer.toString('base64'),
    });
    const parsed = this.parseResponse(response);

    if (!parsed.success) {
      throw new ProtocolError(`Failed to set peer public key: ${parsed.error}`);
    }
  }

  // ============================================================================
  // Secure Enclave Operations
  // ============================================================================

  /**
   * Sign data using the Secure Enclave P-256 key
   *
   * The private key never leaves the Secure Enclave - all signing
   * operations are performed within the secure hardware.
   *
   * @param data - Data to sign (will be hashed with SHA-256 first)
   * @returns Promise resolving to the signature
   */
  async enclaveSign(data: Buffer | string): Promise<SignatureResult> {
    const dataBuffer = typeof data === 'string' ? Buffer.from(data) : data;
    const response = await this.sendCommand('ENCLAVE_SIGN', {
      data: dataBuffer.toString('base64'),
    });
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to sign: ${parsed.error}`);
    }

    const signatureBase64 = parsed.json.signature as string;
    if (!signatureBase64) {
      throw new ProtocolError('Response missing signature field');
    }

    const signatureBuffer = Buffer.from(signatureBase64, 'base64');

    return {
      base64: signatureBase64,
      buffer: signatureBuffer,
      hex: signatureBuffer.toString('hex'),
      // P-256 signatures are typically DER encoded
      format: 'der',
    };
  }

  /**
   * Decrypt ECIES-encrypted data
   *
   * Uses the secp256k1 key to perform ECDH and decrypt the data.
   * Compatible with @digitaldefiance/node-ecies-lib format:
   * - version (1 byte)
   * - cipher suite (1 byte)
   * - encryption type (1 byte): 33=Basic, 66=WithLength, 99=Multiple
   * - ephemeral public key (33 bytes, compressed)
   * - IV (12 bytes)
   * - auth tag (16 bytes)
   * - ciphertext (variable)
   *
   * @param encryptedData - ECIES encrypted data
   * @returns Promise resolving to the decrypted data
   */
  async decrypt(encryptedData: Buffer): Promise<DecryptionResult> {
    const response = await this.sendCommand('ENCLAVE_DECRYPT', {
      data: encryptedData.toString('base64'),
    });
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to decrypt: ${parsed.error}`);
    }

    const plaintextBase64 = parsed.json.plaintext as string;
    if (!plaintextBase64) {
      throw new ProtocolError('Response missing plaintext field');
    }

    const plaintextBuffer = Buffer.from(plaintextBase64, 'base64');

    return {
      base64: plaintextBase64,
      buffer: plaintextBuffer,
      text: plaintextBuffer.toString('utf8'),
    };
  }

  /**
   * Alias for decrypt() to match the Swift API naming
   *
   * @param encryptedData - ECIES encrypted data
   * @returns Promise resolving to the decrypted data
   */
  async enclaveDecrypt(encryptedData: Buffer): Promise<DecryptionResult> {
    return this.decrypt(encryptedData);
  }

  /**
   * Encrypt data using ECIES (client-side)
   * 
   * This performs encryption locally without contacting the bridge.
   * Requires @digitaldefiance/node-ecies-lib to be installed.
   * 
   * @param data - Data to encrypt
   * @param recipientPublicKey - Optional recipient public key (defaults to bridge's key)
   * @returns Promise resolving to encrypted data
   */
  async encrypt(data: Buffer | string, recipientPublicKey?: Buffer): Promise<Buffer> {
    const { encrypt: encryptFn } = await import('./crypto.js');
    const pubKey = recipientPublicKey ?? (await this.getPublicKey()).buffer;
    return encryptFn(pubKey, data);
  }

  /**
   * Verify a signature from the Secure Enclave
   * 
   * @param data - Original data that was signed
   * @param signature - Signature to verify
   * @param publicKey - Optional public key (defaults to Enclave public key)
   * @returns Promise resolving to true if signature is valid
   */
  async verifySignature(
    data: Buffer | string,
    signature: Buffer,
    publicKey?: Buffer
  ): Promise<boolean> {
    const { verifyP256Signature } = await import('./crypto.js');
    const pubKey = publicKey ?? (await this.getEnclavePublicKey()).buffer;
    return verifyP256Signature(data, signature, pubKey);
  }

  // ============================================================================
  // Key Generation
  // ============================================================================

  /**
   * Generate a new key in the Secure Enclave
   *
   * Note: This generates a new ephemeral key, not a replacement for
   * the main Secure Enclave key.
   *
   * @returns Promise resolving to the generated key info
   */
  async enclaveGenerateKey(): Promise<KeyGenerationResult> {
    const response = await this.sendCommand('ENCLAVE_GENERATE_KEY');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to generate key: ${parsed.error}`);
    }

    const publicKeyBase64 = parsed.json.publicKey as string;
    if (!publicKeyBase64) {
      throw new ProtocolError('Response missing publicKey field');
    }

    const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');

    return {
      publicKey: {
        base64: publicKeyBase64,
        buffer: publicKeyBuffer,
        hex: publicKeyBuffer.toString('hex'),
        compressed: publicKeyBuffer.length === 33,
      },
    };
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Check if the EnclaveBridge server is reachable
   *
   * @returns Promise resolving to true if reachable
   */
  async ping(): Promise<boolean> {
    try {
      await this.getPublicKey();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Send a heartbeat to the server
   * 
   * @returns Promise resolving to heartbeat response
   */
  async heartbeat(): Promise<HeartbeatResponse> {
    const response = await this.sendCommand('HEARTBEAT');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Heartbeat failed: ${parsed.error}`);
    }

    const hbResponse = parsed.json as Record<string, unknown>;
    if (!hbResponse.ok) {
      throw new ProtocolError('Heartbeat returned ok: false');
    }

    return {
      ok: hbResponse.ok as boolean,
      timestamp: (hbResponse.timestamp as string) ?? new Date().toISOString(),
      service: (hbResponse.service as string) ?? 'enclave-bridge',
    };
  }

  /**
   * Get server version information
   * 
   * @returns Promise resolving to version info
   */
  async getVersion(): Promise<ServerVersion> {
    const response = await this.sendCommand('VERSION');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to get version: ${parsed.error}`);
    }

    const version = parsed.json;
    return {
      appVersion: (version.appVersion as string) ?? 'unknown',
      build: (version.build as string) ?? 'unknown',
      platform: (version.platform as string) ?? 'unknown',
      uptimeSeconds: (version.uptimeSeconds as number) ?? 0,
    };
  }

  /**
   * Get server status
   * 
   * @returns Promise resolving to server status
   */
  async getStatus(): Promise<ServerStatus> {
    const response = await this.sendCommand('STATUS');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to get status: ${parsed.error}`);
    }

    const status = parsed.json;
    return {
      ok: (status.ok as boolean) ?? false,
      peerPublicKeySet: (status.peerPublicKeySet as boolean) ?? false,
      enclaveKeyAvailable: (status.enclaveKeyAvailable as boolean) ?? false,
    };
  }

  /**
   * Get server metrics
   * 
   * @returns Promise resolving to server metrics
   */
  async getMetrics(): Promise<ServerMetrics> {
    const response = await this.sendCommand('METRICS');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to get metrics: ${parsed.error}`);
    }

    const metrics = parsed.json;
    return {
      service: (metrics.service as string) ?? 'enclave-bridge',
      uptimeSeconds: (metrics.uptimeSeconds as number) ?? 0,
      requestCounters: (metrics.requestCounters as Record<string, number>) ?? {},
    };
  }

  /**
   * List available keys on the server
   * 
   * @returns Promise resolving to available keys
   */
  async listKeys(): Promise<KeyList> {
    const response = await this.sendCommand('LIST_KEYS');
    const parsed = this.parseResponse(response);

    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`Failed to list keys: ${parsed.error}`);
    }

    const keyList = parsed.json;
    return {
      ecies: (keyList.ecies as Array<{ id: string; publicKey: string }>) ?? [],
      enclave: (keyList.enclave as Array<{ id: string; publicKey: string }>) ?? [],
    };
  }

  /**
   * Rotate Secure Enclave key (if supported)
   * 
   * @returns Promise resolving when key rotation completes
   */
  async rotateKey(): Promise<void> {
    const response = await this.sendCommand('ENCLAVE_ROTATE_KEY');
    const parsed = this.parseResponse(response);

    if (!parsed.success) {
      throw new ProtocolError(`Failed to rotate key: ${parsed.error}`);
    }
  }

  /**
   * Get health status information
   *
   * @returns Health status object
   */
  getHealthStatus(): HealthStatus {
    const uptime = this.connectedAt ? Date.now() - this.connectedAt : 0;
    
    return {
      healthy: this.isConnected,
      state: this._connectionState,
      uptime,
      activeRequests: this.activeRequests,
      queuedRequests: this.requestQueue.length,
      lastHeartbeat: this.lastHeartbeat ?? undefined,
      reconnectAttempts: this.reconnectAttempts,
    };
  }

  /**
   * Get connection information
   *
   * @returns Connection info object
   */
  getConnectionInfo(): {
    socketPath: string;
    state: ConnectionState;
    isConnected: boolean;
  } {
    return {
      socketPath: this.socketPath,
      state: this._connectionState,
      isConnected: this.isConnected,
    };
  }
}

/**
 * Create and connect an EnclaveBridge client
 *
 * @param options - Client configuration options
 * @returns Promise resolving to a connected client
 *
 * @example
 * ```typescript
 * const client = await createClient();
 * const publicKey = await client.getPublicKey();
 * await client.disconnect();
 * ```
 */
export async function createClient(options?: EnclaveBridgeClientOptions): Promise<EnclaveBridgeClient> {
  const client = new EnclaveBridgeClient(options);
  await client.connect();
  return client;
}

// Default export
export default EnclaveBridgeClient;
