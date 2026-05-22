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
export * from './brightlink.js';

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
  KeyInfo,
  HeartbeatResponse,
  LinkSession,
  LinkRegisterOptions,
  LinkCoordinateFormat,
  LinkGeoStatusResponse,
  LinkGeoProximityResponse,
  LinkGeoZoneResponse,
  LinkGeoGetResponse,
  LinkGeoRefreshResponse,
  LinkGeoRefreshOptions,
  LinkPushEvent,
  LinkPushEventName,
  LinkPushSubscription,
} from './types.js';

import {
  ConnectionError,
  TimeoutError,
  InvalidOperationError,
  ProtocolError,
  PlatformError,
} from './errors.js';

import {
  buildLinkRegisterEnvelope,
  decryptLinkResponseEnvelope,
  deriveSessionKey,
  buildTranscript,
  verifyTranscriptSignature,
  buildPushAad,
  LINK_SESSION_ID_LENGTH,
  LINK_SHARE_LENGTH,
} from './brightlink.js';
import { createDecipheriv } from 'node:crypto';

/**
 * Default socket path for BrightNexus (canonical BrightLink path).
 *
 * RFC §15 (Compatibility posture): this is the only path. Legacy
 * `~/.enclave/enclave-bridge.sock` and `/tmp/enclave-bridge.sock` are
 * NOT honored.
 */
export const DEFAULT_SOCKET_PATH =
  `${process.env.HOME ?? ''}/.brightchain/brightnexus/brightnexus.sock`;

/**
 * Environment variable that overrides the default socket path. Reserved
 * name; v3-aware deployments set this to point at a non-default bridge
 * (e.g. a test instance).
 */
export const BRIGHTNEXUS_SOCKET_ENV_VAR = 'BRIGHTNEXUS_SOCKET';

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
      /**
       * Export key material (public key) with optional TOTP code
       * @param keyId - Key identifier
       * @param totpCode - Optional TOTP code (if required)
       * @returns Promise resolving to public key info
       */
      async exportKey(keyId: string, totpCode?: string): Promise<PublicKeyInfo> {
        const payload: Record<string, string> = { keyId };
        if (totpCode) payload.totpCode = totpCode;
        const response = await this.sendCommand('EXPORT_KEY', payload);
        const parsed = this.parseResponse(response);
        if (!parsed.success || !parsed.json) {
          throw new ProtocolError(`Failed to export key: ${parsed.error}`);
        }
        const base64Key = parsed.json.publicKey as string;
        if (!base64Key) {
          throw new ProtocolError('Response missing publicKey field');
        }
        const buffer = Buffer.from(base64Key, 'base64');
        return {
          base64: base64Key,
          buffer,
          hex: buffer.toString('hex'),
          compressed: buffer.length === 33,
        };
      }
    /**
     * Enable TOTP for a key
     * @param keyId - Key identifier
     * @param account - Account name (e.g., user email)
     * @param issuer - Issuer name (e.g., app name)
     * @returns Promise resolving to provisioning URI
     */
    async enableTOTP(keyId: string, account: string, issuer: string): Promise<string> {
      const response = await this.sendCommand('ENABLE_TOTP', { keyId, account, issuer });
      const parsed = this.parseResponse(response);
      if (!parsed.success || !parsed.json) {
        throw new ProtocolError(`Failed to enable TOTP: ${parsed.error}`);
      }
      const uri = parsed.json.provisioningURI as string;
      if (!uri) {
        throw new ProtocolError('Response missing provisioningURI field');
      }
      return uri;
    }
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

  // BrightLink v1 (RFC §4.5)
  /**
   * Currently registered BrightLink session, or null if not registered. Set by
   * `linkRegister()`, cleared by `disconnect()` or by re-registration.
   */
  linkSession: LinkSession | null = null;

  /**
   * Active LINK_PUSH subscribers on this client. The data handler dispatches
   * incoming push frames to each subscriber whose `events` set includes the
   * frame's event name. Per RFC §10.4 there is no `unsubscribe` verb —
   * disconnecting the socket is the only way to fully tear down a
   * subscription. Subscriber `close()` simply detaches the local handler;
   * the bridge will keep emitting frames for the lifetime of the connection.
   */
  private linkPushSubscribers: Array<{
    events: Set<string>;
    onPayload: (event: LinkPushEvent) => void;
    onError?: (err: Error, raw: Record<string, unknown>) => void;
  }> = [];
  /**
   * TOFU-pinned SEP public key (RFC §4.5.5). On first successful
   * `linkRegister()`, the bridge's SEP public key is captured here. On
   * subsequent registrations, the SEP key MUST byte-match this pin or
   * the registration is rejected. Callers MAY explicitly set this from
   * persisted storage to enforce a pin across process lifetimes.
   */
  pinnedSepPublicKey: Buffer | null = null;

  /**
   * Creates a new Enclave Bridge client
   *
   * @param options - Client configuration options
   */
  constructor(options: EnclaveBridgeClientOptions = {}) {
    super();
    // Socket path resolution order:
    //   1. Explicit options.socketPath
    //   2. $BRIGHTNEXUS_SOCKET environment variable
    //   3. ~/.brightchain/brightnexus/brightnexus.sock (canonical default)
    // RFC §15: there are no legacy fallbacks.
    this.socketPath =
      options.socketPath ??
      process.env[BRIGHTNEXUS_SOCKET_ENV_VAR] ??
      DEFAULT_SOCKET_PATH;
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

      // BrightLink v1.1 §10 push frame? These arrive asynchronously over
      // the same socket as request responses but are NOT replies to any
      // pending request. We detect them by the presence of the AAD-shaped
      // (event, iv, ciphertext, authTag) tuple — the subscribe-ack frame
      // (`{ok:true, subscribed:[...]}`) does not carry those fields and
      // is handled as a normal response below.
      let parsedJson: Record<string, unknown> | null = null;
      try {
        parsedJson = JSON.parse(jsonStr) as Record<string, unknown>;
      } catch {
        // Malformed JSON — fall through and let the resolver path
        // (or the next-data accumulation) handle it.
      }
      if (
        parsedJson !== null &&
        typeof parsedJson['event'] === 'string' &&
        typeof parsedJson['iv'] === 'string' &&
        typeof parsedJson['ciphertext'] === 'string' &&
        typeof parsedJson['authTag'] === 'string'
      ) {
        this.dispatchPushFrame(parsedJson);
        continue;
      }

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
   * Send request directly to socket.
   *
   * Payload values may be strings, numbers, booleans, or — to support the
   * BrightLink v1.1 surface — arrays of those primitives (e.g. the
   * `subscribe: ["zone-transition"]` array on `LINK_PUSH`).
   */
  private sendRequestToSocket(
    command: string,
    payload?: Record<string, unknown>,
  ): void {
    const request: Record<string, unknown> = {
      cmd: command,
      ...payload,
    };
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
  private async sendCommand(
    command: string,
    payload?: Record<string, unknown>,
  ): Promise<string> {
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
      keys: (keyList.keys as KeyInfo[]) ?? [],
    };
  }

  // ──────────────────────────────────────────────────────────────────────
  // BrightLink v1 — see docs/rfc-brightlink.md
  // ──────────────────────────────────────────────────────────────────────

  /**
   * Establish a BrightLink session against the connected bridge.
   *
   * The handshake flow (RFC §4.5):
   *
   *   1. Fetch the bridge's persistent secp256k1 ECIES public key
   *      (`GET_PUBLIC_KEY`) and SEP P-256 public key
   *      (`GET_ENCLAVE_PUBLIC_KEY`).
   *   2. If `pinnedSepPublicKey` is set, verify the bridge's SEP key
   *      byte-matches the pin (TOFU per §4.5.5). On mismatch, throw.
   *   3. Build the §4.5.1 plaintext envelope (clientPub, clientShare,
   *      issuedAtBd, ttlSeconds, agent), ECIES-encrypt it to the bridge.
   *   4. Send `LINK_REGISTER` with the envelope + a fresh clientNonce.
   *   5. Decrypt the bridge's `responseEnvelope` to recover bridgeShare.
   *   6. Derive K_session via the §4.5.2 bilateral HKDF.
   *   7. Reconstruct the §4.5.3 canonical 234-byte transcript and verify
   *      the bridge's `transcriptSig` against the SEP public key.
   *   8. On success, populate `this.linkSession` and pin the SEP key on
   *      first registration.
   *
   * Throws `InvalidOperationError` if already registered on this client.
   * Throws `ProtocolError` on bridge errors or signature verification failure.
   *
   * @example
   *   const session = await client.linkRegister({ ttlSeconds: 600 });
   *   // session.sessionId, session.kSession, etc. are now available.
   *
   * @returns The newly established session (also stored on `this.linkSession`).
   */
  async linkRegister(options: LinkRegisterOptions = {}): Promise<LinkSession> {
    if (this.linkSession !== null) {
      throw new InvalidOperationError(
        'Already registered on this connection — call disconnect()/reconnect or null linkSession to re-register',
      );
    }
    if (!this.isConnected) {
      throw new InvalidOperationError(
        'Cannot register: client is not connected. Call connect() first.',
      );
    }

    // Fetch keys.
    const bridgePubInfo = await this.getPublicKey();
    if (bridgePubInfo.buffer.length !== 65 || bridgePubInfo.buffer[0] !== 0x04) {
      throw new ProtocolError(
        `Bridge GET_PUBLIC_KEY returned non-uncompressed key (${bridgePubInfo.buffer.length} bytes, prefix 0x${bridgePubInfo.buffer[0].toString(16)}); RFC §4.5 requires 65-byte uncompressed`,
      );
    }
    const sepPubInfo = await this.getEnclavePublicKey();
    if (sepPubInfo.buffer.length !== 65 || sepPubInfo.buffer[0] !== 0x04) {
      throw new ProtocolError(
        `Bridge GET_ENCLAVE_PUBLIC_KEY returned non-uncompressed key (${sepPubInfo.buffer.length} bytes); RFC §4.6 requires 65-byte uncompressed X9.63`,
      );
    }

    // TOFU pinning per §4.5.5.
    if (this.pinnedSepPublicKey && !this.pinnedSepPublicKey.equals(sepPubInfo.buffer)) {
      throw new ProtocolError(
        'SEP public key changed since pinned — refusing registration (TOFU mismatch)',
      );
    }

    // Build the §4.5.1 envelope.
    const built = buildLinkRegisterEnvelope(bridgePubInfo.buffer, {
      ttlSeconds: options.ttlSeconds,
      issuedAtBd: options.issuedAtBd,
      agent: options.agentInfo,
    });

    // Send LINK_REGISTER. The existing `sendCommand` helper takes a flat
    // record of strings; we pass the entire request payload that way.
    // (`cmd` is set inline by `sendRequestToSocket`; we strip it from
    // the flat payload before passing it on.)
    const { cmd: _ignored, ...payload } = built.request;
    void _ignored;
    const response = await this.sendCommand('LINK_REGISTER', {
      protocolVersion: payload.protocolVersion,
      clientNonce: payload.clientNonce,
      envelope: payload.envelope,
    });
    const parsed = this.parseResponse(response);
    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`LINK_REGISTER failed: ${parsed.error}`);
    }

    // Validate response shape.
    const respObj = parsed.json as Record<string, unknown>;
    const sessionIdStr = respObj['sessionId'];
    const respEnvelopeStr = respObj['responseEnvelope'];
    const transcriptSigStr = respObj['transcriptSig'];
    const bridgeIssuedAtUnixRaw = respObj['bridgeIssuedAtUnix'];
    const grantedTtlSecondsRaw = respObj['ttlSeconds'];

    if (
      typeof sessionIdStr !== 'string' ||
      typeof respEnvelopeStr !== 'string' ||
      typeof transcriptSigStr !== 'string' ||
      typeof bridgeIssuedAtUnixRaw !== 'number' ||
      typeof grantedTtlSecondsRaw !== 'number'
    ) {
      throw new ProtocolError('LINK_REGISTER response is missing required fields');
    }

    const sessionId = Buffer.from(sessionIdStr, 'base64');
    if (sessionId.length !== LINK_SESSION_ID_LENGTH) {
      throw new ProtocolError(
        `sessionId is not ${LINK_SESSION_ID_LENGTH} bytes (got ${sessionId.length})`,
      );
    }
    const transcriptSig = Buffer.from(transcriptSigStr, 'base64');
    const responseEnvelope = Buffer.from(respEnvelopeStr, 'base64');
    const bridgeIssuedAtUnix = bridgeIssuedAtUnixRaw;
    const grantedTtlSeconds = grantedTtlSecondsRaw;

    // Decrypt responseEnvelope to recover bridgeShare.
    let bridgeShare: Buffer;
    try {
      bridgeShare = decryptLinkResponseEnvelope(responseEnvelope, built.ephemeralPriv);
    } catch (err) {
      throw new ProtocolError(
        `Failed to decrypt bridge responseEnvelope: ${(err as Error).message}`,
      );
    }
    if (bridgeShare.length !== LINK_SHARE_LENGTH) {
      throw new ProtocolError(
        `bridgeShare is not ${LINK_SHARE_LENGTH} bytes (got ${bridgeShare.length})`,
      );
    }

    // Derive K_session.
    const kSession = deriveSessionKey({
      clientNonce: built.clientNonce,
      sessionId,
      clientShare: built.clientShare,
      bridgeShare,
    });

    // Reconstruct transcript and verify SEP signature.
    const transcript = buildTranscript({
      clientNonce: built.clientNonce,
      clientPub: built.ephemeralPub,
      clientShare: built.clientShare,
      sessionId,
      bridgeShare,
      issuedAtBd: built.issuedAtBd,
      bridgeIssuedAtUnix,
      ttlSeconds: grantedTtlSeconds,
    });
    if (!verifyTranscriptSignature(sepPubInfo.buffer, transcript, transcriptSig)) {
      throw new ProtocolError(
        'Transcript signature verification failed — bridge identity not authenticated',
      );
    }

    // Pin the SEP public key on first successful registration (TOFU).
    if (!this.pinnedSepPublicKey) {
      this.pinnedSepPublicKey = Buffer.from(sepPubInfo.buffer);
    }

    // Build the public session record.
    const session: LinkSession = {
      sessionId,
      kSession,
      bridgeIssuedAtUnix,
      ttlSeconds: grantedTtlSeconds,
      expiresAtUnix: bridgeIssuedAtUnix + grantedTtlSeconds,
      sepPublicKey: Buffer.from(sepPubInfo.buffer),
      outboundCounter: 0n,
      lastInboundCounter: 0n,
    };
    this.linkSession = session;

    // Wipe sensitive intermediates.
    bridgeShare.fill(0);
    built.ephemeralPriv.fill(0);

    this.log('info', `[brightlink] Registered session ${sessionId.toString('hex')} (ttl=${grantedTtlSeconds}s)`);
    return session;
  }

  /**
   * Clear the current BrightLink session, zeroizing K_session. Safe to call
   * even if no session is active. Intended for callers that want to
   * tear down a session without disconnecting the EBP/1 transport.
   */
  linkUnregister(): void {
    if (this.linkSession) {
      this.linkSession.kSession.fill(0);
      this.log('info', `[brightlink] Cleared session ${this.linkSession.sessionId.toString('hex')}`);
      this.linkSession = null;
    }
    // Drop any push subscriptions — they're tied to the session.
    this.linkPushSubscribers = [];
  }

  // ──────────────────────────────────────────────────────────────────────
  // BrightLink v1.1 — geo command surface (RFC §9)
  //
  // Each method requires a registered `LINK_REGISTER` session on this
  // connection (call `linkRegister()` first). Response shapes match
  // RFC §9.{1..5} with snake_case keys converted to camelCase for the
  // TypeScript surface.
  // ──────────────────────────────────────────────────────────────────────

  /**
   * §9.1 LINK_GEO_STATUS — alive + fix age, no scope gate.
   *
   * The only geo command that bypasses the ACL. Carries no location data,
   * just liveness and accuracy. Use this to gate "is geo even available?"
   * before asking for higher-friction scopes.
   */
  async linkGeoStatus(): Promise<LinkGeoStatusResponse> {
    const response = await this.sendCommand('LINK_GEO_STATUS');
    const parsed = this.parseResponse(response);
    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`LINK_GEO_STATUS failed: ${parsed.error}`);
    }
    const r = parsed.json;
    return {
      alive: Boolean(r['alive']),
      engineKind: String(r['engine_kind'] ?? ''),
      fixAgeSeconds:
        typeof r['fix_age_seconds'] === 'number' ? r['fix_age_seconds'] : null,
      accuracyM:
        typeof r['accuracy_m'] === 'number' ? r['accuracy_m'] : null,
    };
  }

  /**
   * §9.2 LINK_GEO_PROXIMITY — yes/no for a named zone.
   *
   * The lowest-friction zone query: the caller MUST name the zone they
   * want to know about, and the bridge does not enumerate zones in the
   * response. A caller cannot use this to discover what zones exist —
   * they can only confirm or deny membership in a zone they already know
   * by name. Gated by the `geo:proximity` scope.
   *
   * @param zoneId The id of the zone to test against (e.g. `"zone-prod-office"`).
   */
  async linkGeoProximity(zoneId: string): Promise<LinkGeoProximityResponse> {
    if (!zoneId) {
      throw new InvalidOperationError('linkGeoProximity requires a non-empty zone id');
    }
    const response = await this.sendCommand('LINK_GEO_PROXIMITY', { zone: zoneId });
    const parsed = this.parseResponse(response);
    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`LINK_GEO_PROXIMITY failed: ${parsed.error}`);
    }
    const r = parsed.json;
    return {
      inZone: Boolean(r['in_zone']),
      brightdate:
        typeof r['brightdate'] === 'number' ? r['brightdate'] : 0,
    };
  }

  /**
   * §9.3 LINK_GEO_ZONE — current zone identifier and dwell duration.
   *
   * Returns the highest-priority current zone (RFC §8) and the duration
   * since the last zone change. Returns `zone: null` when no zone matches.
   * Gated by the `geo:zone` scope.
   */
  async linkGeoZone(): Promise<LinkGeoZoneResponse> {
    const response = await this.sendCommand('LINK_GEO_ZONE');
    const parsed = this.parseResponse(response);
    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`LINK_GEO_ZONE failed: ${parsed.error}`);
    }
    const r = parsed.json;
    return {
      zone: typeof r['zone'] === 'string' ? r['zone'] : null,
      dwellSeconds:
        typeof r['dwell_seconds'] === 'number' ? r['dwell_seconds'] : 0,
      brightdate:
        typeof r['brightdate'] === 'number' ? r['brightdate'] : 0,
    };
  }

  /**
   * §9.4 LINK_GEO_GET — full position.
   *
   * Returns `{position: {wgs84?, brightspace?}, accuracyM, brightdate}`,
   * with the sub-objects populated according to the requested format.
   * Gated by the `geo:precise` scope.
   *
   * @param format `"wgs84"` | `"brightspace"` | `"both"` (default `"both"`).
   */
  async linkGeoGet(
    format: LinkCoordinateFormat = 'both',
  ): Promise<LinkGeoGetResponse> {
    if (format !== 'wgs84' && format !== 'brightspace' && format !== 'both') {
      throw new InvalidOperationError(`Invalid format: ${format}`);
    }
    const response = await this.sendCommand('LINK_GEO_GET', { format });
    const parsed = this.parseResponse(response);
    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`LINK_GEO_GET failed: ${parsed.error}`);
    }
    const r = parsed.json;
    const pos = (r['position'] as Record<string, unknown> | undefined) ?? {};
    return {
      position: pos as LinkGeoGetResponse['position'],
      accuracyM:
        typeof r['accuracy_m'] === 'number' ? r['accuracy_m'] : 0,
      brightdate:
        typeof r['brightdate'] === 'number' ? r['brightdate'] : 0,
    };
  }

  /**
   * §9.5 LINK_GEO_REFRESH — trigger a fresh fix.
   *
   * Returns when the fresh fix lands (or the timeout elapses). Does NOT
   * return location data — the caller still has to issue a `linkGeoGet()`
   * (or `linkGeoZone()`/`linkGeoProximity()`) to read the new position.
   * Gated by the `geo:status` scope.
   *
   * @param options.timeoutSeconds Hold-open timeout in seconds. Default 10.
   */
  async linkGeoRefresh(
    options: LinkGeoRefreshOptions = {},
  ): Promise<LinkGeoRefreshResponse> {
    const timeoutSeconds = options.timeoutSeconds ?? 10;
    const response = await this.sendCommand('LINK_GEO_REFRESH', {
      timeout_seconds: timeoutSeconds,
    });
    const parsed = this.parseResponse(response);
    if (!parsed.success || !parsed.json) {
      throw new ProtocolError(`LINK_GEO_REFRESH failed: ${parsed.error}`);
    }
    const r = parsed.json;
    return {
      fixAgeSeconds:
        typeof r['fix_age_seconds'] === 'number' ? r['fix_age_seconds'] : 0,
      accuracyM:
        typeof r['accuracy_m'] === 'number' ? r['accuracy_m'] : 0,
    };
  }

  // ──────────────────────────────────────────────────────────────────────
  // BrightLink v1.1 — agent-to-shell push (RFC §10)
  // ──────────────────────────────────────────────────────────────────────

  /**
   * §10 LINK_PUSH — subscribe to agent-initiated push events.
   *
   * The bridge holds the connection open and emits AAD-sealed event
   * frames whenever the underlying engine reports an event of one of the
   * subscribed kinds. The client decrypts each frame under `K_session`
   * (which must be established via `linkRegister()` first) and invokes
   * `onPayload` with the decrypted body.
   *
   * Per RFC §10.4, there is no explicit unsubscribe verb — disconnecting
   * the socket is the only way to fully tear down a subscription on the
   * bridge side. The returned handle's `close()` method detaches the
   * local handler so `onPayload` stops firing, but the bridge will keep
   * sending frames for the lifetime of the connection.
   *
   * @param events Event names to subscribe to (e.g. `["zone-transition"]`).
   * @param handlers `onPayload` is called with each decrypted event;
   *                 `onError` (optional) is called when a frame fails to
   *                 decrypt or violates the replay window.
   */
  async linkPushSubscribe(
    events: Array<LinkPushEventName | string>,
    handlers: {
      onPayload: (event: LinkPushEvent) => void;
      onError?: (err: Error, raw: Record<string, unknown>) => void;
    },
  ): Promise<LinkPushSubscription> {
    if (this.linkSession === null) {
      throw new InvalidOperationError(
        'linkPushSubscribe requires a registered session — call linkRegister() first',
      );
    }
    if (events.length === 0) {
      throw new InvalidOperationError(
        'linkPushSubscribe requires at least one event name',
      );
    }

    const subscriber = {
      events: new Set<string>(events),
      onPayload: handlers.onPayload,
      onError: handlers.onError,
    };
    this.linkPushSubscribers.push(subscriber);

    // Send the §10 subscribe request. The bridge's response is a single
    // ack frame `{ok:true, subscribed:[...]}`; subsequent push frames
    // arrive asynchronously and are dispatched via `dispatchPushFrame`.
    const response = await this.sendCommand('LINK_PUSH', {
      subscribe: events,
    });
    const parsed = this.parseResponse(response);
    if (!parsed.success || !parsed.json) {
      // Subscribe failed — back out the local handler.
      this.linkPushSubscribers = this.linkPushSubscribers.filter(
        (s) => s !== subscriber,
      );
      throw new ProtocolError(`LINK_PUSH failed: ${parsed.error}`);
    }

    return {
      close: () => {
        this.linkPushSubscribers = this.linkPushSubscribers.filter(
          (s) => s !== subscriber,
        );
      },
    };
  }

  /** Dispatch a push frame to every subscriber whose event-set includes
   *  the frame's event name. Decrypt the frame body under `K_session`
   *  using the §10.2 AAD construction and the session's
   *  `lastInboundCounter` for replay defence. */
  private dispatchPushFrame(frame: Record<string, unknown>): void {
    if (this.linkPushSubscribers.length === 0) return;
    const session = this.linkSession;
    if (session === null) {
      // Push frame arrived without an active session — should be impossible
      // but the bridge could be misbehaving. Drop silently.
      return;
    }
    const eventName = frame['event'];
    const counterRaw = frame['counter'];
    const ivStr = frame['iv'];
    const ctStr = frame['ciphertext'];
    const tagStr = frame['authTag'];
    if (
      typeof eventName !== 'string' ||
      typeof ivStr !== 'string' ||
      typeof ctStr !== 'string' ||
      typeof tagStr !== 'string'
    ) {
      return;
    }
    let counter: bigint;
    try {
      counter = BigInt(
        typeof counterRaw === 'bigint' ? counterRaw : (counterRaw as number | string),
      );
    } catch {
      return;
    }

    // Find subscribers who care about this event name.
    const targets = this.linkPushSubscribers.filter((s) => s.events.has(eventName));
    if (targets.length === 0) return;

    // Replay-window check (RFC §10.3).
    if (counter <= session.lastInboundCounter) {
      const err = new Error(
        `push counter replayed (${counter} <= ${session.lastInboundCounter})`,
      );
      for (const t of targets) {
        if (t.onError) t.onError(err, frame);
      }
      return;
    }

    let body: Buffer;
    try {
      const iv = Buffer.from(ivStr, 'base64');
      const ct = Buffer.from(ctStr, 'base64');
      const tag = Buffer.from(tagStr, 'base64');
      const aad = buildPushAad({ counter, event: eventName });
      const decipher = createDecipheriv('aes-256-gcm', session.kSession, iv, {
        authTagLength: tag.length,
      });
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      body = Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch (err) {
      const wrapped = err instanceof Error ? err : new Error(String(err));
      for (const t of targets) {
        if (t.onError) t.onError(wrapped, frame);
      }
      return;
    }

    session.lastInboundCounter = counter;

    let parsedBody: Record<string, unknown> = {};
    try {
      parsedBody = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
    } catch {
      // The body wasn't JSON. Hand back an empty object — the event name
      // alone may be enough for some handlers, and we don't want a
      // misbehaving bridge to break the dispatch loop.
    }

    for (const t of targets) {
      try {
        t.onPayload({ event: eventName, counter, body: parsedBody });
      } catch (err) {
        if (t.onError) {
          t.onError(err instanceof Error ? err : new Error(String(err)), frame);
        }
      }
    }
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
