/**
 * Type definitions for EnclaveBridge Client
 */

/**
 * Connection state for the client
 */
export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'error';

/**
 * Client configuration options
 */
export interface EnclaveBridgeClientOptions {
  /**
   * Path to the Unix domain socket
   * @default '/tmp/enclave-bridge.sock'
   */
  socketPath?: string;

  /**
   * Timeout for operations in milliseconds
   * @default 30000
   */
  timeout?: number;

  /**
   * Enable auto-reconnection on disconnect
   * @default true
   */
  autoReconnect?: boolean;

  /**
   * Maximum number of reconnection attempts
   * @default 5
   */
  maxReconnectAttempts?: number;

  /**
   * Initial reconnect delay in milliseconds
   * @default 1000
   */
  reconnectDelay?: number;

  /**
   * Maximum reconnect delay in milliseconds (for exponential backoff)
   * @default 30000
   */
  maxReconnectDelay?: number;

  /**
   * Enable verbose debug logging
   * @default false
   */
  debug?: boolean;

  /**
   * Custom logger function
   */
  logger?: (level: 'debug' | 'info' | 'warn' | 'error', message: string, meta?: Record<string, unknown>) => void;

  /**
   * Enable key caching
   * @default true
   */
  cacheKeys?: boolean;

  /**
   * Maximum number of concurrent requests
   * @default 10
   */
  maxConcurrentRequests?: number;

  /**
   * Enable heartbeat/keepalive
   * @default false
   */
  enableHeartbeat?: boolean;

  /**
   * Heartbeat interval in milliseconds
   * @default 30000
   */
  heartbeatInterval?: number;
}

/**
 * Public key information returned from the bridge
 */
export interface PublicKeyInfo {
  /**
   * Base64 encoded public key
   */
  base64: string;

  /**
   * Raw public key bytes
   */
  buffer: Buffer;

  /**
   * Hex encoded public key
   */
  hex: string;

  /**
   * Whether the key is in compressed format (33 bytes vs 65 bytes)
   */
  compressed: boolean;
}

/**
 * Signature result from Secure Enclave signing
 */
export interface SignatureResult {
  /**
   * Base64 encoded signature
   */
  base64: string;

  /**
   * Raw signature bytes
   */
  buffer: Buffer;

  /**
   * Hex encoded signature
   */
  hex: string;

  /**
   * Signature format (typically 'der' for P-256)
   */
  format: 'der' | 'raw';
}

/**
 * Decryption result
 */
export interface DecryptionResult {
  /**
   * Base64 encoded plaintext
   */
  base64: string;

  /**
   * Raw plaintext bytes
   */
  buffer: Buffer;

  /**
   * Plaintext as UTF-8 string (if applicable)
   */
  text: string;
}

/**
 * Key generation result
 */
export interface KeyGenerationResult {
  /**
   * The generated public key
   */
  publicKey: PublicKeyInfo;
}

/**
 * Bridge response format
 */
export interface BridgeResponse {
  /**
   * Whether the operation succeeded
   */
  success: boolean;

  /**
   * Response data (for successful operations)
   */
  data?: string;

  /**
   * Error message (for failed operations)
   */
  error?: string;
}

/**
 * ECIES encryption format compatible with node-ecies-lib
 */
export interface ECIESFormat {
  /**
   * Protocol version (1 byte)
   */
  version: number;

  /**
   * Cipher suite identifier (1 byte)
   */
  cipherSuite: number;

  /**
   * Encryption type: 33=Basic, 66=WithLength, 99=Multiple
   */
  encryptionType: number;

  /**
   * Ephemeral public key (33 bytes, compressed secp256k1)
   */
  ephemeralPublicKey: Buffer;

  /**
   * Initialization vector (12 bytes)
   */
  iv: Buffer;

  /**
   * Authentication tag (16 bytes)
   */
  authTag: Buffer;

  /**
   * Encrypted ciphertext
   */
  ciphertext: Buffer;
}

/**
 * ECIES encryption type values
 */
export enum ECIESEncryptionType {
  /**
   * Basic encryption (0x21 = 33)
   */
  Basic = 33,

  /**
   * Encryption with length prefix (0x42 = 66)
   */
  WithLength = 66,

  /**
   * Multiple block encryption (0x63 = 99)
   */
  Multiple = 99,
}

/**
 * Client events
 */
export interface EnclaveBridgeClientEvents {
  /**
   * Emitted when the connection state changes
   */
  stateChange: (state: ConnectionState) => void;

  /**
   * Emitted when connected to the bridge
   */
  connect: () => void;

  /**
   * Emitted when disconnected from the bridge
   */
  disconnect: () => void;

  /**
   * Emitted when reconnection attempt starts
   */
  reconnecting: (attempt: number, maxAttempts: number) => void;

  /**
   * Emitted when reconnection succeeds
   */
  reconnected: () => void;

  /**
   * Emitted when all reconnection attempts fail
   */
  reconnectFailed: (error: Error) => void;

  /**
   * Emitted when an error occurs
   */
  error: (error: Error) => void;

  /**
   * Emitted when debug logging is enabled
   */
  debug: (message: string, meta?: Record<string, unknown>) => void;

  /**
   * Emitted before disconnect
   */
  beforeDisconnect: () => void;

  /**
   * Emitted when a request is sent (debug only)
   */
  requestSent: (command: string, payload?: Record<string, string>) => void;

  /**
   * Emitted when a response is received (debug only)
   */
  responseReceived: (response: string) => void;
}

/**
 * Queued request information
 */
export interface QueuedRequest {
  command: string;
  payload?: Record<string, string>;
  resolve: (value: string) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
  timestamp: number;
  sent: boolean;
}

/**
 * Platform support information
 */
export interface PlatformSupport {
  /**
   * Whether the platform is supported
   */
  supported: boolean;

  /**
   * Reason for lack of support (if unsupported)
   */
  reason?: string;

  /**
   * Detected platform
   */
  platform: string;

  /**
   * Whether socket file exists
   */
  socketExists: boolean;

  /**
   * Socket file path checked
   */
  socketPath: string;
}

/**
 * Health status information
 */
export interface HealthStatus {
  /**
   * Whether the bridge is healthy
   */
  healthy: boolean;

  /**
   * Connection state
   */
  state: ConnectionState;

  /**
   * Uptime in milliseconds
   */
  uptime: number;

  /**
   * Number of active requests
   */
  activeRequests: number;

  /**
   * Number of queued requests
   */
  queuedRequests: number;

  /**
   * Last heartbeat time
   */
  lastHeartbeat?: number;

  /**
   * Reconnection attempts
   */
  reconnectAttempts?: number;
}

/**
 * Server version information
 */
export interface ServerVersion {
  /**
   * Application version
   */
  appVersion: string;

  /**
   * Build number/identifier
   */
  build: string;

  /**
   * Platform (e.g., "macOS")
   */
  platform: string;

  /**
   * Server uptime in seconds
   */
  uptimeSeconds: number;
}

/**
 * Server status information
 */
export interface ServerStatus {
  /**
   * Whether operation succeeded
   */
  ok: boolean;

  /**
   * Whether peer public key is set
   */
  peerPublicKeySet: boolean;

  /**
   * Whether Secure Enclave key is available
   */
  enclaveKeyAvailable: boolean;
}

/**
 * Server metrics
 */
export interface ServerMetrics {
  /**
   * Service name
   */
  service: string;

  /**
   * Server uptime in seconds
   */
  uptimeSeconds: number;

  /**
   * Request counters
   */
  requestCounters?: Record<string, number>;
}

/**
 * Key information in list
 */
export interface KeyInfo {
  /**
   * Key identifier
   */
  id: string;

  /**
   * Base64 encoded public key
   */
  publicKey: string;
}

/**
 * Available keys list
 */
export interface KeyList {
  /**
   * ECIES keys
   */
  ecies: KeyInfo[];

  /**
   * Enclave keys
   */
  enclave: KeyInfo[];
}

/**
 * Heartbeat response
 */
export interface HeartbeatResponse {
  /**
   * Whether operation succeeded
   */
  ok: boolean;

  /**
   * Server timestamp (ISO8601)
   */
  timestamp: string;

  /**
   * Service name
   */
  service: string;
}
