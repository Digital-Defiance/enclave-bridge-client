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
  requestSent: (command: string, payload?: Record<string, string | number | boolean>) => void;

  /**
   * Emitted when a response is received (debug only)
   */
  responseReceived: (response: string) => void;
}

/**
 * Queued request information
 */
export interface QueuedRequest {
  /** Command name. */
  command: string;
  /** Payload values may be strings, numbers, booleans, or — to support the
   *  BrightLink v1.1 surface — arrays of those primitives (e.g. the
   *  `subscribe: ["zone-transition"]` array on `LINK_PUSH`). */
  payload?: Record<string, unknown>;
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
   * Key type (secp256k1 or Secure Enclave)
   */
  type: string;

  /**
   * Public key fingerprint
   */
  publicKeyFingerprint: string;

  /**
   * Is Secure Enclave key
   */
  isSecureEnclave: boolean;

  /**
   * TOTP enabled status
   */
  totpEnabled: boolean;

  /**
   * TOTP provisioning URI (if enabled)
   */
  totpProvisioningURI?: string;
}

/**
 * Available keys list
 */
export interface KeyList {
  /**
   * All keys (merged)
   */
  keys: KeyInfo[];
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

// ──────────────────────────────────────────────────────────────────────────
// BrightLink v1 — see docs/rfc-brightlink.md
// ──────────────────────────────────────────────────────────────────────────

/**
 * Information identifying the client to the bridge during LINK_REGISTER.
 * Recorded in the bridge's audit log for diagnostic purposes per RFC §4.5.1.
 *
 * Each field is capped at 64 characters by the bridge; longer values are
 * silently truncated, so prefer short values.
 */
export interface LinkAgentInfo {
  /** Client identifier, e.g. "bsh", "my-cli". */
  name: string;
  /** Client version, e.g. "1.4.2". */
  version: string;
  /** Free-form platform tag, e.g. "darwin-arm64", "node-darwin-arm64". */
  platform: string;
}

/**
 * Options for `EnclaveBridgeClient.linkRegister(...)`.
 */
export interface LinkRegisterOptions {
  /**
   * Requested session lifetime in seconds. The bridge caps at 8h
   * (`LINK_MAX_TTL_SECONDS = 28800`). Defaults to 1 hour if omitted.
   */
  ttlSeconds?: number;

  /**
   * Override the BrightDate scalar in the §4.5.1 envelope plaintext.
   * Defaults to `Math.floor(Date.now() / 1000) / 86400` if omitted.
   * Tests use this to reproduce known-answer vectors.
   */
  issuedAtBd?: number;

  /**
   * Identification advertised in the §4.5.1 envelope's `agent` field.
   * Defaults to `{ name: "enclave-bridge-client", version: <pkg version>,
   * platform: "node-<process.platform>-<process.arch>" }`.
   */
  agentInfo?: LinkAgentInfo;
}

/**
 * The result of a successful LINK_REGISTER. The client holds this
 * internally as `client.linkSession`; callers can read the public fields
 * to drive their own session-aware logic.
 *
 * `kSession` is sensitive; do not log, do not persist. The client zeros
 * this buffer on `disconnect()` and on re-registration.
 */
export interface LinkSession {
  /** 16-byte session identifier the wire protocol uses. */
  sessionId: Buffer;
  /** 32-byte AES-256-GCM session key. */
  kSession: Buffer;
  /** Bridge's clock when the session was minted (Unix seconds). */
  bridgeIssuedAtUnix: number;
  /** Granted TTL after the bridge cap (≤ requested, ≤ 8h). */
  ttlSeconds: number;
  /** Effective expiry instant (Unix seconds). */
  expiresAtUnix: number;
  /** Bridge's SEP P-256 public key (65-byte uncompressed X9.63). */
  sepPublicKey: Buffer;
  /** Outbound (Shell → Agent) counter. Caller increments per emit. */
  outboundCounter: bigint;
  /** Highest accepted inbound (Agent → Shell) counter. Updated by the
   *  receive path on successful packet verification. */
  lastInboundCounter: bigint;
}


// ──────────────────────────────────────────────────────────────────────────
// BrightLink v1.1 — geo command surface (RFC §9) and push (RFC §10)
// ──────────────────────────────────────────────────────────────────────────

/** Coordinate format selector for `LINK_GEO_GET` (RFC §9.4). */
export type LinkCoordinateFormat = 'wgs84' | 'brightspace' | 'both';

/** WGS84 lat/lon/altitude (degrees / metres). */
export interface LinkWgs84Position {
  lat: number;
  lon: number;
  alt_m?: number;
}

/** BrightSpace ECEF position in BrightMeters (`x_bm = ecef_x_m / c`). */
export interface LinkBrightSpacePosition {
  x_bm: number;
  y_bm: number;
  z_bm: number;
  /** BrightDate at which the fix was sampled (RFC §9.4 — long-lived
   *  spatial claims SHOULD record this so consumers can re-project). */
  epoch_bd: number;
}

/** Result of `LINK_GEO_STATUS` (RFC §9.1). */
export interface LinkGeoStatusResponse {
  alive: boolean;
  engineKind: string;
  fixAgeSeconds: number | null;
  accuracyM: number | null;
}

/** Result of `LINK_GEO_PROXIMITY` (RFC §9.2). */
export interface LinkGeoProximityResponse {
  inZone: boolean;
  brightdate: number;
}

/** Result of `LINK_GEO_ZONE` (RFC §9.3). */
export interface LinkGeoZoneResponse {
  /** Current zone id, or null if no zone matches. */
  zone: string | null;
  /** Seconds since the last zone transition. 0 on first observation. */
  dwellSeconds: number;
  brightdate: number;
}

/** Result of `LINK_GEO_GET` (RFC §9.4). At least one of `wgs84` or
 *  `brightspace` is present, depending on the requested format. */
export interface LinkGeoGetResponse {
  position: {
    wgs84?: LinkWgs84Position;
    brightspace?: LinkBrightSpacePosition;
  };
  accuracyM: number;
  brightdate: number;
}

/** Result of `LINK_GEO_REFRESH` (RFC §9.5). The data itself is NOT
 *  returned — the caller still has to issue a `LINK_GEO_GET` afterwards
 *  to read the fresh position. */
export interface LinkGeoRefreshResponse {
  fixAgeSeconds: number;
  accuracyM: number;
}

/** Options for `LINK_GEO_REFRESH`. */
export interface LinkGeoRefreshOptions {
  /** Hold-open timeout in seconds. Default 10. */
  timeoutSeconds?: number;
}

/** Event-name strings carried in `LINK_PUSH` frames (RFC §10.1).
 *  Exposed as a string union so callers can pass literal strings. */
export type LinkPushEventName = 'zone-transition' | 'geo-grant-changed';

/** A decrypted push event delivered to a `linkPushSubscribe` handler.
 *  The body is whatever the bridge sealed under K_session for this event
 *  type — for `zone-transition` it's `{from, to, at_bd}`; for
 *  `geo-grant-changed` it's `{scope, policy, by}`. */
export interface LinkPushEvent {
  /** The event name, e.g. `"zone-transition"`. */
  event: LinkPushEventName | string;
  /** Per-session monotonic counter (`c_agent_to_shell`). Strictly
   *  increasing across the subscriber's lifetime. */
  counter: bigint;
  /** Decrypted plaintext body. JSON-decoded shape varies by event type. */
  body: Record<string, unknown>;
}

/** Subscription handle returned by `linkPushSubscribe`. Calling `close()`
 *  detaches the handler; the underlying socket subscription persists for
 *  the life of the EBP/1 connection (per RFC §10.4 — disconnect is the
 *  only way to fully unsubscribe). */
export interface LinkPushSubscription {
  close(): void;
}
