/**
 * Type definitions for EnclaveBridge Client
 */

/**
 * Connection state for the client
 */
export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error';

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
   * Emitted when an error occurs
   */
  error: (error: Error) => void;
}
