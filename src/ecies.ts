/**
 * ECIES utilities for working with node-ecies-lib format
 */

import type { ECIESFormat } from './types.js';
import { ECIESEncryptionType } from './types.js';

/**
 * ECIES format constants
 */
export const ECIES_CONSTANTS = {
  /** Size of version field */
  VERSION_SIZE: 1,
  /** Size of cipher suite field */
  CIPHER_SUITE_SIZE: 1,
  /** Size of encryption type field */
  ENCRYPTION_TYPE_SIZE: 1,
  /** Size of compressed secp256k1 public key */
  EPHEMERAL_KEY_SIZE: 33,
  /** Size of AES-GCM initialization vector */
  IV_SIZE: 12,
  /** Size of AES-GCM authentication tag */
  AUTH_TAG_SIZE: 16,
  /** Total header size (before ciphertext) */
  HEADER_SIZE: 1 + 1 + 1 + 33 + 12 + 16, // 64 bytes
} as const;

/**
 * Parse ECIES encrypted data into its components
 *
 * @param data - Raw ECIES encrypted data
 * @returns Parsed ECIES format object
 * @throws Error if data is too short or has invalid format
 */
export function parseECIES(data: Buffer): ECIESFormat {
  if (data.length < ECIES_CONSTANTS.HEADER_SIZE) {
    throw new Error(
      `ECIES data too short: ${data.length} bytes, minimum ${ECIES_CONSTANTS.HEADER_SIZE} bytes required`
    );
  }

  let offset = 0;

  // Version (1 byte)
  const version = data[offset];
  offset += ECIES_CONSTANTS.VERSION_SIZE;

  // Cipher suite (1 byte)
  const cipherSuite = data[offset];
  offset += ECIES_CONSTANTS.CIPHER_SUITE_SIZE;

  // Encryption type (1 byte)
  const encryptionType = data[offset];
  offset += ECIES_CONSTANTS.ENCRYPTION_TYPE_SIZE;

  // Validate encryption type
  if (
    encryptionType !== ECIESEncryptionType.Basic &&
    encryptionType !== ECIESEncryptionType.WithLength &&
    encryptionType !== ECIESEncryptionType.Multiple
  ) {
    throw new Error(`Invalid ECIES encryption type: ${encryptionType}`);
  }

  // Ephemeral public key (33 bytes, compressed)
  const ephemeralPublicKey = data.subarray(offset, offset + ECIES_CONSTANTS.EPHEMERAL_KEY_SIZE);
  offset += ECIES_CONSTANTS.EPHEMERAL_KEY_SIZE;

  // Validate ephemeral key prefix (0x02 or 0x03 for compressed)
  if (ephemeralPublicKey[0] !== 0x02 && ephemeralPublicKey[0] !== 0x03) {
    throw new Error(`Invalid ephemeral public key prefix: 0x${ephemeralPublicKey[0].toString(16)}`);
  }

  // IV (12 bytes)
  const iv = data.subarray(offset, offset + ECIES_CONSTANTS.IV_SIZE);
  offset += ECIES_CONSTANTS.IV_SIZE;

  // Auth tag (16 bytes)
  const authTag = data.subarray(offset, offset + ECIES_CONSTANTS.AUTH_TAG_SIZE);
  offset += ECIES_CONSTANTS.AUTH_TAG_SIZE;

  // Ciphertext (remaining bytes)
  const ciphertext = data.subarray(offset);

  return {
    version,
    cipherSuite,
    encryptionType,
    ephemeralPublicKey: Buffer.from(ephemeralPublicKey),
    iv: Buffer.from(iv),
    authTag: Buffer.from(authTag),
    ciphertext: Buffer.from(ciphertext),
  };
}

/**
 * Serialize ECIES components into raw format
 *
 * @param format - ECIES format object
 * @returns Raw ECIES encrypted data
 */
export function serializeECIES(format: ECIESFormat): Buffer {
  const totalSize =
    ECIES_CONSTANTS.VERSION_SIZE +
    ECIES_CONSTANTS.CIPHER_SUITE_SIZE +
    ECIES_CONSTANTS.ENCRYPTION_TYPE_SIZE +
    format.ephemeralPublicKey.length +
    format.iv.length +
    format.authTag.length +
    format.ciphertext.length;

  const buffer = Buffer.alloc(totalSize);
  let offset = 0;

  // Version
  buffer[offset] = format.version;
  offset += ECIES_CONSTANTS.VERSION_SIZE;

  // Cipher suite
  buffer[offset] = format.cipherSuite;
  offset += ECIES_CONSTANTS.CIPHER_SUITE_SIZE;

  // Encryption type
  buffer[offset] = format.encryptionType;
  offset += ECIES_CONSTANTS.ENCRYPTION_TYPE_SIZE;

  // Ephemeral public key
  format.ephemeralPublicKey.copy(buffer, offset);
  offset += format.ephemeralPublicKey.length;

  // IV
  format.iv.copy(buffer, offset);
  offset += format.iv.length;

  // Auth tag
  format.authTag.copy(buffer, offset);
  offset += format.authTag.length;

  // Ciphertext
  format.ciphertext.copy(buffer, offset);

  return buffer;
}

/**
 * Get the encryption type name
 *
 * @param type - Encryption type value
 * @returns Human-readable name
 */
export function getEncryptionTypeName(type: number): string {
  switch (type) {
    case ECIESEncryptionType.Basic:
      return 'Basic';
    case ECIESEncryptionType.WithLength:
      return 'WithLength';
    case ECIESEncryptionType.Multiple:
      return 'Multiple';
    default:
      return `Unknown(${type})`;
  }
}

/**
 * Validate ECIES encrypted data format
 *
 * @param data - Data to validate
 * @returns Object with valid flag and optional error message
 */
export function validateECIES(data: Buffer): { valid: boolean; error?: string } {
  try {
    parseECIES(data);
    return { valid: true };
  } catch (err) {
    return { valid: false, error: (err as Error).message };
  }
}
