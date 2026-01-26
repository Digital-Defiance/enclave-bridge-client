/**
 * Custom error types for EnclaveBridge Client
 */

/**
 * Base error class for all EnclaveBridge errors
 */
export class EnclaveBridgeError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'EnclaveBridgeError';
    Error.captureStackTrace?.(this, this.constructor);
  }
}

/**
 * Connection-related errors
 */
export class ConnectionError extends EnclaveBridgeError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'CONNECTION_ERROR', details);
    this.name = 'ConnectionError';
  }
}

/**
 * Timeout errors for operations that exceed the configured timeout
 */
export class TimeoutError extends EnclaveBridgeError {
  constructor(
    message: string,
    public readonly operation: string,
    public readonly timeoutMs: number
  ) {
    super(message, 'TIMEOUT', { operation, timeoutMs });
    this.name = 'TimeoutError';
  }
}

/**
 * Decryption-related errors
 */
export class DecryptionError extends EnclaveBridgeError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'DECRYPTION_ERROR', details);
    this.name = 'DecryptionError';
  }
}

/**
 * Encryption-related errors
 */
export class EncryptionError extends EnclaveBridgeError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'ENCRYPTION_ERROR', details);
    this.name = 'EncryptionError';
  }
}

/**
 * Signature verification errors
 */
export class SignatureError extends EnclaveBridgeError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'SIGNATURE_ERROR', details);
    this.name = 'SignatureError';
  }
}

/**
 * Invalid operation errors (e.g., calling methods when not connected)
 */
export class InvalidOperationError extends EnclaveBridgeError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'INVALID_OPERATION', details);
    this.name = 'InvalidOperationError';
  }
}

/**
 * Protocol errors (invalid responses, parse errors, etc.)
 */
export class ProtocolError extends EnclaveBridgeError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'PROTOCOL_ERROR', details);
    this.name = 'ProtocolError';
  }
}

/**
 * Platform/environment errors (unsupported OS, missing socket, etc.)
 */
export class PlatformError extends EnclaveBridgeError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'PLATFORM_ERROR', details);
    this.name = 'PlatformError';
  }
}

/**
 * Error code constants
 */
export const ErrorCodes = {
  CONNECTION_ERROR: 'CONNECTION_ERROR',
  TIMEOUT: 'TIMEOUT',
  DECRYPTION_ERROR: 'DECRYPTION_ERROR',
  ENCRYPTION_ERROR: 'ENCRYPTION_ERROR',
  SIGNATURE_ERROR: 'SIGNATURE_ERROR',
  INVALID_OPERATION: 'INVALID_OPERATION',
  PROTOCOL_ERROR: 'PROTOCOL_ERROR',
  PLATFORM_ERROR: 'PLATFORM_ERROR',
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
