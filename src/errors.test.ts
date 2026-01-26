/**
 * Tests for custom error types
 */

import { describe, it, expect } from 'vitest';
import {
  EnclaveBridgeError,
  ConnectionError,
  TimeoutError,
  DecryptionError,
  EncryptionError,
  SignatureError,
  InvalidOperationError,
  ProtocolError,
  PlatformError,
  ErrorCodes,
} from '../src/errors.js';

describe('Custom Error Types', () => {
  describe('EnclaveBridgeError', () => {
    it('should create error with code and details', () => {
      const error = new EnclaveBridgeError('Test error', 'TEST_CODE', { foo: 'bar' });
      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe('EnclaveBridgeError');
      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.details).toEqual({ foo: 'bar' });
    });

    it('should have stack trace', () => {
      const error = new EnclaveBridgeError('Test', 'CODE');
      expect(error.stack).toBeDefined();
    });
  });

  describe('ConnectionError', () => {
    it('should create connection error', () => {
      const error = new ConnectionError('Connection failed');
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('ConnectionError');
      expect(error.code).toBe(ErrorCodes.CONNECTION_ERROR);
    });
  });

  describe('TimeoutError', () => {
    it('should create timeout error with operation details', () => {
      const error = new TimeoutError('Timed out', 'connect', 5000);
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('TimeoutError');
      expect(error.code).toBe(ErrorCodes.TIMEOUT);
      expect(error.operation).toBe('connect');
      expect(error.timeoutMs).toBe(5000);
    });
  });

  describe('DecryptionError', () => {
    it('should create decryption error', () => {
      const error = new DecryptionError('Decryption failed');
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('DecryptionError');
      expect(error.code).toBe(ErrorCodes.DECRYPTION_ERROR);
    });
  });

  describe('EncryptionError', () => {
    it('should create encryption error', () => {
      const error = new EncryptionError('Encryption failed');
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('EncryptionError');
      expect(error.code).toBe(ErrorCodes.ENCRYPTION_ERROR);
    });
  });

  describe('SignatureError', () => {
    it('should create signature error', () => {
      const error = new SignatureError('Signature invalid');
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('SignatureError');
      expect(error.code).toBe(ErrorCodes.SIGNATURE_ERROR);
    });
  });

  describe('InvalidOperationError', () => {
    it('should create invalid operation error', () => {
      const error = new InvalidOperationError('Not connected');
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('InvalidOperationError');
      expect(error.code).toBe(ErrorCodes.INVALID_OPERATION);
    });
  });

  describe('ProtocolError', () => {
    it('should create protocol error', () => {
      const error = new ProtocolError('Invalid JSON');
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('ProtocolError');
      expect(error.code).toBe(ErrorCodes.PROTOCOL_ERROR);
    });
  });

  describe('PlatformError', () => {
    it('should create platform error', () => {
      const error = new PlatformError('macOS required');
      expect(error).toBeInstanceOf(EnclaveBridgeError);
      expect(error.name).toBe('PlatformError');
      expect(error.code).toBe(ErrorCodes.PLATFORM_ERROR);
    });
  });
});
