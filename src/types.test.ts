import { describe, it, expect } from 'vitest';
import type {
  ConnectionState,
  EnclaveBridgeClientOptions,
  PublicKeyInfo,
  SignatureResult,
  DecryptionResult,
  KeyGenerationResult,
  BridgeResponse,
  ECIESFormat,
  EnclaveBridgeClientEvents,
} from './types.js';
import { ECIESEncryptionType } from './types.js';

describe('Type definitions', () => {
  describe('ConnectionState', () => {
    it('should accept valid states', () => {
      const states: ConnectionState[] = ['disconnected', 'connecting', 'connected', 'error'];
      expect(states).toHaveLength(4);
    });
  });

  describe('EnclaveBridgeClientOptions', () => {
    it('should allow empty options', () => {
      const options: EnclaveBridgeClientOptions = {};
      expect(options).toBeDefined();
    });

    it('should allow socketPath', () => {
      const options: EnclaveBridgeClientOptions = { socketPath: '/test/path' };
      expect(options.socketPath).toBe('/test/path');
    });

    it('should allow timeout', () => {
      const options: EnclaveBridgeClientOptions = { timeout: 5000 };
      expect(options.timeout).toBe(5000);
    });

    it('should allow both options', () => {
      const options: EnclaveBridgeClientOptions = {
        socketPath: '/test/path',
        timeout: 5000,
      };
      expect(options.socketPath).toBe('/test/path');
      expect(options.timeout).toBe(5000);
    });
  });

  describe('PublicKeyInfo', () => {
    it('should have all required fields', () => {
      const keyInfo: PublicKeyInfo = {
        base64: 'dGVzdA==',
        buffer: Buffer.from('test'),
        hex: '74657374',
        compressed: true,
      };
      expect(keyInfo.base64).toBe('dGVzdA==');
      expect(keyInfo.buffer).toBeInstanceOf(Buffer);
      expect(keyInfo.hex).toBe('74657374');
      expect(keyInfo.compressed).toBe(true);
    });
  });

  describe('SignatureResult', () => {
    it('should have all required fields', () => {
      const sig: SignatureResult = {
        base64: 'c2ln',
        buffer: Buffer.from('sig'),
        hex: '736967',
        format: 'der',
      };
      expect(sig.format).toBe('der');
    });

    it('should accept raw format', () => {
      const sig: SignatureResult = {
        base64: 'c2ln',
        buffer: Buffer.from('sig'),
        hex: '736967',
        format: 'raw',
      };
      expect(sig.format).toBe('raw');
    });
  });

  describe('DecryptionResult', () => {
    it('should have all required fields', () => {
      const result: DecryptionResult = {
        base64: 'aGVsbG8=',
        buffer: Buffer.from('hello'),
        text: 'hello',
      };
      expect(result.text).toBe('hello');
    });
  });

  describe('KeyGenerationResult', () => {
    it('should have publicKey field', () => {
      const result: KeyGenerationResult = {
        publicKey: {
          base64: 'dGVzdA==',
          buffer: Buffer.from('test'),
          hex: '74657374',
          compressed: true,
        },
      };
      expect(result.publicKey.compressed).toBe(true);
    });
  });

  describe('BridgeResponse', () => {
    it('should support success response', () => {
      const response: BridgeResponse = {
        success: true,
        data: 'result',
      };
      expect(response.success).toBe(true);
      expect(response.data).toBe('result');
    });

    it('should support error response', () => {
      const response: BridgeResponse = {
        success: false,
        error: 'Something went wrong',
      };
      expect(response.success).toBe(false);
      expect(response.error).toBe('Something went wrong');
    });
  });

  describe('ECIESFormat', () => {
    it('should have all required fields', () => {
      const format: ECIESFormat = {
        version: 1,
        cipherSuite: 0,
        encryptionType: ECIESEncryptionType.Basic,
        ephemeralPublicKey: Buffer.alloc(33),
        iv: Buffer.alloc(12),
        authTag: Buffer.alloc(16),
        ciphertext: Buffer.from('data'),
      };
      expect(format.version).toBe(1);
      expect(format.ephemeralPublicKey.length).toBe(33);
      expect(format.iv.length).toBe(12);
      expect(format.authTag.length).toBe(16);
    });
  });

  describe('ECIESEncryptionType', () => {
    it('should have Basic = 33 (0x21)', () => {
      expect(ECIESEncryptionType.Basic).toBe(33);
    });

    it('should have WithLength = 66 (0x42)', () => {
      expect(ECIESEncryptionType.WithLength).toBe(66);
    });

    it('should have Multiple = 99 (0x63)', () => {
      expect(ECIESEncryptionType.Multiple).toBe(99);
    });
  });
});

describe('Type compatibility', () => {
  it('should allow Buffer to be used in PublicKeyInfo', () => {
    const buffer = Buffer.from([0x03, ...Array(32).fill(0xab)]);
    const keyInfo: PublicKeyInfo = {
      base64: buffer.toString('base64'),
      buffer,
      hex: buffer.toString('hex'),
      compressed: buffer.length === 33,
    };
    expect(keyInfo.compressed).toBe(true);
  });
});
