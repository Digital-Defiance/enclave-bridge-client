import { describe, it, expect } from 'vitest';
import {
  parseECIES,
  serializeECIES,
  validateECIES,
  getEncryptionTypeName,
  ECIES_CONSTANTS,
} from './ecies.js';
import { ECIESEncryptionType } from './types.js';

describe('ECIES_CONSTANTS', () => {
  it('should have correct sizes', () => {
    expect(ECIES_CONSTANTS.VERSION_SIZE).toBe(1);
    expect(ECIES_CONSTANTS.CIPHER_SUITE_SIZE).toBe(1);
    expect(ECIES_CONSTANTS.ENCRYPTION_TYPE_SIZE).toBe(1);
    expect(ECIES_CONSTANTS.EPHEMERAL_KEY_SIZE).toBe(33);
    expect(ECIES_CONSTANTS.IV_SIZE).toBe(12);
    expect(ECIES_CONSTANTS.AUTH_TAG_SIZE).toBe(16);
    expect(ECIES_CONSTANTS.HEADER_SIZE).toBe(64);
  });
});

describe('parseECIES', () => {
  const createValidECIESData = (
    version = 1,
    cipherSuite = 0,
    encryptionType = ECIESEncryptionType.Basic,
    ciphertext = Buffer.from('test ciphertext')
  ): Buffer => {
    const ephemeralKey = Buffer.alloc(33);
    ephemeralKey[0] = 0x02; // Compressed key prefix
    for (let i = 1; i < 33; i++) ephemeralKey[i] = i;

    const iv = Buffer.alloc(12);
    for (let i = 0; i < 12; i++) iv[i] = i + 100;

    const authTag = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) authTag[i] = i + 200;

    return Buffer.concat([
      Buffer.from([version, cipherSuite, encryptionType]),
      ephemeralKey,
      iv,
      authTag,
      ciphertext,
    ]);
  };

  it('should parse valid ECIES data with Basic encryption type', () => {
    const data = createValidECIESData(1, 0, ECIESEncryptionType.Basic);
    const result = parseECIES(data);

    expect(result.version).toBe(1);
    expect(result.cipherSuite).toBe(0);
    expect(result.encryptionType).toBe(ECIESEncryptionType.Basic);
    expect(result.ephemeralPublicKey.length).toBe(33);
    expect(result.ephemeralPublicKey[0]).toBe(0x02);
    expect(result.iv.length).toBe(12);
    expect(result.authTag.length).toBe(16);
    expect(result.ciphertext.toString()).toBe('test ciphertext');
  });

  it('should parse valid ECIES data with WithLength encryption type', () => {
    const data = createValidECIESData(1, 0, ECIESEncryptionType.WithLength);
    const result = parseECIES(data);
    expect(result.encryptionType).toBe(ECIESEncryptionType.WithLength);
  });

  it('should parse valid ECIES data with Multiple encryption type', () => {
    const data = createValidECIESData(1, 0, ECIESEncryptionType.Multiple);
    const result = parseECIES(data);
    expect(result.encryptionType).toBe(ECIESEncryptionType.Multiple);
  });

  it('should accept 0x03 prefix for ephemeral key', () => {
    const data = createValidECIESData();
    data[3] = 0x03; // Change ephemeral key prefix
    const result = parseECIES(data);
    expect(result.ephemeralPublicKey[0]).toBe(0x03);
  });

  it('should throw on data that is too short', () => {
    const shortData = Buffer.alloc(32);
    expect(() => parseECIES(shortData)).toThrow('ECIES data too short');
  });

  it('should throw on invalid encryption type', () => {
    const data = createValidECIESData(1, 0, 0x01); // Invalid type
    expect(() => parseECIES(data)).toThrow('Invalid ECIES encryption type');
  });

  it('should throw on invalid ephemeral key prefix', () => {
    const data = createValidECIESData();
    data[3] = 0x04; // Uncompressed key prefix (not supported)
    expect(() => parseECIES(data)).toThrow('Invalid ephemeral public key prefix');
  });

  it('should handle empty ciphertext', () => {
    const data = createValidECIESData(1, 0, ECIESEncryptionType.Basic, Buffer.alloc(0));
    const result = parseECIES(data);
    expect(result.ciphertext.length).toBe(0);
  });

  it('should handle large ciphertext', () => {
    const largeCiphertext = Buffer.alloc(10000);
    const data = createValidECIESData(1, 0, ECIESEncryptionType.Basic, largeCiphertext);
    const result = parseECIES(data);
    expect(result.ciphertext.length).toBe(10000);
  });
});

describe('serializeECIES', () => {
  it('should serialize ECIES format correctly', () => {
    const format = {
      version: 1,
      cipherSuite: 0,
      encryptionType: ECIESEncryptionType.Basic,
      ephemeralPublicKey: Buffer.alloc(33, 0x02),
      iv: Buffer.alloc(12, 0x01),
      authTag: Buffer.alloc(16, 0x02),
      ciphertext: Buffer.from('hello'),
    };

    const serialized = serializeECIES(format);

    expect(serialized[0]).toBe(1); // version
    expect(serialized[1]).toBe(0); // cipherSuite
    expect(serialized[2]).toBe(33); // encryptionType (Basic)
    expect(serialized.slice(3, 36)).toEqual(format.ephemeralPublicKey);
    expect(serialized.slice(36, 48)).toEqual(format.iv);
    expect(serialized.slice(48, 64)).toEqual(format.authTag);
    expect(serialized.slice(64).toString()).toBe('hello');
  });

  it('should round-trip correctly with parseECIES', () => {
    const original = {
      version: 2,
      cipherSuite: 1,
      encryptionType: ECIESEncryptionType.WithLength,
      ephemeralPublicKey: Buffer.concat([Buffer.from([0x03]), Buffer.alloc(32, 0xab)]),
      iv: Buffer.alloc(12, 0xcd),
      authTag: Buffer.alloc(16, 0xef),
      ciphertext: Buffer.from('test message'),
    };

    const serialized = serializeECIES(original);
    const parsed = parseECIES(serialized);

    expect(parsed.version).toBe(original.version);
    expect(parsed.cipherSuite).toBe(original.cipherSuite);
    expect(parsed.encryptionType).toBe(original.encryptionType);
    expect(parsed.ephemeralPublicKey).toEqual(original.ephemeralPublicKey);
    expect(parsed.iv).toEqual(original.iv);
    expect(parsed.authTag).toEqual(original.authTag);
    expect(parsed.ciphertext).toEqual(original.ciphertext);
  });
});

describe('validateECIES', () => {
  const createValidData = (): Buffer => {
    const data = Buffer.alloc(70);
    data[0] = 1; // version
    data[1] = 0; // cipherSuite
    data[2] = 33; // Basic encryption type
    data[3] = 0x02; // compressed key prefix
    return data;
  };

  it('should return valid for correct ECIES data', () => {
    const result = validateECIES(createValidData());
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should return invalid for short data', () => {
    const result = validateECIES(Buffer.alloc(10));
    expect(result.valid).toBe(false);
    expect(result.error).toContain('too short');
  });

  it('should return invalid for bad encryption type', () => {
    const data = createValidData();
    data[2] = 0x05; // invalid type
    const result = validateECIES(data);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('encryption type');
  });

  it('should return invalid for bad key prefix', () => {
    const data = createValidData();
    data[3] = 0x00; // invalid prefix
    const result = validateECIES(data);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('public key prefix');
  });
});

describe('getEncryptionTypeName', () => {
  it('should return "Basic" for type 33', () => {
    expect(getEncryptionTypeName(ECIESEncryptionType.Basic)).toBe('Basic');
    expect(getEncryptionTypeName(33)).toBe('Basic');
  });

  it('should return "WithLength" for type 66', () => {
    expect(getEncryptionTypeName(ECIESEncryptionType.WithLength)).toBe('WithLength');
    expect(getEncryptionTypeName(66)).toBe('WithLength');
  });

  it('should return "Multiple" for type 99', () => {
    expect(getEncryptionTypeName(ECIESEncryptionType.Multiple)).toBe('Multiple');
    expect(getEncryptionTypeName(99)).toBe('Multiple');
  });

  it('should return "Unknown(N)" for unknown types', () => {
    expect(getEncryptionTypeName(0)).toBe('Unknown(0)');
    expect(getEncryptionTypeName(255)).toBe('Unknown(255)');
  });
});

describe('ECIESEncryptionType enum', () => {
  it('should have correct values', () => {
    expect(ECIESEncryptionType.Basic).toBe(33);
    expect(ECIESEncryptionType.WithLength).toBe(66);
    expect(ECIESEncryptionType.Multiple).toBe(99);
  });

  it('should match hex values', () => {
    expect(ECIESEncryptionType.Basic).toBe(0x21);
    expect(ECIESEncryptionType.WithLength).toBe(0x42);
    expect(ECIESEncryptionType.Multiple).toBe(0x63);
  });
});
