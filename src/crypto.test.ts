/**
 * Tests for cryptographic utilities
 */

import { describe, it, expect } from 'vitest';
import { sha256, verifyP256Signature } from '../src/crypto.js';
import { createSign, generateKeyPairSync } from 'node:crypto';

describe('Crypto Utilities', () => {
  describe('sha256', () => {
    it('should hash string data', () => {
      const hash = sha256('hello world');
      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.length).toBe(32);
      expect(hash.toString('hex')).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });

    it('should hash buffer data', () => {
      const hash = sha256(Buffer.from('hello world'));
      expect(hash).toBeInstanceOf(Buffer);
      expect(hash.toString('hex')).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });
  });

  describe('verifyP256Signature', () => {
    it('should verify valid P-256 signature', () => {
      // Generate test keypair
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1', // P-256
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });

      // Extract raw public key from DER (skip ASN.1 headers)
      // For uncompressed P-256, the public key is 65 bytes starting with 0x04
      const publicKeyBuffer = Buffer.from(publicKey);
      const rawPublicKey = publicKeyBuffer.subarray(publicKeyBuffer.length - 65);

      // Sign data
      const data = Buffer.from('test data');
      const sign = createSign('SHA256');
      sign.update(sha256(data));
      sign.end();
      const signature = sign.sign({ key: privateKey, format: 'der', type: 'pkcs8' });

      // Verify
      const isValid = verifyP256Signature(data, signature, rawPublicKey);
      expect(isValid).toBe(true);
    });

    it('should reject invalid signature', () => {
      // Generate test keypair
      const { publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });

      const publicKeyBuffer = Buffer.from(publicKey);
      const rawPublicKey = publicKeyBuffer.subarray(publicKeyBuffer.length - 65);

      const data = Buffer.from('test data');
      const invalidSignature = Buffer.alloc(64);

      const isValid = verifyP256Signature(data, invalidSignature, rawPublicKey);
      expect(isValid).toBe(false);
    });

    it('should handle string data', () => {
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });

      const publicKeyBuffer = Buffer.from(publicKey);
      const rawPublicKey = publicKeyBuffer.subarray(publicKeyBuffer.length - 65);

      const data = 'test string';
      const sign = createSign('SHA256');
      sign.update(sha256(data));
      sign.end();
      const signature = sign.sign({ key: privateKey, format: 'der', type: 'pkcs8' });

      const isValid = verifyP256Signature(data, signature, rawPublicKey);
      expect(isValid).toBe(true);
    });
  });
});
