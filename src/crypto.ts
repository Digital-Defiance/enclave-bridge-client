/**
 * Cryptographic utilities for EnclaveBridge Client
 * 
 * These utilities provide client-side encryption and signature verification
 * without requiring the Enclave Bridge connection.
 */

import { createVerify, createHash } from 'node:crypto';
import { DecryptionError, EncryptionError, SignatureError } from './errors.js';

/**
 * Encrypt data using ECIES with a recipient's public key
 * 
 * This is a convenience wrapper around @digitaldefiance/node-ecies-lib.
 * Encryption doesn't require the Secure Enclave - only decryption does.
 * 
 * @param recipientPublicKey - Recipient's secp256k1 public key (33 or 65 bytes)
 * @param data - Data to encrypt
 * @returns Encrypted data buffer
 * @throws EncryptionError if encryption fails
 */
export async function encrypt(recipientPublicKey: Buffer, data: Buffer | string): Promise<Buffer> {
  try {
    // Dynamically import node-ecies-lib to avoid peer dependency issues
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const eciesModule = await import('@digitaldefiance/node-ecies-lib');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const encryptFn = (eciesModule as any).encrypt;
    
    const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    return encryptFn(recipientPublicKey, dataBuffer) as Buffer;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'MODULE_NOT_FOUND') {
      throw new EncryptionError(
        'node-ecies-lib is required for client-side encryption. Install with: npm install @digitaldefiance/node-ecies-lib',
        { originalError: err }
      );
    }
    throw new EncryptionError(
      err instanceof Error ? err.message : 'Encryption failed',
      { originalError: err }
    );
  }
}

/**
 * Verify a P-256 (NIST secp256r1) signature from the Secure Enclave
 * 
 * @param data - Original data that was signed
 * @param signature - DER-encoded signature from Secure Enclave
 * @param publicKey - P-256 public key (65 bytes uncompressed or 33 bytes compressed)
 * @returns True if signature is valid
 * @throws SignatureError if verification fails
 */
export function verifyP256Signature(
  data: Buffer | string,
  signature: Buffer,
  publicKey: Buffer
): boolean {
  try {
    const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    
    // Hash the data with SHA-256 (Secure Enclave uses SHA-256)
    const hash = createHash('sha256').update(dataBuffer).digest();
    
    // P-256 public key in PEM format
    let pemKey: string;
    if (publicKey.length === 65 && publicKey[0] === 0x04) {
      // Uncompressed public key (0x04 prefix)
      pemKey = publicKeyToPEM(publicKey, false);
    } else if (publicKey.length === 33 && (publicKey[0] === 0x02 || publicKey[0] === 0x03)) {
      // Compressed public key
      pemKey = publicKeyToPEM(publicKey, true);
    } else {
      throw new SignatureError('Invalid P-256 public key format', { 
        keyLength: publicKey.length,
        prefix: publicKey[0]
      });
    }
    
    const verify = createVerify('SHA256');
    verify.update(hash);
    return verify.verify(pemKey, signature);
  } catch (err) {
    if (err instanceof SignatureError) {
      throw err;
    }
    throw new SignatureError(
      err instanceof Error ? err.message : 'Signature verification failed',
      { originalError: err }
    );
  }
}

/**
 * Convert a raw P-256 public key to PEM format
 * 
 * @param publicKey - Raw public key bytes
 * @param compressed - Whether the key is compressed
 * @returns PEM-formatted public key
 */
function publicKeyToPEM(publicKey: Buffer, compressed: boolean): string {
  // P-256 OID: 1.2.840.10045.3.1.7
  const p256Oid = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  
  // EC public key OID: 1.2.840.10045.2.1
  const ecPublicKeyOid = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  
  // Build the ASN.1 structure for the public key
  const algorithmIdentifier = Buffer.concat([
    Buffer.from([0x30, ecPublicKeyOid.length + p256Oid.length]), // SEQUENCE
    ecPublicKeyOid,
    p256Oid
  ]);
  
  const publicKeyBitString = Buffer.concat([
    Buffer.from([0x03, publicKey.length + 1, 0x00]), // BIT STRING with no unused bits
    publicKey
  ]);
  
  const subjectPublicKeyInfo = Buffer.concat([
    Buffer.from([0x30, algorithmIdentifier.length + publicKeyBitString.length]), // SEQUENCE
    algorithmIdentifier,
    publicKeyBitString
  ]);
  
  const base64 = subjectPublicKeyInfo.toString('base64');
  const pem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----\n`;
  
  return pem;
}

/**
 * Hash data with SHA-256
 * 
 * @param data - Data to hash
 * @returns SHA-256 hash
 */
export function sha256(data: Buffer | string): Buffer {
  const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return createHash('sha256').update(dataBuffer).digest();
}
