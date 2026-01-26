/**
 * Streaming utilities for large payload encryption/decryption
 * 
 * Handles chunked operations with progress callbacks.
 */

import type { EnclaveBridgeClient } from './index.js';
import { EncryptionError, DecryptionError } from './errors.js';

export interface StreamOptions {
  /**
   * Chunk size in bytes
   * @default 65536 (64KB)
   */
  chunkSize?: number;

  /**
   * Progress callback
   */
  onProgress?: (processed: number, total: number) => void;
}

/**
 * Encrypt large data in chunks
 * 
 * @param client - EnclaveBridge client
 * @param data - Data to encrypt
 * @param recipientPublicKey - Recipient's public key
 * @param options - Streaming options
 * @returns Promise resolving to encrypted chunks
 */
export async function encryptStream(
  client: EnclaveBridgeClient,
  data: Buffer,
  recipientPublicKey?: Buffer,
  options: StreamOptions = {}
): Promise<Buffer[]> {
  const chunkSize = options.chunkSize ?? 65536;
  const total = data.length;
  const chunks: Buffer[] = [];

  try {
    for (let offset = 0; offset < total; offset += chunkSize) {
      const end = Math.min(offset + chunkSize, total);
      const chunk = data.subarray(offset, end);

      const encrypted = await client.encrypt(chunk, recipientPublicKey);
      chunks.push(encrypted);

      if (options.onProgress) {
        options.onProgress(end, total);
      }
    }

    return chunks;
  } catch (err) {
    throw new EncryptionError(
      `Stream encryption failed: ${err instanceof Error ? err.message : String(err)}`,
      { originalError: err }
    );
  }
}

/**
 * Decrypt large data from chunks
 * 
 * @param client - EnclaveBridge client
 * @param encryptedChunks - Encrypted data chunks
 * @param options - Streaming options
 * @returns Promise resolving to decrypted data
 */
export async function decryptStream(
  client: EnclaveBridgeClient,
  encryptedChunks: Buffer[],
  options: StreamOptions = {}
): Promise<Buffer> {
  const total = encryptedChunks.length;
  const decryptedChunks: Buffer[] = [];

  try {
    for (let i = 0; i < total; i++) {
      const chunk = encryptedChunks[i];
      const decrypted = await client.decrypt(chunk);
      decryptedChunks.push(decrypted.buffer);

      if (options.onProgress) {
        options.onProgress(i + 1, total);
      }
    }

    return Buffer.concat(decryptedChunks);
  } catch (err) {
    throw new DecryptionError(
      `Stream decryption failed: ${err instanceof Error ? err.message : String(err)}`,
      { originalError: err }
    );
  }
}

/**
 * Stream encryption helper for files
 * 
 * @param client - EnclaveBridge client
 * @param filePath - Path to file to encrypt
 * @param recipientPublicKey - Recipient's public key
 * @param options - Streaming options
 * @returns Promise resolving to encrypted chunks
 */
export async function encryptFile(
  client: EnclaveBridgeClient,
  filePath: string,
  recipientPublicKey?: Buffer,
  options: StreamOptions = {}
): Promise<Buffer[]> {
  const fs = await import('node:fs/promises');
  const data = await fs.readFile(filePath);
  return encryptStream(client, data, recipientPublicKey, options);
}

/**
 * Stream decryption helper for files
 * 
 * @param client - EnclaveBridge client
 * @param encryptedChunks - Encrypted data chunks
 * @param outputPath - Path to write decrypted file
 * @param options - Streaming options
 * @returns Promise resolving when file is written
 */
export async function decryptToFile(
  client: EnclaveBridgeClient,
  encryptedChunks: Buffer[],
  outputPath: string,
  options: StreamOptions = {}
): Promise<void> {
  const fs = await import('node:fs/promises');
  const decrypted = await decryptStream(client, encryptedChunks, options);
  await fs.writeFile(outputPath, decrypted);
}
