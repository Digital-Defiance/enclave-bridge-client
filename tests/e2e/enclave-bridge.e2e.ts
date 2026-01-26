#!/usr/bin/env npx tsx
/**
 * E2E Test for EnclaveBridge Client
 *
 * This test requires:
 * 1. The EnclaveBridge macOS app to be running
 * 2. @digitaldefiance/node-ecies-lib to be installed
 *
 * Usage:
 *   npx tsx tests/e2e/enclave-bridge.e2e.ts
 *
 * Or via npm script:
 *   npm run test:e2e
 */

import { EnclaveBridgeClient, parseECIES, ECIESEncryptionType } from '../../src/index.js';

// Detect if running in sandboxed app or not
const SOCKET_PATHS = [
  // Sandboxed app path
  `${process.env.HOME}/Library/Containers/com.JessicaMulein.EnclaveBridge/Data/.enclave/enclave-bridge.sock`,
  // Non-sandboxed path
  `${process.env.HOME}/.enclave/enclave-bridge.sock`,
  // Default path
  '/tmp/enclave-bridge.sock',
];

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
  duration: number;
}

const results: TestResult[] = [];

async function findSocketPath(): Promise<string | null> {
  const fs = await import('node:fs/promises');

  for (const socketPath of SOCKET_PATHS) {
    try {
      await fs.access(socketPath);
      console.log(`Found socket at: ${socketPath}`);
      return socketPath;
    } catch {
      // Try next path
    }
  }
  return null;
}

async function runTest(name: string, fn: () => Promise<void>): Promise<void> {
  const start = Date.now();
  try {
    await fn();
    results.push({ name, passed: true, duration: Date.now() - start });
    console.log(`  ✓ ${name} (${Date.now() - start}ms)`);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    results.push({ name, passed: false, error: errorMsg, duration: Date.now() - start });
    console.log(`  ✗ ${name}: ${errorMsg}`);
  }
}

async function main() {
  console.log('=== EnclaveBridge E2E Tests ===\n');

  // Find socket path
  const socketPath = await findSocketPath();
  if (!socketPath) {
    console.error('ERROR: EnclaveBridge socket not found. Is the app running?');
    console.error('Expected paths:');
    SOCKET_PATHS.forEach((p) => console.error(`  - ${p}`));
    process.exit(1);
  }

  let client: EnclaveBridgeClient | null = null;
  let bridgePublicKey: Buffer | null = null;

  try {
    // Test: Connection
    console.log('Connection Tests:');
    await runTest('Should connect to EnclaveBridge', async () => {
      client = new EnclaveBridgeClient({ socketPath, timeout: 10000 });
      await client.connect();
      if (!client.isConnected) {
        throw new Error('Client reports not connected');
      }
    });

    await runTest('Should report correct connection state', async () => {
      const info = client!.getConnectionInfo();
      if (info.state !== 'connected') {
        throw new Error(`Expected state 'connected', got '${info.state}'`);
      }
      if (!info.isConnected) {
        throw new Error('Expected isConnected to be true');
      }
    });

    // Test: Public Key Operations
    console.log('\nPublic Key Tests:');
    await runTest('Should get secp256k1 public key', async () => {
      const result = await client!.getPublicKey();
      bridgePublicKey = result.buffer;

      if (result.buffer.length !== 33) {
        throw new Error(`Expected 33-byte compressed key, got ${result.buffer.length} bytes`);
      }
      if (result.buffer[0] !== 0x02 && result.buffer[0] !== 0x03) {
        throw new Error(`Invalid key prefix: 0x${result.buffer[0].toString(16)}`);
      }
      if (!result.compressed) {
        throw new Error('Key should be marked as compressed');
      }

      console.log(`    Public key: ${result.hex.slice(0, 20)}...`);
    });

    await runTest('Should get Secure Enclave public key', async () => {
      const result = await client!.getEnclavePublicKey();

      // P-256 keys can be compressed (33 bytes) or uncompressed (65 bytes)
      if (result.buffer.length !== 33 && result.buffer.length !== 65) {
        throw new Error(`Unexpected key length: ${result.buffer.length} bytes`);
      }

      console.log(`    Enclave key: ${result.hex.slice(0, 20)}...`);
    });

    await runTest('Should set peer public key', async () => {
      // Generate a test peer public key (just for protocol test)
      const testPeerKey = Buffer.alloc(33);
      testPeerKey[0] = 0x02;
      for (let i = 1; i < 33; i++) testPeerKey[i] = i;

      await client!.setPeerPublicKey(testPeerKey);
    });

    // Test: Signing
    console.log('\nSigning Tests:');
    await runTest('Should sign data with Secure Enclave', async () => {
      const testMessage = Buffer.from('Test message for signing');
      const result = await client!.enclaveSign(testMessage);

      if (result.buffer.length === 0) {
        throw new Error('Empty signature returned');
      }

      console.log(`    Signature: ${result.hex.slice(0, 30)}... (${result.buffer.length} bytes)`);
    });

    await runTest('Should sign string data', async () => {
      const result = await client!.enclaveSign('String message');
      if (result.buffer.length === 0) {
        throw new Error('Empty signature returned');
      }
    });

    // Test: ECIES Decryption (requires node-ecies-lib)
    console.log('\nECIES Decryption Tests:');

    let eciesLib: typeof import('@digitaldefiance/node-ecies-lib') | null = null;
    try {
      eciesLib = await import('@digitaldefiance/node-ecies-lib');
    } catch {
      console.log('  ⚠ Skipping ECIES tests - @digitaldefiance/node-ecies-lib not installed');
    }

    if (eciesLib && bridgePublicKey) {
      await runTest('Should decrypt ECIES-encrypted message', async () => {
        const ecies = new eciesLib!.ECIESService();
        const testMessage = Buffer.from('Hello from E2E test!');

        // Encrypt using node-ecies-lib
        const encrypted = await ecies.encryptBasic(bridgePublicKey!, testMessage);

        console.log(`    Encrypted: ${encrypted.length} bytes`);

        // Decrypt using the bridge
        const result = await client!.decrypt(encrypted);

        if (result.text !== 'Hello from E2E test!') {
          throw new Error(`Decryption mismatch: got "${result.text}"`);
        }

        console.log(`    Decrypted: "${result.text}"`);
      });

      await runTest('Should handle ECIES format correctly', async () => {
        const ecies = new eciesLib!.ECIESService();
        const testMessage = Buffer.from('Format test message');

        const encrypted = await ecies.encryptBasic(bridgePublicKey!, testMessage);

        // Parse and verify format
        const parsed = parseECIES(encrypted);

        if (parsed.encryptionType !== ECIESEncryptionType.Basic) {
          throw new Error(`Expected Basic (33), got ${parsed.encryptionType}`);
        }
        if (parsed.iv.length !== 12) {
          throw new Error(`Expected 12-byte IV, got ${parsed.iv.length}`);
        }
        if (parsed.authTag.length !== 16) {
          throw new Error(`Expected 16-byte auth tag, got ${parsed.authTag.length}`);
        }
      });

      await runTest('Should decrypt larger messages', async () => {
        const ecies = new eciesLib!.ECIESService();
        const largeMessage = Buffer.alloc(1024, 'A');

        const encrypted = await ecies.encryptBasic(bridgePublicKey!, largeMessage);
        const result = await client!.decrypt(encrypted);

        if (result.buffer.length !== 1024) {
          throw new Error(`Expected 1024 bytes, got ${result.buffer.length}`);
        }
        if (!result.buffer.every((b) => b === 65)) {
          // 65 = 'A'
          throw new Error('Decrypted content mismatch');
        }
      });
    }

    // Test: Ping utility
    console.log('\nUtility Tests:');
    await runTest('Should ping successfully', async () => {
      const pingResult = await client!.ping();
      if (!pingResult) {
        throw new Error('Ping returned false');
      }
    });

    // Test: Disconnection
    console.log('\nDisconnection Tests:');
    await runTest('Should disconnect cleanly', async () => {
      await client!.disconnect();
      if (client!.isConnected) {
        throw new Error('Client still reports connected after disconnect');
      }
    });

    await runTest('Should report disconnected state', async () => {
      const info = client!.getConnectionInfo();
      if (info.state !== 'disconnected') {
        throw new Error(`Expected state 'disconnected', got '${info.state}'`);
      }
    });
  } catch (error) {
    console.error('\nFatal error:', error);
  } finally {
    // Ensure disconnection
    if (client?.isConnected) {
      await client.disconnect();
    }
  }

  // Print summary
  console.log('\n=== Test Summary ===');
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Total:  ${results.length}`);

  if (failed > 0) {
    console.log('\nFailed tests:');
    results
      .filter((r) => !r.passed)
      .forEach((r) => {
        console.log(`  - ${r.name}: ${r.error}`);
      });
    process.exit(1);
  }

  console.log('\n✓ All tests passed!');
  process.exit(0);
}

main().catch((error) => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
