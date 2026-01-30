# @digitaldefiance/enclave-bridge-client

TypeScript client for **Enclave Bridge** - a macOS app that bridges Node.js to Apple's Secure Enclave via Unix domain socket.

## Features

- 🔐 **Secure Enclave Integration** - Sign data with P-256 keys stored in Apple's Secure Enclave
- 🔑 **ECIES Encryption** - Encrypt/decrypt data with secp256k1 ECIES (compatible with `@digitaldefiance/node-ecies-lib`)
- 🔌 **Unix Socket IPC** - Fast local communication with the native macOS bridge app
- 📦 **TypeScript First** - Full type definitions included
- ⚡ **Async/Await** - Modern Promise-based API
- 🔄 **Auto-Reconnection** - Configurable reconnection with exponential backoff
- 📊 **Request Queuing** - Concurrent request handling with configurable limits
- 💾 **Key Caching** - Optional caching for frequently-used public keys
- 🌊 **Streaming Support** - Process large files with chunked encryption/decryption
- 🏊 **Connection Pooling** - Manage multiple connections for high-throughput scenarios

## Prerequisites

- macOS with Apple Silicon (M1/M2/M3/M4) chip
- [Enclave Bridge](https://github.com/Digital-Defiance/enclave-bridge/releases) macOS app running. Also available directly from [Apple App Store](https://apps.apple.com/us/app/enclave-bridge/id6758280835?mt=12).
- Node.js 18+

## Installation

```bash
npm install @digitaldefiance/enclave-bridge-client
```

### Optional Dependencies

For client-side encryption support, install:

```bash
npm install @digitaldefiance/node-ecies-lib
```

## Quick Start

```typescript
import { EnclaveBridgeClient } from '@digitaldefiance/enclave-bridge-client';

async function main() {
  // Create and connect client
  const client = new EnclaveBridgeClient();
  await client.connect();

  try {
    // Get the secp256k1 public key for ECIES encryption
    const publicKey = await client.getPublicKey();
    console.log('ECIES Public Key:', publicKey.hex);

    // Get the Secure Enclave P-256 public key
    const enclaveKey = await client.getEnclavePublicKey();
    console.log('Enclave Public Key:', enclaveKey.hex);

    // Sign data with Secure Enclave
    const signature = await client.enclaveSign(Buffer.from('Hello, Secure Enclave!'));
    console.log('Signature:', signature.hex);

    // Decrypt ECIES-encrypted data
    // (encrypted with the public key from getPublicKey())
    const decrypted = await client.decrypt(encryptedBuffer);
    console.log('Decrypted:', decrypted.text);
  } finally {
    await client.disconnect();
  }
}

main().catch(console.error);
```

## API Reference

### Constructor

```typescript
new EnclaveBridgeClient(options?: EnclaveBridgeClientOptions)
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `socketPath` | `string` | `/tmp/enclave-bridge.sock` | Path to Unix socket |
| `timeout` | `number` | `30000` | Operation timeout in ms |
| `autoReconnect` | `boolean` | `true` | Auto-reconnect on disconnect |
| `maxReconnectAttempts` | `number` | `5` | Max reconnection attempts |
| `reconnectDelay` | `number` | `1000` | Initial reconnect delay in ms |
| `maxReconnectDelay` | `number` | `30000` | Max reconnect delay (backoff cap) |
| `debug` | `boolean` | `false` | Enable verbose debug logging |
| `logger` | `function` | `console.log` | Custom logging function |
| `cacheKeys` | `boolean` | `true` | Cache public keys |
| `maxConcurrentRequests` | `number` | `1` | Max concurrent requests to server |
| `enableHeartbeat` | `boolean` | `false` | Enable automatic heartbeat |
| `heartbeatInterval` | `number` | `30000` | Heartbeat interval in ms |

### Static Methods

#### `EnclaveBridgeClient.isSupported(socketPath?): Promise<PlatformSupport>`

Check if the current platform supports Enclave Bridge.

```typescript
const support = await EnclaveBridgeClient.isSupported();
if (!support.supported) {
  console.log('Not supported:', support.reason);
}
```

### Connection Methods

#### `connect(): Promise<void>`

Connect to the EnclaveBridge socket server.

```typescript
await client.connect();
```

#### `disconnect(): Promise<void>`

Disconnect from the server.

```typescript
await client.disconnect();
```

#### `isConnected: boolean`

Check if currently connected.

#### `connectionState: ConnectionState`

Get current state: `'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'error'`

### Key Operations

#### `getPublicKey(): Promise<PublicKeyInfo>`

Get the secp256k1 public key used for ECIES operations. This key is persisted in the macOS Keychain.

```typescript
const key = await client.getPublicKey();
console.log(key.base64);  // Base64 encoded
console.log(key.hex);     // Hex encoded
console.log(key.buffer);  // Raw Buffer
```

#### `getEnclavePublicKey(): Promise<PublicKeyInfo>`

Get the Secure Enclave P-256 public key. The private key never leaves the Secure Enclave.

```typescript
const enclaveKey = await client.getEnclavePublicKey();
```

#### `setPeerPublicKey(publicKey: string | Buffer): Promise<void>`

Set a peer's public key for ECDH operations.

```typescript
await client.setPeerPublicKey(peerPublicKeyHex);
```

#### `listKeys(): Promise<KeyList>`

List all available keys (requires server support).

```typescript
const keys = await client.listKeys();
keys.keys.forEach(key => {
  console.log(key.keyId, key.keyType, key.createdAt);
});
```

#### `rotateKey(): Promise<KeyRotationResult>`

Rotate the current key (requires server support).

```typescript
const result = await client.rotateKey();
console.log('New key ID:', result.newKeyId);
```

### Cryptographic Operations

#### `enclaveSign(data: Buffer | string): Promise<SignatureResult>`

Sign data using the Secure Enclave P-256 key. The data is hashed with SHA-256 before signing.

```typescript
const signature = await client.enclaveSign('message to sign');
console.log(signature.hex);
```

#### `decrypt(encryptedData: Buffer): Promise<DecryptionResult>`

Decrypt ECIES-encrypted data. Compatible with `@digitaldefiance/node-ecies-lib` format.

```typescript
const result = await client.decrypt(encryptedBuffer);
console.log(result.text);    // As UTF-8 string
console.log(result.buffer);  // As Buffer
```

#### `encrypt(data: Buffer, publicKey: Buffer): Promise<Buffer>`

Encrypt data using ECIES (requires `@digitaldefiance/node-ecies-lib`).

```typescript
const publicKey = await client.getPublicKey();
const encrypted = await client.encrypt(
  Buffer.from('secret'),
  publicKey.buffer
);
```

#### `verifySignature(signature: Buffer, data: Buffer, publicKey: Buffer): Promise<boolean>`

Verify a P-256 signature.

```typescript
const isValid = await client.verifySignature(
  signatureBuffer,
  dataBuffer,
  publicKeyBuffer
);
```

#### `enclaveGenerateKey(): Promise<KeyGenerationResult>`

Generate a new ephemeral key.

```typescript
const newKey = await client.enclaveGenerateKey();
console.log(newKey.publicKey.hex);
```

### Server Commands

#### `heartbeat(): Promise<HeartbeatResponse>`

Send a heartbeat to the server.

```typescript
const response = await client.heartbeat();
console.log('Server time:', response.timestamp);
```

#### `getVersion(): Promise<ServerVersion>`

Get the server version information.

```typescript
const version = await client.getVersion();
console.log(version.version, version.protocol);
```

#### `getStatus(): Promise<ServerStatus>`

Get detailed server status.

```typescript
const status = await client.getStatus();
console.log(status.status, status.connections, status.uptime);
```

#### `getMetrics(): Promise<ServerMetrics>`

Get server performance metrics.

```typescript
const metrics = await client.getMetrics();
console.log('Total requests:', metrics.totalRequests);
```

#### `getHealthStatus(): Promise<HealthStatus>`

Get comprehensive health status.

```typescript
const health = await client.getHealthStatus();
console.log(health.isHealthy, health.uptime);
```

### Events

The client extends `EventEmitter` and emits:

| Event | Description | Payload |
|-------|-------------|---------|
| `connect` | Connected to bridge | None |
| `disconnect` | Disconnected from bridge | None |
| `error` | Error occurred | `Error` |
| `stateChange` | Connection state changed | `ConnectionState` |
| `reconnecting` | Attempting reconnection | `{ attempt, maxAttempts, delay }` |
| `reconnected` | Successfully reconnected | None |
| `reconnectFailed` | All reconnection attempts failed | None |
| `beforeDisconnect` | About to disconnect | None |
| `debug` | Debug log message | `{ message, meta }` |
| `requestSent` | Request sent to server | `{ command, payload }` |
| `responseReceived` | Response received | `response` |

```typescript
client.on('connect', () => console.log('Connected!'));
client.on('reconnecting', ({ attempt, maxAttempts }) => {
  console.log(`Reconnecting: attempt ${attempt}/${maxAttempts}`);
});
client.on('error', (err) => console.error('Error:', err));
```

## Advanced Usage

### Connection Pooling

For high-throughput scenarios, use the connection pool:

```typescript
import { ConnectionPool } from '@digitaldefiance/enclave-bridge-client';

const pool = new ConnectionPool({ poolSize: 3 });
await pool.initialize();

// Execute with automatic connection management
const signature = await pool.execute(async (client) => {
  return await client.enclaveSign('data');
});

// Or manually manage connections
const client = await pool.acquire();
try {
  await client.enclaveSign('data');
} finally {
  pool.release(client);
}

await pool.close();
```

### Streaming Support

For large files, use streaming to process data in chunks:

```typescript
import {
  encryptStream,
  decryptStream,
  encryptFile,
  decryptToFile
} from '@digitaldefiance/enclave-bridge-client/streaming';

// Encrypt a file with progress callback
await encryptFile(
  client,
  publicKey,
  '/path/to/input.txt',
  '/path/to/output.enc',
  { chunkSize: 1024 * 1024 }, // 1MB chunks
  (progress) => console.log(`${progress.percentage}% complete`)
);

// Decrypt a file
await decryptToFile(
  client,
  '/path/to/input.enc',
  '/path/to/output.txt'
);
```

### Auto-Reconnection

Configure automatic reconnection with exponential backoff:

```typescript
const client = new EnclaveBridgeClient({
  autoReconnect: true,
  maxReconnectAttempts: 10,
  reconnectDelay: 500,       // Start at 500ms
  maxReconnectDelay: 60000,  // Cap at 60 seconds
});

client.on('reconnecting', ({ attempt, delay }) => {
  console.log(`Reconnecting in ${delay}ms (attempt ${attempt})`);
});

client.on('reconnected', () => {
  console.log('Successfully reconnected!');
});

client.on('reconnectFailed', () => {
  console.error('All reconnection attempts failed');
});
```

### Request Queuing

Multiple concurrent requests are automatically queued:

```typescript
const client = new EnclaveBridgeClient({
  maxConcurrentRequests: 1, // Serialize requests
});

// These will be queued and processed sequentially
const [key1, key2, sig] = await Promise.all([
  client.getPublicKey(),
  client.getEnclavePublicKey(),
  client.enclaveSign('data'),
]);
```

### Debug Logging

Enable verbose logging for troubleshooting:

```typescript
const client = new EnclaveBridgeClient({
  debug: true,
  logger: (level, message, meta) => {
    console.log(`[${level}] ${message}`, meta);
  },
});

client.on('debug', (message, meta) => {
  // Handle debug events
});
```

## Custom Error Types

The library provides specific error types for better error handling:

```typescript
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
} from '@digitaldefiance/enclave-bridge-client';

try {
  await client.connect();
} catch (err) {
  if (err instanceof ConnectionError) {
    console.error('Connection failed:', err.code);
  } else if (err instanceof TimeoutError) {
    console.error('Timed out:', err.operation, err.timeoutMs);
  } else if (err instanceof PlatformError) {
    console.error('Platform not supported:', err.message);
  }
}
```

## ECIES Format

The client uses the `@digitaldefiance/node-ecies-lib` ECIES format:

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | Protocol version |
| Cipher Suite | 1 byte | Cipher suite identifier |
| Encryption Type | 1 byte | 33=Basic, 66=WithLength, 99=Multiple |
| Ephemeral Public Key | 33 bytes | Compressed secp256k1 key |
| IV | 12 bytes | Initialization vector |
| Auth Tag | 16 bytes | GCM authentication tag |
| Ciphertext | Variable | Encrypted data |

## Protocol

Communication uses a JSON-based protocol over Unix domain socket:

**Request Format:**
```json
{ "cmd": "COMMAND_NAME", "data": "optional_payload" }
```

**Response Format:**
```json
{ "publicKey": "base64_data" }  // Success
{ "error": "error_message" }     // Error
```

### Commands

| Command | Payload | Description |
|---------|---------|-------------|
| `GET_PUBLIC_KEY` | None | Get secp256k1 public key |
| `GET_ENCLAVE_PUBLIC_KEY` | None | Get Secure Enclave P-256 key |
| `SET_PEER_PUBLIC_KEY` | `{ publicKey }` | Store peer's public key |
| `ENCLAVE_SIGN` | `{ data }` | Sign with Secure Enclave |
| `ENCLAVE_DECRYPT` | `{ data }` | Decrypt ECIES data |
| `ENCLAVE_GENERATE_KEY` | None | Generate new key |
| `HEARTBEAT` | None | Server heartbeat |
| `VERSION` | None | Get server version |
| `STATUS` | None | Get server status |
| `METRICS` | None | Get server metrics |
| `LIST_KEYS` | None | List available keys |
| `ENCLAVE_ROTATE_KEY` | None | Rotate current key |

## Example: Encrypt in Node.js, Decrypt in Secure Enclave

```typescript
import { eciesEncrypt } from '@digitaldefiance/node-ecies-lib';
import { EnclaveBridgeClient } from '@digitaldefiance/enclave-bridge-client';

async function encryptAndDecrypt() {
  const client = new EnclaveBridgeClient();
  await client.connect();

  // Get the bridge's public key
  const { buffer: publicKey } = await client.getPublicKey();

  // Encrypt a message using node-ecies-lib
  const message = Buffer.from('Secret message');
  const encrypted = eciesEncrypt(publicKey, message);

  // Decrypt using the Secure Enclave bridge
  const decrypted = await client.decrypt(encrypted);
  console.log('Decrypted:', decrypted.text); // "Secret message"

  await client.disconnect();
}
```

## Security Considerations

- **Secure Enclave Keys**: Private keys for P-256 operations never leave the Secure Enclave hardware
- **secp256k1 Keys**: Stored in macOS Keychain with access control
- **Local Only**: Communication is via Unix domain socket (local only)
- **No Network**: The bridge does not expose any network interfaces
- **Key Caching**: Public keys can be cached in memory to reduce socket calls

## Migration Guide

### From v1.x to v2.x

The v2.x release adds new features while maintaining backward compatibility:

1. **Connection State**: Now includes `'reconnecting'` state
2. **Error Types**: Use specific error classes for better handling
3. **Event Names**: New events added (`reconnecting`, `reconnected`, `debug`, etc.)

No breaking changes - existing code continues to work.

## License

MIT
