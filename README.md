# @digitaldefiance/enclave-bridge-client

TypeScript client for **Enclave Bridge** - a macOS app that bridges Node.js to Apple's Secure Enclave via Unix domain socket.

## Features

- 🔐 **Secure Enclave Integration** - Sign data with P-256 keys stored in Apple's Secure Enclave
- 🔑 **ECIES Encryption** - Decrypt data encrypted with secp256k1 ECIES (compatible with `@digitaldefiance/node-ecies-lib`)
- 🔌 **Unix Socket IPC** - Fast local communication with the native macOS bridge app
- 📦 **TypeScript First** - Full type definitions included
- ⚡ **Async/Await** - Modern Promise-based API

## Prerequisites

- macOS with Apple Silicon (M1/M2/M3) or T2 chip
- [Enclave Bridge](https://github.com/Digital-Defiance/enclave-bridge/releases) macOS app running
- Node.js 18+

## Installation

```bash
npm install @digitaldefiance/enclave-bridge-client
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
- `socketPath` - Path to Unix socket (default: `/tmp/enclave-bridge.sock`)
- `timeout` - Operation timeout in ms (default: 30000)

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

Get current state: `'disconnected' | 'connecting' | 'connected' | 'error'`

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

#### `enclaveGenerateKey(): Promise<KeyGenerationResult>`

Generate a new ephemeral key.

```typescript
const newKey = await client.enclaveGenerateKey();
console.log(newKey.publicKey.hex);
```

### Events

The client extends `EventEmitter` and emits:

- `connect` - Connected to bridge
- `disconnect` - Disconnected from bridge
- `error` - Error occurred
- `stateChange` - Connection state changed

```typescript
client.on('connect', () => console.log('Connected!'));
client.on('error', (err) => console.error('Error:', err));
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

Communication uses a simple text-based protocol over Unix domain socket:

**Request:** `COMMAND:base64_payload\n`

**Response:** `OK:base64_result\n` or `ERROR:message\n`

### Commands

| Command | Payload | Description |
|---------|---------|-------------|
| `GET_PUBLIC_KEY` | None | Get secp256k1 public key |
| `GET_ENCLAVE_PUBLIC_KEY` | None | Get Secure Enclave P-256 key |
| `SET_PEER_PUBLIC_KEY` | Base64 public key | Store peer's public key |
| `ENCLAVE_SIGN` | Base64 data | Sign with Secure Enclave |
| `ENCLAVE_DECRYPT` | Base64 ciphertext | Decrypt ECIES data |
| `ENCLAVE_GENERATE_KEY` | None | Generate new key |

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

## License

MIT
