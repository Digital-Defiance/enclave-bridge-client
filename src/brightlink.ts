/**
 * BrightLink v1 cryptographic helpers — pure functions, no transport.
 *
 * Source of truth: docs/rfc-brightlink.md (the BrightLink RFC).
 *
 * This module exports the byte-level primitives the BrightLink registration
 * handshake depends on:
 *
 *   - `buildLinkRegisterEnvelope` — constructs the §4.5.1 plaintext and
 *     ECIES-encrypts it (Basic mode, type 0x21) to the bridge's persistent
 *     secp256k1 public key.
 *   - `decryptLinkResponseEnvelope` — peels the ECIES envelope the bridge
 *     returns in `responseEnvelope` to recover bridgeShare.
 *   - `deriveSessionKey` — the §4.5.2 bilateral HKDF-SHA256.
 *   - `buildTranscript` — the §4.5.3 canonical 238-byte transcript.
 *   - `verifyTranscriptSignature` — DER ECDSA verify against the bridge's
 *     SEP-issued P-256 public key (Apple CryptoKit hashes internally with
 *     SHA-256, matching Node's `createVerify('SHA256')` behavior per
 *     EBP/1 §4.9).
 *
 * These functions are stateless. They are tested independently from the
 * transport in `brightlink.test.ts`. The class-level `EnclaveBridgeClient.linkRegister`
 * method composes them with the existing `sendCommand` plumbing.
 */

import { Buffer } from 'node:buffer';
import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  createVerify,
  randomBytes,
} from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

// ────────────────────────────────────────────────────────────────────────────
// Constants — pinned from RFC v3
// ────────────────────────────────────────────────────────────────────────────

/** BrightLink protocol version this client speaks. */
export const LINK_PROTOCOL_VERSION = 1;

/** HKDF info string for the bilateral session-key derivation (RFC §4.5.2).
 *  CRITICAL: this is the BrightLink v1 string. A typo here breaks all
 *  LINK_DELIVER traffic with no useful diagnostic. */
export const LINK_SESSION_KEY_HKDF_INFO = 'brightlink-session-key-v1';

/** Maximum granted session TTL (RFC §4.1). */
export const LINK_MAX_TTL_SECONDS = 8 * 3600;

/** Length of `clientNonce` (RFC §4.5). */
export const LINK_CLIENT_NONCE_LENGTH = 16;
/** Length of each share / session id (RFC §4.5.1, §4.5.2). */
export const LINK_SHARE_LENGTH = 32;
export const LINK_SESSION_ID_LENGTH = 16;
export const LINK_SESSION_KEY_LENGTH = 32;

/** Total canonical-transcript byte length (RFC §4.5.3). */
export const LINK_TRANSCRIPT_TOTAL_LENGTH = 238;

/** Literal NUL-terminated header for the canonical transcript (RFC §4.5.3). */
const TRANSCRIPT_HEADER = Buffer.concat([
  Buffer.from('BrightLink v1 transcript', 'utf8'),
  Buffer.from([0x00]),
]);

// ECIES constants — for the outer BrightLink envelope (DD-ECIES Basic mode 0x21).
const ECIES_HKDF_INFO = 'ecies-v2-key-derivation';
const ECIES_HKDF_OUTPUT_LENGTH = 32;
const ECIES_IV_SIZE = 12;
const ECIES_AUTH_TAG_SIZE = 16;
const ECIES_VERSION_BYTE = 0x01;
const ECIES_CIPHER_SUITE_BYTE = 0x01;
const ECIES_TYPE_BASIC = 0x21;
const ECIES_PUB_COMPRESSED_LEN = 33;

// ────────────────────────────────────────────────────────────────────────────
// LINK_REGISTER envelope (client → bridge)
// ────────────────────────────────────────────────────────────────────────────

/**
 * The plaintext schema of the §4.5.1 LINK_REGISTER envelope.
 * After construction, this object is JSON-serialised, then ECIES-encrypted.
 */
export interface LinkRegisterPlaintext {
  v: 1;
  /** 65-byte uncompressed secp256k1 public key, base64-encoded. */
  clientPub: string;
  /** 32-byte random share, base64-encoded. */
  clientShare: string;
  /** BrightDate scalar (days since J2000.0). */
  issuedAtBd: number;
  /** Requested TTL in seconds. */
  ttlSeconds: number;
  /** Free-form agent identification. */
  agent: { name: string; version: string; platform: string };
}

/**
 * Build a complete LINK_REGISTER request: generates client material,
 * builds the §4.5.1 plaintext, ECIES-encrypts it to the bridge's
 * persistent secp256k1 public key, and returns the request payload
 * along with the per-registration secrets the caller will need to
 * complete the handshake.
 *
 * The caller MUST pass the result.envelopeRequest to the bridge as
 * `LINK_REGISTER`, then use result.clientNonce / clientShare /
 * ephemeralPriv / ephemeralPub when verifying the bridge's response.
 *
 * @param bridgePubUncompressed The bridge's persistent secp256k1 public key
 *   in 65-byte uncompressed form (from GET_PUBLIC_KEY).
 * @param opts Optional overrides (defaults are fresh randomness).
 */
export function buildLinkRegisterEnvelope(
  bridgePubUncompressed: Buffer,
  opts: {
    ttlSeconds?: number;
    issuedAtBd?: number;
    agent?: { name: string; version: string; platform: string };
    /** Override RNG (testing). */
    rng?: (n: number) => Buffer;
    /** Override client-generated material (testing). */
    clientNonce?: Buffer;
    clientShare?: Buffer;
    ephemeralPriv?: Buffer;
  } = {},
): {
  /** The JSON request payload to pass to the bridge as LINK_REGISTER. */
  request: {
    cmd: 'LINK_REGISTER';
    protocolVersion: 1;
    clientNonce: string;
    envelope: string;
  };
  /** The clientNonce — needed to verify the bridge's transcript. */
  clientNonce: Buffer;
  /** The clientShare — needed to derive K_session. */
  clientShare: Buffer;
  /** The ephemeral secp256k1 private key — needed to decrypt the
   *  bridge's responseEnvelope. */
  ephemeralPriv: Buffer;
  /** The ephemeral secp256k1 public key (65-byte uncompressed) —
   *  needed to verify the bridge's transcript. */
  ephemeralPub: Buffer;
  /** The issuedAtBd actually sent — needed to verify the transcript. */
  issuedAtBd: number;
} {
  const rng = opts.rng ?? ((n: number) => Buffer.from(randomBytes(n)));
  const clientNonce = opts.clientNonce ?? rng(LINK_CLIENT_NONCE_LENGTH);
  const clientShare = opts.clientShare ?? rng(LINK_SHARE_LENGTH);

  // Generate ephemeral keypair. RNG must produce a valid private key.
  let ephPriv: Buffer = opts.ephemeralPriv ?? rng(32);
  if (opts.ephemeralPriv === undefined) {
    // Validate / retry on the (vanishingly improbable) out-of-range scalar.
    let attempts = 0;
    while (attempts < 4) {
      try {
        secp256k1.getPublicKey(ephPriv, false);
        break;
      } catch {
        ephPriv = rng(32);
        attempts++;
      }
    }
  }
  const ephPub = Buffer.from(secp256k1.getPublicKey(ephPriv, false));
  if (ephPub.length !== 65) {
    throw new Error(`internal: secp256k1 uncompressed pub not 65 bytes (${ephPub.length})`);
  }

  const issuedAtBd =
    opts.issuedAtBd ?? Math.floor(Date.now() / 1000) / 86400;
  const ttlSeconds = opts.ttlSeconds ?? 3600;
  const agent = opts.agent ?? {
    name: 'enclave-bridge-client',
    version: '1.2.0',
    platform: `node-${process.platform}-${process.arch}`,
  };

  const plaintext: LinkRegisterPlaintext = {
    v: LINK_PROTOCOL_VERSION,
    clientPub: ephPub.toString('base64'),
    clientShare: clientShare.toString('base64'),
    issuedAtBd,
    ttlSeconds,
    agent,
  };

  const envelope = encryptBasicEnvelope(
    Buffer.from(JSON.stringify(plaintext), 'utf8'),
    bridgePubUncompressed,
    rng,
  );

  return {
    request: {
      cmd: 'LINK_REGISTER',
      protocolVersion: LINK_PROTOCOL_VERSION,
      clientNonce: clientNonce.toString('base64'),
      envelope: envelope.toString('base64'),
    },
    clientNonce,
    clientShare,
    ephemeralPriv: ephPriv,
    ephemeralPub: ephPub,
    issuedAtBd,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Bridge response: decrypt the responseEnvelope
// ────────────────────────────────────────────────────────────────────────────

/**
 * Peel a DD-ECIES Basic-mode envelope (the bridge's `responseEnvelope`)
 * to recover its plaintext. The bridge encrypts `bridgeShare` (32 bytes)
 * to the client's ephemeral public key in Basic mode (type 0x21).
 *
 * Strict 33-byte-only ephemeral key per RFC §15 (Compatibility posture).
 * The DD-ECIES §5.3 65/64-byte tolerance is not honored.
 */
export function decryptLinkResponseEnvelope(
  envelope: Buffer,
  recipientPriv: Buffer,
): Buffer {
  if (envelope.length < 64) {
    throw new Error('responseEnvelope too short');
  }
  if (envelope[0] !== ECIES_VERSION_BYTE) {
    throw new Error(`bad version byte 0x${envelope[0].toString(16)}`);
  }
  if (envelope[1] !== ECIES_CIPHER_SUITE_BYTE) {
    throw new Error(`bad cipher-suite byte 0x${envelope[1].toString(16)}`);
  }
  if (envelope[2] !== ECIES_TYPE_BASIC) {
    throw new Error(`responseEnvelope must be Basic mode (0x21), got 0x${envelope[2].toString(16)}`);
  }
  const prefix = envelope[3];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error(
      `responseEnvelope ephemeral key must be 33-byte compressed; got prefix 0x${prefix.toString(16)}`,
    );
  }
  const ephPub = envelope.subarray(3, 3 + ECIES_PUB_COMPRESSED_LEN);
  const iv = envelope.subarray(36, 48);
  const tag = envelope.subarray(48, 64);
  const ct = envelope.subarray(64);

  const shared33 = secp256k1.getSharedSecret(recipientPriv, ephPub, true);
  const x32 = shared33.subarray(1);
  const aesKey = Buffer.from(
    hkdf(sha256, x32, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );
  const aad = Buffer.concat([
    Buffer.from([envelope[0], envelope[1], envelope[2]]),
    ephPub,
  ]);

  const decipher = createDecipheriv('aes-256-gcm', aesKey, iv, {
    authTagLength: ECIES_AUTH_TAG_SIZE,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ────────────────────────────────────────────────────────────────────────────
// Session-key derivation (RFC §4.5.2)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Derive K_session via the bilateral HKDF-SHA256 from RFC §4.5.2:
 *
 *   IKM   = clientShare ‖ bridgeShare       (64 bytes)
 *   salt  = clientNonce ‖ sessionId          (32 bytes)
 *   info  = "brightlink-session-key-v1"      (25 bytes UTF-8)
 *   K     = HKDF-SHA256(IKM, salt, info, 32)
 *
 * Inputs are size-checked; mis-sized inputs throw.
 */
export function deriveSessionKey(args: {
  clientShare: Buffer;
  bridgeShare: Buffer;
  clientNonce: Buffer;
  sessionId: Buffer;
}): Buffer {
  if (args.clientShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`clientShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (args.bridgeShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`bridgeShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (args.clientNonce.length !== LINK_CLIENT_NONCE_LENGTH) {
    throw new Error(`clientNonce must be ${LINK_CLIENT_NONCE_LENGTH} bytes`);
  }
  if (args.sessionId.length !== LINK_SESSION_ID_LENGTH) {
    throw new Error(`sessionId must be ${LINK_SESSION_ID_LENGTH} bytes`);
  }

  const ikm = Buffer.concat([args.clientShare, args.bridgeShare]);
  const salt = Buffer.concat([args.clientNonce, args.sessionId]);
  const info = Buffer.from(LINK_SESSION_KEY_HKDF_INFO, 'utf8');
  return Buffer.from(hkdf(sha256, ikm, salt, info, LINK_SESSION_KEY_LENGTH));
}

// ────────────────────────────────────────────────────────────────────────────
// Canonical transcript (RFC §4.5.3)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Build the canonical 238-byte transcript per RFC §4.5.3.
 *
 *   "BrightLink v1 transcript\0"                            25 bytes
 *   LE32(len(clientNonce))   ‖ clientNonce                  4 + 16
 *   LE32(len(clientPub))     ‖ clientPub                    4 + 65
 *   LE32(len(clientShare))   ‖ clientShare                  4 + 32
 *   LE32(len(sessionId))     ‖ sessionId                    4 + 16
 *   LE32(len(bridgeShare))   ‖ bridgeShare                  4 + 32
 *   LE32(8)                  ‖ u64_be(round(issuedAtBd*86400))
 *   LE32(8)                  ‖ u64_be(bridgeIssuedAtUnix)
 *   LE32(4)                  ‖ u32_be(ttlSeconds)
 */
export function buildTranscript(args: {
  clientNonce: Buffer;
  clientPub: Buffer; // 65-byte uncompressed
  clientShare: Buffer;
  sessionId: Buffer;
  bridgeShare: Buffer;
  issuedAtBd: number;
  bridgeIssuedAtUnix: number;
  ttlSeconds: number;
}): Buffer {
  if (args.clientNonce.length !== LINK_CLIENT_NONCE_LENGTH) {
    throw new Error(`clientNonce must be ${LINK_CLIENT_NONCE_LENGTH} bytes`);
  }
  if (args.clientPub.length !== 65) {
    throw new Error(`clientPub must be 65 bytes (uncompressed secp256k1)`);
  }
  if (args.clientShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`clientShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (args.sessionId.length !== LINK_SESSION_ID_LENGTH) {
    throw new Error(`sessionId must be ${LINK_SESSION_ID_LENGTH} bytes`);
  }
  if (args.bridgeShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`bridgeShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (!Number.isFinite(args.issuedAtBd)) {
    throw new Error('issuedAtBd must be a finite number');
  }
  if (!Number.isInteger(args.bridgeIssuedAtUnix) || args.bridgeIssuedAtUnix < 0) {
    throw new Error('bridgeIssuedAtUnix must be a non-negative integer');
  }
  if (
    !Number.isInteger(args.ttlSeconds) ||
    args.ttlSeconds < 0 ||
    args.ttlSeconds > 0xffff_ffff
  ) {
    throw new Error('ttlSeconds must be a u32');
  }

  // RFC §4.5.3: round (issuedAtBd*86400) to nearest second.
  const issuedAtUnixRounded = Math.round(args.issuedAtBd * 86400);
  if (issuedAtUnixRounded < 0 || issuedAtUnixRounded > Number.MAX_SAFE_INTEGER) {
    throw new Error('issuedAtBd resolves to out-of-range Unix seconds');
  }

  const lenLE32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
  };
  const u64BE = (n: number): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n), 0);
    return b;
  };
  const u32BE = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
  };

  return Buffer.concat([
    TRANSCRIPT_HEADER,
    lenLE32(args.clientNonce.length),
    args.clientNonce,
    lenLE32(args.clientPub.length),
    args.clientPub,
    lenLE32(args.clientShare.length),
    args.clientShare,
    lenLE32(args.sessionId.length),
    args.sessionId,
    lenLE32(args.bridgeShare.length),
    args.bridgeShare,
    lenLE32(8),
    u64BE(issuedAtUnixRounded),
    lenLE32(8),
    u64BE(args.bridgeIssuedAtUnix),
    lenLE32(4),
    u32BE(args.ttlSeconds),
  ]);
}

// ────────────────────────────────────────────────────────────────────────────
// Transcript signature verification (RFC §4.5.3, EBP/1 §4.9)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Verify a DER-encoded ECDSA-over-P-256 signature against the bridge's
 * SEP public key (65-byte uncompressed X9.63). Apple CryptoKit's
 * `priv.signature(for:)` SHA-256-hashes internally before signing
 * (EBP/1 §4.9); Node's `createVerify('SHA256')` matches that behavior.
 *
 * Returns `true` if the signature is valid, `false` otherwise. Does not
 * throw — invalid keys / signatures simply return false so callers can
 * decide their own escalation policy.
 */
export function verifyTranscriptSignature(
  sepPubUncompressed: Buffer,
  transcript: Buffer,
  signatureDer: Buffer,
): boolean {
  if (sepPubUncompressed.length !== 65 || sepPubUncompressed[0] !== 0x04) {
    return false;
  }
  try {
    const x = sepPubUncompressed.subarray(1, 33);
    const y = sepPubUncompressed.subarray(33, 65);
    const jwk = {
      kty: 'EC' as const,
      crv: 'P-256' as const,
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    };
    const pubKey = createPublicKey({ key: jwk, format: 'jwk' });
    const verifier = createVerify('SHA256');
    verifier.update(transcript);
    return verifier.verify({ key: pubKey, dsaEncoding: 'der' }, signatureDer);
  } catch {
    return false;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Internal: outer ECIES Basic-mode encrypt
// ────────────────────────────────────────────────────────────────────────────

/**
 * Build a DD-ECIES Basic-mode envelope addressed to `recipientPub`,
 * carrying `plaintext`. Used by `buildLinkRegisterEnvelope` to wrap the
 * §4.5.1 plaintext.
 */
function encryptBasicEnvelope(
  plaintext: Buffer,
  recipientPub: Buffer,
  rng: (n: number) => Buffer,
): Buffer {
  // Generate ephemeral key (different from the BrightLink clientPub above —
  // this is the ECIES outer-envelope ephemeral, scoped to one envelope).
  let ephPriv: Buffer;
  for (let attempts = 0; ; attempts++) {
    ephPriv = rng(32);
    try {
      secp256k1.getPublicKey(ephPriv, true);
      break;
    } catch {
      if (attempts > 4) throw new Error('internal: cannot generate valid ephemeral scalar');
    }
  }
  const ephPubCompressed = Buffer.from(secp256k1.getPublicKey(ephPriv, true));
  if (ephPubCompressed.length !== ECIES_PUB_COMPRESSED_LEN) {
    throw new Error('internal: compressed pub not 33 bytes');
  }

  const shared33 = secp256k1.getSharedSecret(ephPriv, recipientPub, true);
  const x32 = shared33.subarray(1);
  const aesKey = Buffer.from(
    hkdf(sha256, x32, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );

  const iv = rng(ECIES_IV_SIZE);
  const aad = Buffer.concat([
    Buffer.from([ECIES_VERSION_BYTE, ECIES_CIPHER_SUITE_BYTE, ECIES_TYPE_BASIC]),
    ephPubCompressed,
  ]);

  const cipher = createCipheriv('aes-256-gcm', aesKey, iv, {
    authTagLength: ECIES_AUTH_TAG_SIZE,
  });
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([
    Buffer.from([ECIES_VERSION_BYTE, ECIES_CIPHER_SUITE_BYTE, ECIES_TYPE_BASIC]),
    ephPubCompressed,
    iv,
    tag,
    ct,
  ]);
}


// ════════════════════════════════════════════════════════════════════════════
// BrightLink v1.1 — geo + push helpers (RFC §6.3, §10)
//
// Pure functions, no transport. Mirror byte-for-byte the equivalents in
// `test-harness/src/spec/brightlink.ts`.
// ════════════════════════════════════════════════════════════════════════════

import { Buffer as _Buffer } from 'node:buffer';

/** Direction tag values for the §4.6.3 / §10.2 length-prefixed AAD. */
export const LINK_DIR_TAG = {
  /** Shell → Agent (LINK_DELIVER). */
  SHELL_TO_AGENT: 0x01,
  /** Agent → Shell (LINK_PUSH). */
  AGENT_TO_SHELL: 0x02,
} as const;

export type LinkDirTag = (typeof LINK_DIR_TAG)[keyof typeof LINK_DIR_TAG];

/** AES-GCM nonce length on the wire (RFC §4.9.1). */
export const LINK_GCM_IV_LENGTH = 12;
/** AES-GCM auth-tag length. */
export const LINK_GCM_TAG_LENGTH = 16;
/** Replay-protection window. RFC §4.6.4 / §10.3. */
export const LINK_COUNTER_REPLAY_WINDOW = 1000;

// ────────────────────────────────────────────────────────────────────────────
// §10.2 — LINK_PUSH AAD construction
// ────────────────────────────────────────────────────────────────────────────

/** Build the AES-256-GCM AAD for a `LINK_PUSH` frame. RFC §10.2.
 *
 *   AAD = LE32(1) ‖ 0x02            (dir_tag = AGENT_TO_SHELL)
 *      ‖ LE32(8) ‖ u64_be(counter)
 *      ‖ LE32(len(event_name)) ‖ event_name_utf8
 *      ‖ LE32(0) ‖ ""              (empty context for push events)
 *
 * The empty-context length-prefix of `LE32(0)` is required for symmetry
 * with the LINK_DELIVER AAD scheme — it MUST be present even though it
 * carries no body bytes. */
export function buildPushAad(args: {
  counter: bigint;
  event: string;
}): Buffer {
  if (args.counter < 0n || args.counter > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`counter out of u64 range: ${args.counter}`);
  }

  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(args.counter, 0);

  const eventBytes = Buffer.from(args.event, 'utf8');

  const lenLE32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
  };

  return Buffer.concat([
    lenLE32(1),
    Buffer.from([LINK_DIR_TAG.AGENT_TO_SHELL]),
    lenLE32(counterBytes.length),
    counterBytes,
    lenLE32(eventBytes.length),
    eventBytes,
    lenLE32(0),
    // empty context bytes follow — zero of them
  ]);
}

// ────────────────────────────────────────────────────────────────────────────
// §6.3 — coordinate conversion (WGS84 ↔ ECEF ↔ BrightSpace)
//
// All conversions are exact under IEEE 754 double precision at terrestrial
// scale. ECEF is in metres (ITRF2020 / WGS84 — they share an origin to
// sub-millimetre at the surface). BrightSpace is ECEF / c per the
// BrightSpace standard.
// ────────────────────────────────────────────────────────────────────────────

/** Speed of light in metres per second. Exact since the 1983 SI redefinition
 *  of the metre, and directly the conversion factor between ECEF metres and
 *  BrightSpace BrightMeters per the BrightSpace standard. */
export const SPEED_OF_LIGHT_MPS = 299_792_458;

/** WGS84 ellipsoid semi-major axis in metres. Exact by definition. */
export const WGS84_A = 6_378_137.0;
/** WGS84 ellipsoid flattening. */
export const WGS84_F = 1 / 298.257_223_563;
/** First eccentricity squared, derived: e² = 2f − f². */
export const WGS84_E2 = 2 * WGS84_F - WGS84_F * WGS84_F;
/** Semi-minor axis derived from a and f. */
export const WGS84_B = WGS84_A * (1 - WGS84_F);

export interface Wgs84Point {
  lat: number;        // degrees
  lon: number;        // degrees
  alt_m?: number;     // metres above WGS84 ellipsoid; default 0
}

export interface EcefPoint {
  x_m: number;
  y_m: number;
  z_m: number;
}

export interface BrightSpacePoint {
  x_bm: number;
  y_bm: number;
  z_bm: number;
  /** BrightDate at which the position was sampled. */
  epoch_bd: number;
}

const DEG2RAD = Math.PI / 180;
const RAD2DEG = 180 / Math.PI;

/** WGS84 lat/lon/alt → ECEF metres. Exact closed-form. */
export function wgs84ToEcef(p: Wgs84Point): EcefPoint {
  const phi = p.lat * DEG2RAD;
  const lam = p.lon * DEG2RAD;
  const h = p.alt_m ?? 0;

  const sinPhi = Math.sin(phi);
  const cosPhi = Math.cos(phi);
  const sinLam = Math.sin(lam);
  const cosLam = Math.cos(lam);

  // Radius of curvature in the prime vertical.
  const N = WGS84_A / Math.sqrt(1 - WGS84_E2 * sinPhi * sinPhi);

  return {
    x_m: (N + h) * cosPhi * cosLam,
    y_m: (N + h) * cosPhi * sinLam,
    z_m: (N * (1 - WGS84_E2) + h) * sinPhi,
  };
}

/** ECEF metres → WGS84 lat/lon/alt. Heikkinen 1982 closed-form, no iteration.
 *  Accurate to better than 0.1 mm at the surface; degrades only at the
 *  geocentre (0,0,0) where the answer is undefined anyway. */
export function ecefToWgs84(p: EcefPoint): Wgs84Point {
  const { x_m: x, y_m: y, z_m: z } = p;
  const a = WGS84_A;
  const b = WGS84_B;
  const e2 = WGS84_E2;
  // Second eccentricity squared.
  const ep2 = (a * a - b * b) / (b * b);

  const r = Math.sqrt(x * x + y * y);
  const F = 54 * b * b * z * z;
  const G = r * r + (1 - e2) * z * z - e2 * (a * a - b * b);
  const c = (e2 * e2 * F * r * r) / (G * G * G);
  const s = Math.cbrt(1 + c + Math.sqrt(c * c + 2 * c));
  const P = F / (3 * (s + 1 / s + 1) ** 2 * G * G);
  const Q = Math.sqrt(1 + 2 * e2 * e2 * P);
  const r0 =
    -(P * e2 * r) / (1 + Q) +
    Math.sqrt(
      0.5 * a * a * (1 + 1 / Q) -
        (P * (1 - e2) * z * z) / (Q * (1 + Q)) -
        0.5 * P * r * r,
    );
  const U = Math.sqrt((r - e2 * r0) ** 2 + z * z);
  const V = Math.sqrt((r - e2 * r0) ** 2 + (1 - e2) * z * z);
  const z0 = (b * b * z) / (a * V);

  const alt_m = U * (1 - (b * b) / (a * V));
  const lat = Math.atan2(z + ep2 * z0, r) * RAD2DEG;
  const lon = Math.atan2(y, x) * RAD2DEG;

  return { lat, lon, alt_m };
}

/** ECEF metres → BrightSpace BrightMeters (divide by c). Exact. */
export function ecefToBrightSpace(p: EcefPoint, epoch_bd: number): BrightSpacePoint {
  return {
    x_bm: p.x_m / SPEED_OF_LIGHT_MPS,
    y_bm: p.y_m / SPEED_OF_LIGHT_MPS,
    z_bm: p.z_m / SPEED_OF_LIGHT_MPS,
    epoch_bd,
  };
}

/** BrightSpace BrightMeters → ECEF metres (multiply by c). Exact. */
export function brightSpaceToEcef(p: BrightSpacePoint): EcefPoint {
  return {
    x_m: p.x_bm * SPEED_OF_LIGHT_MPS,
    y_m: p.y_bm * SPEED_OF_LIGHT_MPS,
    z_m: p.z_bm * SPEED_OF_LIGHT_MPS,
  };
}

/** Euclidean ECEF chord distance in metres between two points. The exact
 *  metric for `circle_2d` and `cylinder_3d` zone membership in BrightSpace.
 *  At terrestrial scales the chord-to-surface-distance error is below
 *  1 cm for radii under 200 m, well within zone tolerance. */
export function ecefChordDistance(a: EcefPoint, b: EcefPoint): number {
  const dx = a.x_m - b.x_m;
  const dy = a.y_m - b.y_m;
  const dz = a.z_m - b.z_m;
  return Math.sqrt(dx * dx + dy * dy + dz * dz);
}

// Unused-import tickle to keep linters happy; the runtime does not use this.
void _Buffer;
