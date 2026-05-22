/**
 * Unit tests for sr./brightlink.ts — pure BrightLink v1 cryptographic helpers.
 *
 * These tests exercise the byte-exact behavior of the helpers without any
 * transport. The known-answer vectors come from DD-ECIES §18 and from the
 * BrightLink v1 RFC §4.5; cross-implementation verification against the
 * test-harness mock-bridge is done in the integration test file.
 *
 * What this file covers:
 *   - HKDF derivation produces the same K_session that @noble/hashes does
 *     directly (binds us to the spec — drift in the info string would fail).
 *   - `buildTranscript` produces the exact 238-byte canonical layout.
 *   - `decryptLinkResponseEnvelope` round-trips against `buildLinkRegisterEnvelope`
 *     and rejects the legacy 65-byte uncompressed ephemeral form.
 *   - Size guards on every helper.
 *   - `verifyTranscriptSignature` accepts a Node-generated DER ECDSA-P256
 *     signature and rejects a tampered transcript.
 */

import { describe, expect, it } from 'vitest';
import {
  createSign,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
} from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import {
  buildLinkRegisterEnvelope,
  decryptLinkResponseEnvelope,
  deriveSessionKey,
  buildTranscript,
  verifyTranscriptSignature,
  LINK_PROTOCOL_VERSION,
  LINK_SESSION_KEY_HKDF_INFO,
  LINK_TRANSCRIPT_TOTAL_LENGTH,
  LINK_CLIENT_NONCE_LENGTH,
  LINK_SHARE_LENGTH,
  LINK_SESSION_ID_LENGTH,
  LINK_SESSION_KEY_LENGTH,
} from './brightlink.js';

// ────────────────────────────────────────────────────────────────────────────
// Fixtures (no randomness — fully deterministic)
// ────────────────────────────────────────────────────────────────────────────

/** SHA-256("BrightLink v1 test clientNonce")[0..16] — matches harness vector. */
const CLIENT_NONCE = Buffer.from('b1b8a3a3eb89dc8c1ad7b89f3aac1c83', 'hex');
const SESSION_ID = Buffer.from('aef7e09e3ee0c4886a25b0bbabb2cf94', 'hex');
const CLIENT_SHARE = Buffer.from(
  '5c01dee7d5e1b1a06ee20cd97a05dba9b9d3a35d76d72c39a8f8b2e6f6c5d2eb',
  'hex',
);
const BRIDGE_SHARE = Buffer.from(
  '8d6f0a1b88ac1c0c6c6a4727d99cae93d1e3789a6b0f5a9c5b5fdd7e4d091b3a',
  'hex',
);
const ISSUED_AT_BD = 9637.5;
const BRIDGE_ISSUED_AT_UNIX = 1747915200;
const TTL_SECONDS = 3600;

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

describe('BrightLink v1 constants', () => {
  it('protocol version is 1', () => {
    expect(LINK_PROTOCOL_VERSION).toBe(1);
  });
  it('HKDF info string is the v1 string verbatim', () => {
    expect(LINK_SESSION_KEY_HKDF_INFO).toBe('brightlink-session-key-v1');
  });
  it('transcript length is 238 bytes', () => {
    expect(LINK_TRANSCRIPT_TOTAL_LENGTH).toBe(238);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// deriveSessionKey
// ────────────────────────────────────────────────────────────────────────────

describe('deriveSessionKey', () => {
  it('matches a direct HKDF-SHA256 invocation with the v1 info string', () => {
    const direct = Buffer.from(
      hkdf(
        sha256,
        Buffer.concat([CLIENT_SHARE, BRIDGE_SHARE]),
        Buffer.concat([CLIENT_NONCE, SESSION_ID]),
        'brightlink-session-key-v1',
        LINK_SESSION_KEY_LENGTH,
      ),
    );

    const derived = deriveSessionKey({
      clientShare: CLIENT_SHARE,
      bridgeShare: BRIDGE_SHARE,
      clientNonce: CLIENT_NONCE,
      sessionId: SESSION_ID,
    });

    expect(derived.equals(direct)).toBe(true);
    expect(derived.length).toBe(32);
  });

  it('rejects mis-sized clientShare', () => {
    expect(() =>
      deriveSessionKey({
        clientShare: Buffer.alloc(31),
        bridgeShare: BRIDGE_SHARE,
        clientNonce: CLIENT_NONCE,
        sessionId: SESSION_ID,
      }),
    ).toThrow(/clientShare/);
  });

  it('rejects mis-sized bridgeShare', () => {
    expect(() =>
      deriveSessionKey({
        clientShare: CLIENT_SHARE,
        bridgeShare: Buffer.alloc(33),
        clientNonce: CLIENT_NONCE,
        sessionId: SESSION_ID,
      }),
    ).toThrow(/bridgeShare/);
  });

  it('rejects mis-sized clientNonce', () => {
    expect(() =>
      deriveSessionKey({
        clientShare: CLIENT_SHARE,
        bridgeShare: BRIDGE_SHARE,
        clientNonce: Buffer.alloc(15),
        sessionId: SESSION_ID,
      }),
    ).toThrow(/clientNonce/);
  });

  it('rejects mis-sized sessionId', () => {
    expect(() =>
      deriveSessionKey({
        clientShare: CLIENT_SHARE,
        bridgeShare: BRIDGE_SHARE,
        clientNonce: CLIENT_NONCE,
        sessionId: Buffer.alloc(15),
      }),
    ).toThrow(/sessionId/);
  });

  it('produces different keys when any input changes', () => {
    const base = deriveSessionKey({
      clientShare: CLIENT_SHARE,
      bridgeShare: BRIDGE_SHARE,
      clientNonce: CLIENT_NONCE,
      sessionId: SESSION_ID,
    });
    const perturbed = deriveSessionKey({
      clientShare: CLIENT_SHARE,
      bridgeShare: BRIDGE_SHARE,
      clientNonce: CLIENT_NONCE,
      sessionId: Buffer.from(
        'aef7e09e3ee0c4886a25b0bbabb2cf95', // last byte differs
        'hex',
      ),
    });
    expect(base.equals(perturbed)).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// buildTranscript
// ────────────────────────────────────────────────────────────────────────────

describe('buildTranscript', () => {
  // Use a fixed 65-byte uncompressed key so the test is deterministic.
  const CLIENT_PUB_HEX =
    '04' +
    'a0c5b8d4f1e09712a06b58cd0e9f3a5d7e2c8a4b6f1c3e5d7a9b8c6d4e2f0a1b3' +
    'c5d7e9f1b3d5a7c9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7';
  const CLIENT_PUB = Buffer.from(CLIENT_PUB_HEX, 'hex');

  it('produces a 238-byte transcript', () => {
    const t = buildTranscript({
      clientNonce: CLIENT_NONCE,
      clientPub: CLIENT_PUB,
      clientShare: CLIENT_SHARE,
      sessionId: SESSION_ID,
      bridgeShare: BRIDGE_SHARE,
      issuedAtBd: ISSUED_AT_BD,
      bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
      ttlSeconds: TTL_SECONDS,
    });
    expect(t.length).toBe(LINK_TRANSCRIPT_TOTAL_LENGTH);
  });

  it('starts with the literal NUL-terminated header', () => {
    const t = buildTranscript({
      clientNonce: CLIENT_NONCE,
      clientPub: CLIENT_PUB,
      clientShare: CLIENT_SHARE,
      sessionId: SESSION_ID,
      bridgeShare: BRIDGE_SHARE,
      issuedAtBd: ISSUED_AT_BD,
      bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
      ttlSeconds: TTL_SECONDS,
    });
    const expectedHeader = Buffer.concat([
      Buffer.from('BrightLink v1 transcript', 'utf8'),
      Buffer.from([0x00]),
    ]);
    expect(t.subarray(0, expectedHeader.length).equals(expectedHeader)).toBe(true);
    expect(expectedHeader.length).toBe(25);
  });

  it('places the trailing TTL u32 in big-endian at the end', () => {
    const t = buildTranscript({
      clientNonce: CLIENT_NONCE,
      clientPub: CLIENT_PUB,
      clientShare: CLIENT_SHARE,
      sessionId: SESSION_ID,
      bridgeShare: BRIDGE_SHARE,
      issuedAtBd: ISSUED_AT_BD,
      bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
      ttlSeconds: TTL_SECONDS,
    });
    // Last 4 bytes are u32 BE TTL.
    expect(t.readUInt32BE(t.length - 4)).toBe(TTL_SECONDS);
    // The 4 bytes before are LE32 length-prefix == 4.
    expect(t.readUInt32LE(t.length - 8)).toBe(4);
  });

  it('rounds (issuedAtBd*86400) to nearest second when emitting', () => {
    // 9637.5 * 86400 = 832636800 exactly — no rounding ambiguity.
    const t = buildTranscript({
      clientNonce: CLIENT_NONCE,
      clientPub: CLIENT_PUB,
      clientShare: CLIENT_SHARE,
      sessionId: SESSION_ID,
      bridgeShare: BRIDGE_SHARE,
      issuedAtBd: 9637.5,
      bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
      ttlSeconds: TTL_SECONDS,
    });
    // The issuedAtUnix u64 is at offset:
    //   header(25) + (4+16) + (4+65) + (4+32) + (4+16) + (4+32) + 4 = 210
    const off = 25 + 20 + 69 + 36 + 20 + 36 + 4;
    expect(t.readBigUInt64BE(off)).toBe(BigInt(Math.round(9637.5 * 86400)));
  });

  it.each([
    [{ name: 'clientNonce', size: 15 }],
    [{ name: 'clientShare', size: 31 }],
    [{ name: 'sessionId', size: 17 }],
    [{ name: 'bridgeShare', size: 33 }],
  ])('rejects mis-sized $name', ({ name, size }) => {
    const args = {
      clientNonce: CLIENT_NONCE,
      clientPub: CLIENT_PUB,
      clientShare: CLIENT_SHARE,
      sessionId: SESSION_ID,
      bridgeShare: BRIDGE_SHARE,
      issuedAtBd: ISSUED_AT_BD,
      bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
      ttlSeconds: TTL_SECONDS,
    };
    (args as Record<string, Buffer | number>)[name] = Buffer.alloc(size);
    expect(() => buildTranscript(args)).toThrow(new RegExp(name));
  });

  it('rejects clientPub that is not 65 bytes', () => {
    expect(() =>
      buildTranscript({
        clientNonce: CLIENT_NONCE,
        clientPub: Buffer.alloc(33),
        clientShare: CLIENT_SHARE,
        sessionId: SESSION_ID,
        bridgeShare: BRIDGE_SHARE,
        issuedAtBd: ISSUED_AT_BD,
        bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
        ttlSeconds: TTL_SECONDS,
      }),
    ).toThrow(/clientPub/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// buildLinkRegisterEnvelope ↔ decryptLinkResponseEnvelope round-trip
// ────────────────────────────────────────────────────────────────────────────

describe('buildLinkRegisterEnvelope', () => {
  // Generate a deterministic recipient (the "bridge"). We treat the bridge's
  // private key as the well-known DD-ECIES test-vector private key — that key
  // sits in the spec for exactly this purpose.
  const BRIDGE_PRIV = Buffer.from(
    '1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f',
    'hex',
  );
  const BRIDGE_PUB_UNCOMPRESSED = Buffer.from(
    secp256k1.getPublicKey(BRIDGE_PRIV, false),
  );

  it('produces a request whose protocol version is 1', () => {
    const built = buildLinkRegisterEnvelope(BRIDGE_PUB_UNCOMPRESSED);
    expect(built.request.protocolVersion).toBe(1);
    expect(built.request.cmd).toBe("LINK_REGISTER");
  });

  it('clientNonce is 16 bytes, clientShare is 32 bytes, ephemeralPub is 65 bytes', () => {
    const built = buildLinkRegisterEnvelope(BRIDGE_PUB_UNCOMPRESSED);
    expect(built.clientNonce.length).toBe(LINK_CLIENT_NONCE_LENGTH);
    expect(built.clientShare.length).toBe(LINK_SHARE_LENGTH);
    expect(built.ephemeralPub.length).toBe(65);
    expect(built.ephemeralPub[0]).toBe(0x04); // uncompressed prefix
  });

  it('uses the rng override deterministically', () => {
    let counter = 0;
    const rng = (n: number): Buffer => {
      counter += 1;
      // Simple: fill with a per-call constant byte.
      return Buffer.alloc(n, counter);
    };
    const a = buildLinkRegisterEnvelope(BRIDGE_PUB_UNCOMPRESSED, { rng });
    counter = 0;
    const b = buildLinkRegisterEnvelope(BRIDGE_PUB_UNCOMPRESSED, { rng });
    expect(a.clientNonce.equals(b.clientNonce)).toBe(true);
    expect(a.clientShare.equals(b.clientShare)).toBe(true);
    // The envelope wraps an ECIES ephemeral that's regenerated per build —
    // so the envelope bytes WON'T match unless we also pin the ephemeral RNG.
    // What MUST match is the inner plaintext: we pinned both clientShare and
    // ephemeralPriv via the same rng sequence.
    expect(a.ephemeralPub.equals(b.ephemeralPub)).toBe(true);
  });

  it('round-trips through decryptLinkResponseEnvelope when the bridge encrypts back', async () => {
    const built = buildLinkRegisterEnvelope(BRIDGE_PUB_UNCOMPRESSED);

    // Simulate the bridge: the ephemeralPub from the LINK_REGISTER envelope
    // is the recipient of the bridge's responseEnvelope. We craft a Basic-mode
    // envelope addressed to built.ephemeralPub carrying a 32-byte bridgeShare.
    const responseEnvelope = encryptToEphemeral(built.ephemeralPub, BRIDGE_SHARE);

    const recovered = decryptLinkResponseEnvelope(responseEnvelope, built.ephemeralPriv);
    expect(recovered.equals(BRIDGE_SHARE)).toBe(true);
  });
});

describe('decryptLinkResponseEnvelope', () => {
  const BRIDGE_PRIV = Buffer.from(
    '1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f',
    'hex',
  );

  it('rejects envelopes with wrong version byte', () => {
    const built = buildLinkRegisterEnvelope(
      Buffer.from(secp256k1.getPublicKey(BRIDGE_PRIV, false)),
    );
    const env = encryptToEphemeral(built.ephemeralPub, BRIDGE_SHARE);
    env[0] = 0x02; // tamper version
    expect(() => decryptLinkResponseEnvelope(env, built.ephemeralPriv)).toThrow(/version/);
  });

  it('rejects envelopes that are not Basic mode (0x21)', () => {
    const built = buildLinkRegisterEnvelope(
      Buffer.from(secp256k1.getPublicKey(BRIDGE_PRIV, false)),
    );
    const env = encryptToEphemeral(built.ephemeralPub, BRIDGE_SHARE);
    env[2] = 0x42; // tamper to WithLength
    expect(() => decryptLinkResponseEnvelope(env, built.ephemeralPriv)).toThrow(/Basic/);
  });

  it('rejects envelopes whose ephemeral key has the legacy 65-byte uncompressed prefix', () => {
    // Construct a malformed envelope with prefix byte 0x04 where the compressed
    // ephemeral should sit. The Compatibility posture (RFC §15) demands strict
    // 33-byte-only.
    const built = buildLinkRegisterEnvelope(
      Buffer.from(secp256k1.getPublicKey(BRIDGE_PRIV, false)),
    );
    const env = encryptToEphemeral(built.ephemeralPub, BRIDGE_SHARE);
    env[3] = 0x04; // ← would be valid in legacy uncompressed form
    expect(() => decryptLinkResponseEnvelope(env, built.ephemeralPriv)).toThrow(
      /33-byte compressed/,
    );
  });

  it('rejects too-short envelopes', () => {
    expect(() => decryptLinkResponseEnvelope(Buffer.alloc(40), BRIDGE_PRIV)).toThrow(
      /too short/,
    );
  });
});

// ────────────────────────────────────────────────────────────────────────────
// verifyTranscriptSignature
// ────────────────────────────────────────────────────────────────────────────

describe('verifyTranscriptSignature', () => {
  it('accepts a valid Node-generated DER ECDSA-P256 signature over the transcript', () => {
    // Generate a P-256 keypair, get the uncompressed public-key bytes.
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    const sepPubUncompressed = exportP256PublicKeyAsUncompressed(publicKey);

    const transcript = buildTranscript({
      clientNonce: CLIENT_NONCE,
      clientPub: Buffer.from(secp256k1.getPublicKey(BRIDGE_SHARE, false)),
      clientShare: CLIENT_SHARE,
      sessionId: SESSION_ID,
      bridgeShare: BRIDGE_SHARE,
      issuedAtBd: ISSUED_AT_BD,
      bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
      ttlSeconds: TTL_SECONDS,
    });

    const signer = createSign('SHA256');
    signer.update(transcript);
    const signature = signer.sign({ key: privateKey, dsaEncoding: 'der' });

    expect(verifyTranscriptSignature(sepPubUncompressed, transcript, signature)).toBe(true);
  });

  it('rejects a tampered transcript', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    const sepPubUncompressed = exportP256PublicKeyAsUncompressed(publicKey);

    const transcript = buildTranscript({
      clientNonce: CLIENT_NONCE,
      clientPub: Buffer.from(secp256k1.getPublicKey(BRIDGE_SHARE, false)),
      clientShare: CLIENT_SHARE,
      sessionId: SESSION_ID,
      bridgeShare: BRIDGE_SHARE,
      issuedAtBd: ISSUED_AT_BD,
      bridgeIssuedAtUnix: BRIDGE_ISSUED_AT_UNIX,
      ttlSeconds: TTL_SECONDS,
    });

    const signer = createSign('SHA256');
    signer.update(transcript);
    const signature = signer.sign({ key: privateKey, dsaEncoding: 'der' });

    const tampered = Buffer.from(transcript);
    tampered[100] ^= 0x01;
    expect(verifyTranscriptSignature(sepPubUncompressed, tampered, signature)).toBe(false);
  });

  it('returns false (not throws) on malformed SEP key', () => {
    expect(
      verifyTranscriptSignature(
        Buffer.alloc(64),
        Buffer.from('hello'),
        Buffer.from('00', 'hex'),
      ),
    ).toBe(false);
  });

  it('returns false on SEP key with wrong prefix byte', () => {
    const bad = Buffer.alloc(65);
    bad[0] = 0x05; // legal length, illegal prefix
    expect(
      verifyTranscriptSignature(bad, Buffer.from('hello'), Buffer.from('00', 'hex')),
    ).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// helpers (test-local — minimal Basic-mode encrypter for round-trips)
// ────────────────────────────────────────────────────────────────────────────

import { createCipheriv } from 'node:crypto';

function encryptToEphemeral(recipientPubUncompressed: Buffer, plaintext: Buffer): Buffer {
  // Generate a deterministic-ish ephemeral. Using a fresh random scalar is fine
  // for round-trip tests — we just need a valid envelope.
  let priv: Buffer;
  while (true) {
    priv = Buffer.from(secp256k1.utils.randomPrivateKey());
    try {
      secp256k1.getPublicKey(priv, true);
      break;
    } catch {
      // retry
    }
  }
  const ephPubCompressed = Buffer.from(secp256k1.getPublicKey(priv, true));
  const shared = secp256k1.getSharedSecret(priv, recipientPubUncompressed, true);
  const x = Buffer.from(shared.subarray(1));
  const aesKey = Buffer.from(
    hkdf(sha256, x, new Uint8Array(0), 'ecies-v2-key-derivation', 32),
  );
  const iv = Buffer.alloc(12, 0x42);
  const aad = Buffer.concat([Buffer.from([0x01, 0x01, 0x21]), ephPubCompressed]);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([0x01, 0x01, 0x21]), ephPubCompressed, iv, tag, ct]);
}

function exportP256PublicKeyAsUncompressed(publicKey: ReturnType<typeof generateKeyPairSync>['publicKey']): Buffer {
  // Export to JWK and reconstruct the 65-byte uncompressed X9.63 form.
  // `publicKey` is already a KeyObject; export directly.
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

// Trick: silence unused-import warning when the file is read by editors.
void createPrivateKey;
void createPublicKey;


// ════════════════════════════════════════════════════════════════════════════
// BrightLink v1.1 — geo + push helpers (RFC §6.3, §10)
// ════════════════════════════════════════════════════════════════════════════

import {
  buildPushAad,
  LINK_DIR_TAG,
  LINK_GCM_IV_LENGTH,
  LINK_GCM_TAG_LENGTH,
  LINK_COUNTER_REPLAY_WINDOW,
  SPEED_OF_LIGHT_MPS,
  WGS84_A,
  WGS84_F,
  WGS84_E2,
  WGS84_B,
  wgs84ToEcef,
  ecefToWgs84,
  ecefToBrightSpace,
  brightSpaceToEcef,
  ecefChordDistance,
} from './brightlink.js';

// ────────────────────────────────────────────────────────────────────────────
// §6.3 / §10 — wire constants pinned
// ────────────────────────────────────────────────────────────────────────────

describe('BrightLink v1.1 wire constants', () => {
  it('LINK_DIR_TAG.SHELL_TO_AGENT = 0x01, AGENT_TO_SHELL = 0x02', () => {
    expect(LINK_DIR_TAG.SHELL_TO_AGENT).toBe(0x01);
    expect(LINK_DIR_TAG.AGENT_TO_SHELL).toBe(0x02);
  });

  it('AES-GCM nonce is 12 bytes, auth tag is 16 bytes', () => {
    expect(LINK_GCM_IV_LENGTH).toBe(12);
    expect(LINK_GCM_TAG_LENGTH).toBe(16);
  });

  it('replay window is 1000 counters', () => {
    expect(LINK_COUNTER_REPLAY_WINDOW).toBe(1000);
  });

  it('speed of light is exactly 299_792_458 m/s', () => {
    // Exact since the 1983 SI redefinition of the metre.
    expect(SPEED_OF_LIGHT_MPS).toBe(299_792_458);
  });

  it('WGS84 ellipsoid constants pin to the 1984 definition', () => {
    expect(WGS84_A).toBe(6_378_137.0);
    expect(WGS84_F).toBeCloseTo(1 / 298.257223563, 15);
    expect(WGS84_E2).toBeCloseTo(2 * WGS84_F - WGS84_F * WGS84_F, 15);
    expect(WGS84_B).toBeCloseTo(WGS84_A * (1 - WGS84_F), 9);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §10.2 — buildPushAad
// ────────────────────────────────────────────────────────────────────────────

describe('§10.2 buildPushAad', () => {
  it('produces the 40-byte zone-transition layout for counter 1', () => {
    const aad = buildPushAad({ counter: 1n, event: 'zone-transition' });
    // Layout:
    //   LE32(1) ‖ 0x02
    //   LE32(8) ‖ u64_be(1)
    //   LE32(15) ‖ "zone-transition"
    //   LE32(0)
    // = 4+1+4+8+4+15+4 = 40 bytes.
    expect(aad.length).toBe(40);
    expect(aad.readUInt32LE(0)).toBe(1);
    expect(aad[4]).toBe(LINK_DIR_TAG.AGENT_TO_SHELL);
    expect(aad.readUInt32LE(5)).toBe(8);
    expect(aad.readBigUInt64BE(9)).toBe(1n);
    expect(aad.readUInt32LE(17)).toBe(15);
    expect(aad.subarray(21, 36).toString('utf8')).toBe('zone-transition');
    expect(aad.readUInt32LE(36)).toBe(0);
  });

  it('different counter values produce different AAD bytes', () => {
    const a = buildPushAad({ counter: 1n, event: 'zone-transition' });
    const b = buildPushAad({ counter: 2n, event: 'zone-transition' });
    expect(a.equals(b)).toBe(false);
  });

  it('different event names produce different AAD bytes', () => {
    const a = buildPushAad({ counter: 1n, event: 'zone-transition' });
    const b = buildPushAad({ counter: 1n, event: 'geo-grant-changed' });
    expect(a.equals(b)).toBe(false);
  });

  it('rejects out-of-range u64 counters', () => {
    expect(() => buildPushAad({ counter: -1n, event: 'x' })).toThrow(
      /counter out of u64 range/,
    );
    expect(() =>
      buildPushAad({ counter: 0xffff_ffff_ffff_ffffn + 1n, event: 'x' }),
    ).toThrow(/counter out of u64 range/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §6.3 — coordinate conversion
// ────────────────────────────────────────────────────────────────────────────

describe('§6.3 WGS84 ↔ ECEF conversion', () => {
  it('round-trips Pike Place Market through ECEF and back', () => {
    const original = { lat: 47.6097, lon: -122.3422, alt_m: 17 };
    const ecef = wgs84ToEcef(original);
    const back = ecefToWgs84(ecef);
    expect(back.lat).toBeCloseTo(original.lat, 9);
    expect(back.lon).toBeCloseTo(original.lon, 9);
    expect(back.alt_m).toBeCloseTo(original.alt_m, 6);
  });

  it('agrees with the BrightSpace standard GODE worked example', () => {
    // ITRF2020 GODE @ epoch 2015.0 (per the BrightSpace standard §5).
    const targetEcef = {
      x_m: 1_130_773.5956,
      y_m: -4_831_253.5718,
      z_m: 3_994_200.4453,
    };
    const wgs84 = ecefToWgs84(targetEcef);
    const back = wgs84ToEcef(wgs84);
    expect(back.x_m).toBeCloseTo(targetEcef.x_m, 3);
    expect(back.y_m).toBeCloseTo(targetEcef.y_m, 3);
    expect(back.z_m).toBeCloseTo(targetEcef.z_m, 3);
    // Sanity: this is in Maryland, USA.
    expect(wgs84.lat).toBeGreaterThan(38);
    expect(wgs84.lat).toBeLessThan(40);
  });
});

describe('§6.3 ECEF ↔ BrightSpace conversion', () => {
  it('ECEF → BrightSpace divides every component by c, exact', () => {
    const ecef = { x_m: 1_130_773.5956, y_m: -4_831_253.5718, z_m: 3_994_200.4453 };
    const bs = ecefToBrightSpace(ecef, 9638.5);
    expect(bs.x_bm).toBe(ecef.x_m / SPEED_OF_LIGHT_MPS);
    expect(bs.y_bm).toBe(ecef.y_m / SPEED_OF_LIGHT_MPS);
    expect(bs.z_bm).toBe(ecef.z_m / SPEED_OF_LIGHT_MPS);
    expect(bs.epoch_bd).toBe(9638.5);
  });

  it('BrightSpace → ECEF round-trips bit-exactly', () => {
    const ecef = { x_m: 1_130_773.5956, y_m: -4_831_253.5718, z_m: 3_994_200.4453 };
    const bs = ecefToBrightSpace(ecef, 9638.5);
    const back = brightSpaceToEcef(bs);
    expect(back.x_m).toBe(ecef.x_m);
    expect(back.y_m).toBe(ecef.y_m);
    expect(back.z_m).toBe(ecef.z_m);
  });
});

describe('§6.3 ecefChordDistance', () => {
  it('zero distance from a point to itself', () => {
    const a = wgs84ToEcef({ lat: 47.6062, lon: -122.3321 });
    expect(ecefChordDistance(a, a)).toBe(0);
  });

  it('roughly 1 km between two points 0.009° latitude apart', () => {
    const a = wgs84ToEcef({ lat: 47.6062, lon: -122.3321, alt_m: 0 });
    const b = wgs84ToEcef({ lat: 47.6152, lon: -122.3321, alt_m: 0 });
    const d = ecefChordDistance(a, b);
    expect(d).toBeGreaterThan(990);
    expect(d).toBeLessThan(1010);
  });
});
