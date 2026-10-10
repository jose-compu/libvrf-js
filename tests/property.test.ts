// Licensed under the MIT license.

import fc from 'fast-check';
import { VRF, VRFType, bytesEqual, bytesToHex, hexToBytes } from '../src';

const SUITES = [
  VRFType.EC_VRF_P256_SHA256_TAI,
  VRFType.RSA_FDH_VRF_RSA2048_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
];

describe('property: hex round-trip', () => {
  test('bytesToHex / hexToBytes', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 64 }), (bytes) => {
        expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
      }),
      { numRuns: 40 }
    );
  });
});

describe.each(SUITES)('property: %s', (type) => {
  const runs = type === VRFType.EC_VRF_P256_SHA256_TAI ? 8 : 3;
  const sk = VRF.createOrThrow(type);
  const pk = sk.getPublicKey();
  if (!pk) {
    throw new Error('public key');
  }

  test('secret key round-trip', () => {
    const raw = VRF.secretKeyToBytes(sk);
    expect(raw).not.toBeNull();
    const restored = VRF.secretKeyFromBytesOrThrow(type, raw!);
    const alpha = new Uint8Array([1, 2, 3]);
    const a = sk.getVRFProof(alpha);
    const b = restored.getVRFProof(alpha);
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(bytesEqual(a!.toBytes(), b!.toBytes())).toBe(true);
  });

  test('proof and public key round-trip; tampered proof is rejected', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 0, maxLength: 24 }), (alpha) => {
        const proof = sk.getVRFProof(alpha);
        expect(proof).not.toBeNull();
        const proofBytes = proof!.toBytes();
        const loaded = VRF.proofFromBytesOrThrow(type, proofBytes);
        const [ok] = pk.verifyVRFProof(alpha, loaded);
        expect(ok).toBe(true);

        const pk2 = VRF.publicKeyFromBytesOrThrow(type, pk.toBytes());
        const [ok2] = pk2.verifyVRFProof(alpha, loaded);
        expect(ok2).toBe(true);

        const tampered = new Uint8Array(proofBytes);
        tampered[0] ^= 0x01;
        const bad = VRF.proofFromBytes(type, tampered);
        if (bad && bad.isInitialized()) {
          const [badOk] = pk.verifyVRFProof(alpha, bad);
          expect(badOk).toBe(false);
        }
      }),
      { numRuns: runs }
    );
  }, 120000);
});
