// Licensed under the MIT license.

import { VRF, VRFType, isRSAType, isECType } from '../src';

/** Default CI matrix — fast (no 3072/4096 RSA keygen). */
const FAST_TEST_TYPES = [
  VRFType.RSA_FDH_VRF_RSA2048_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
  VRFType.EC_VRF_P256_SHA256_TAI,
];

const ALL_RSA_TYPES = [
  VRFType.RSA_FDH_VRF_RSA2048_SHA256,
  VRFType.RSA_FDH_VRF_RSA3072_SHA256,
  VRFType.RSA_FDH_VRF_RSA4096_SHA384,
  VRFType.RSA_FDH_VRF_RSA4096_SHA512,
  VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384,
  VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512,
];

const ALL_EC_TYPES = [VRFType.EC_VRF_P256_SHA256_TAI];

describe('VRF Type Checks', () => {
  test('isRSAType identifies RSA types', () => {
    for (const type of ALL_RSA_TYPES) {
      expect(isRSAType(type)).toBe(true);
      expect(isECType(type)).toBe(false);
    }
  });

  test('isECType identifies EC types', () => {
    for (const type of ALL_EC_TYPES) {
      expect(isECType(type)).toBe(true);
      expect(isRSAType(type)).toBe(false);
    }
  });
});

describe.each(FAST_TEST_TYPES)('VRF Tests - %s', (type) => {
  let sk: ReturnType<typeof VRF.create>;
  let pk: ReturnType<NonNullable<ReturnType<typeof VRF.create>>['getPublicKey']>;

  beforeAll(() => {
    sk = VRF.create(type);
    pk = sk?.getPublicKey() || null;
  });

  test('Create', () => {
    expect(sk).not.toBeNull();
    expect(sk!.isInitialized()).toBe(true);
    expect(sk!.getType()).toBe(type);
  });

  test('GetPublicKey', () => {
    expect(pk).not.toBeNull();
    expect(pk!.isInitialized()).toBe(true);
    expect(pk!.getType()).toBe(type);
    const derSpki = pk!.toBytes();
    expect(derSpki.length).toBeGreaterThan(0);
    expect(sk!.getPublicKey()!.toBytes()).toEqual(derSpki);
  });

  test('CreateVerifyProof', () => {
    const proof = sk!.getVRFProof(new Uint8Array(0));
    expect(proof).not.toBeNull();
    const [success, vrfValue] = pk!.verifyVRFProof(new Uint8Array(0), proof!);
    expect(success).toBe(true);
    expect(vrfValue.length).toBeGreaterThan(0);
  });

  test('ProofToBytesFromBytes', () => {
    const data = new Uint8Array(0);
    const proof = sk!.getVRFProof(data)!;
    const loaded = VRF.proofFromBytes(type, proof.toBytes());
    expect(loaded).not.toBeNull();
    const [success] = pk!.verifyVRFProof(data, loaded!);
    expect(success).toBe(true);
  });

  test('PublicKeyEncodeDecode', () => {
    const pkLoaded = VRF.publicKeyFromBytes(type, pk!.toBytes());
    expect(pkLoaded).not.toBeNull();
    const proof = sk!.getVRFProof(new Uint8Array(0))!;
    const [success] = pkLoaded!.verifyVRFProof(new Uint8Array(0), proof);
    expect(success).toBe(true);
  });

  test('SecretKeyEncodeDecode', () => {
    const skBytes = VRF.secretKeyToBytes(sk!);
    expect(skBytes).not.toBeNull();
    expect(skBytes!.length).toBeGreaterThan(0);

    const skLoaded = VRF.secretKeyFromBytes(type, skBytes!);
    expect(skLoaded).not.toBeNull();
    expect(skLoaded!.getType()).toBe(type);

    const proofA = sk!.getVRFProof(new Uint8Array([1]))!;
    const proofB = skLoaded!.getVRFProof(new Uint8Array([1]))!;
    expect(proofA.toBytes()).toEqual(proofB.toBytes());
  });

  test('ValueIsDeterministic', () => {
    const data = new Uint8Array(0);
    const p1 = sk!.getVRFProof(data)!;
    const p2 = sk!.getVRFProof(data)!;
    expect(p1.toBytes()).toEqual(p2.toBytes());
  });

  test('InvalidProof', () => {
    const data = new Uint8Array([0x99, 0x88, 0x77, 0x66]);
    const bytes = sk!.getVRFProof(data)!.toBytes();
    bytes[0] ^= 0xff;
    const bad = VRF.proofFromBytes(type, bytes)!;
    const [success] = pk!.verifyVRFProof(data, bad);
    expect(success).toBe(false);
    expect(VRF.proofFromBytes(type, new Uint8Array(0))).toBeNull();
  });

  test('InvalidPublicKey', () => {
    expect(VRF.publicKeyFromBytes(type, new Uint8Array(0))).toBeNull();
    expect(VRF.publicKeyFromBytes(VRFType.UNKNOWN, pk!.toBytes())).toBeNull();
  });
});

describe('VRF Clone Tests', () => {
  test('Clone secret key', () => {
    const sk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI)!;
    const clone = sk.clone();
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(sk.getVRFProof(data)!.toBytes()).toEqual(clone.getVRFProof(data)!.toBytes());
  });

  test('Clone public key', () => {
    const pk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI)!.getPublicKey()!;
    const clone = pk.clone();
    expect(pk.toBytes()).toEqual(clone.toBytes());
  });

  test('Clone proof', () => {
    const sk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI)!;
    const data = new Uint8Array([0xca, 0xfe]);
    const proof = sk.getVRFProof(data)!;
    expect(proof.toBytes()).toEqual(proof.clone().toBytes());
  });
});

describe('VRF Edge Cases', () => {
  test('Null input handling', () => {
    expect(VRF.create(VRFType.UNKNOWN)).toBeNull();
    expect(VRF.proofFromBytes(VRFType.UNKNOWN, new Uint8Array([1]))).toBeNull();
    expect(VRF.publicKeyFromBytes(VRFType.UNKNOWN, new Uint8Array([1]))).toBeNull();
    expect(VRF.secretKeyFromBytes(VRFType.UNKNOWN, new Uint8Array([1]))).toBeNull();
  });

  test('Large input handling', () => {
    const sk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI)!;
    const pk = sk.getPublicKey()!;
    const large = Uint8Array.from({ length: 1024 }, (_, i) => i % 256);
    const proof = sk.getVRFProof(large)!;
    const [success] = pk.verifyVRFProof(large, proof);
    expect(success).toBe(true);
  });
});
