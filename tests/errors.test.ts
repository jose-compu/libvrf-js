// Licensed under the MIT license.

import { VRF, VRFType, VRFError, VRFErrorCode } from '../src';

describe('VRFError and OrThrow APIs', () => {
  test('createOrThrow rejects UNKNOWN', () => {
    expect(() => VRF.createOrThrow(VRFType.UNKNOWN)).toThrow(VRFError);
    try {
      VRF.createOrThrow(VRFType.UNKNOWN);
    } catch (e) {
      expect(e).toBeInstanceOf(VRFError);
      expect((e as VRFError).code).toBe(VRFErrorCode.INVALID_TYPE);
    }
  });

  test('proofFromBytesOrThrow rejects empty proof', () => {
    expect(() =>
      VRF.proofFromBytesOrThrow(VRFType.RSA_FDH_VRF_RSA2048_SHA256, new Uint8Array(0))
    ).toThrow(VRFError);
  });

  test('publicKeyFromBytesOrThrow rejects empty key', () => {
    expect(() =>
      VRF.publicKeyFromBytesOrThrow(VRFType.RSA_FDH_VRF_RSA2048_SHA256, new Uint8Array(0))
    ).toThrow(VRFError);
  });

  test('createOrThrow succeeds for EC', () => {
    const sk = VRF.createOrThrow(VRFType.EC_VRF_P256_SHA256_TAI);
    expect(sk.isInitialized()).toBe(true);
  });

  test('legacy create still returns null for UNKNOWN', () => {
    expect(VRF.create(VRFType.UNKNOWN)).toBeNull();
  });
});
