// Licensed under the MIT license.

import fc from 'fast-check';
import { VRF, VRFError, VRFType } from '../src';

const TYPES = [
  VRFType.UNKNOWN,
  VRFType.EC_VRF_P256_SHA256_TAI,
  VRFType.RSA_FDH_VRF_RSA2048_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
];

function onlyVrfError(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    if (!(err instanceof VRFError)) {
      throw err;
    }
  }
}

describe('fuzz: proof and public key deserialization', () => {
  test('garbage bytes yield null or VRFError', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...TYPES),
        fc.uint8Array({ minLength: 0, maxLength: 96 }),
        (type, data) => {
          onlyVrfError(() => VRF.proofFromBytes(type, data));
          onlyVrfError(() => VRF.proofFromBytesOrThrow(type, data));
          onlyVrfError(() => VRF.publicKeyFromBytes(type, data));
          onlyVrfError(() => VRF.publicKeyFromBytesOrThrow(type, data));
        }
      ),
      { numRuns: 30 }
    );
  }, 60000);
});
