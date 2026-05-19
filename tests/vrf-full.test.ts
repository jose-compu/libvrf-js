// Licensed under the MIT license.
// Optional slow suite: npm run test:full (3072/4096 RSA key generation).

import { VRF, VRFType } from '../src';

jest.setTimeout(120000);

const FULL_MATRIX_TYPES = [
  VRFType.RSA_FDH_VRF_RSA3072_SHA256,
  VRFType.RSA_FDH_VRF_RSA4096_SHA384,
  VRFType.RSA_FDH_VRF_RSA4096_SHA512,
  VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384,
  VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512,
];

describe.each(FULL_MATRIX_TYPES)('VRF full matrix - %s', (type) => {
  test('create, prove, verify', () => {
    const sk = VRF.create(type);
    expect(sk).not.toBeNull();
    const pk = sk!.getPublicKey();
    expect(pk).not.toBeNull();

    const proof = sk!.getVRFProof(new Uint8Array(0));
    expect(proof).not.toBeNull();
    const [ok, value] = pk!.verifyVRFProof(new Uint8Array(0), proof!);
    expect(ok).toBe(true);
    expect(value.length).toBeGreaterThan(0);
  });
});
