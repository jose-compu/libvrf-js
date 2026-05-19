// Licensed under the MIT license.
// RFC 9381 Appendix A vectors (from Microsoft libvrf tests/rsa_test_vectors.h)

import { VRF, VRFType } from '../src';
import vectors from './fixtures/rsa-rfc9381-vectors.json';
import { hexToBytes, bytesToHex } from './helpers/hex';

interface RsaVectorFixture {
  type: string;
  p: string;
  q: string;
  alpha: string;
  proof: string;
  beta: string;
}

describe('RFC 9381 RSA-FDH cross-vectors (libvrf C++)', () => {
  const fixtures = vectors as RsaVectorFixture[];

  test.each(fixtures)('$type', ({ type, p, q, alpha, proof, beta }) => {
    const vrfType = type as VRFType;
    const sk = VRF.createRsaFromPrimes(vrfType, hexToBytes(p), hexToBytes(q));
    expect(sk).not.toBeNull();
    expect(sk!.isInitialized()).toBe(true);

    const input = hexToBytes(alpha);
    const generated = sk!.getVRFProof(input);
    expect(generated).not.toBeNull();

    const generatedProof = generated!.toBytes();
    const expectedProof = hexToBytes(proof);
    expect(bytesToHex(generatedProof)).toBe(bytesToHex(expectedProof));

    const pk = sk!.getPublicKey();
    expect(pk).not.toBeNull();

    const [success, vrfValue] = pk!.verifyVRFProof(input, generated!);
    expect(success).toBe(true);
    expect(bytesToHex(vrfValue)).toBe(beta.toLowerCase());

    const loadedProof = VRF.proofFromBytes(vrfType, expectedProof);
    expect(loadedProof).not.toBeNull();
    const [success2, vrfValue2] = pk!.verifyVRFProof(input, loadedProof!);
    expect(success2).toBe(true);
    expect(bytesToHex(vrfValue2)).toBe(beta.toLowerCase());
  });
});
