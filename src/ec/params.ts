// Licensed under the MIT license.

import { VRFType } from '../types';

/**
 * Domain parameters for an EC VRF suite.
 *
 * For {@link VRFType.EC_VRF_P256_SHA256_TAI}: `qLen=32`, `ptLen=33`, `cLen=16`,
 * `fLen=80` (proof π), `hLen=32` (β).
 */
export interface ECVRFParams {
  algorithmName: string;
  curve: string;
  cofactor: number;
  digest: string;
  suiteString: Uint8Array;
  /** Field / scalar length in bytes (P-256: 32). */
  qLen: number;
  /** Compressed point encoding length in bytes (P-256: 33). */
  ptLen: number;
  /** Challenge length in bytes. */
  cLen: number;
  /** Serialized proof π length in bytes (P-256: 80). */
  fLen: number;
  /** Hash / VRF output β length in bytes (SHA-256: 32). */
  hLen: number;
}

/**
 * Domain parameters for an EC VRF suite, or `null` if `type` is not EC.
 *
 * @param type - VRF suite.
 * @returns {@link ECVRFParams}, or `null`.
 */
export function getECVRFParams(type: VRFType): ECVRFParams | null {
  switch (type) {
    case VRFType.EC_VRF_P256_SHA256_TAI:
      return {
        algorithmName: 'ECVRF-P256-SHA256-TAI',
        curve: 'P-256',
        cofactor: 1,
        digest: 'sha256',
        suiteString: new Uint8Array([0x01]),
        qLen: 32,
        ptLen: 33,
        cLen: 16,
        fLen: 80,
        hLen: 32
      };
    default:
      return null;
  }
}

