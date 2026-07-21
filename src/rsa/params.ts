// Licensed under the MIT license.

import { VRFType } from '../types';
import { constants } from 'crypto';

/**
 * Domain parameters for an RSA VRF suite (RFC 9381 FDH / PSS-NOSALT).
 *
 * Proof π length equals `bits / 8` (256 / 384 / 512). β length equals the
 * digest size (32 / 48 / 64 for SHA-256 / SHA-384 / SHA-512).
 */
export interface RSAVRFParams {
  algorithmName: string;
  /** Modulus bit length (2048, 3072, or 4096). */
  bits: number;
  primes: number;
  e: number;
  digest: string;
  padMode: number;
  suiteString: string;
}

/**
 * Domain parameters for an RSA VRF suite, or `null` if `type` is not RSA.
 *
 * @param type - VRF suite.
 * @returns {@link RSAVRFParams}, or `null`.
 */
export function getRSAVRFParams(type: VRFType): RSAVRFParams | null {
  switch (type) {
    case VRFType.RSA_FDH_VRF_RSA2048_SHA256:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA2048-SHA256',
        bits: 2048,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_NO_PADDING,
        suiteString: '\x01'
      };
    case VRFType.RSA_FDH_VRF_RSA3072_SHA256:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA3072-SHA256',
        bits: 3072,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_NO_PADDING,
        suiteString: '\x01'
      };
    case VRFType.RSA_FDH_VRF_RSA4096_SHA384:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA4096-SHA384',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha384',
        padMode: constants.RSA_NO_PADDING,
        suiteString: '\x02'
      };
    case VRFType.RSA_FDH_VRF_RSA4096_SHA512:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA4096-SHA512',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha512',
        padMode: constants.RSA_NO_PADDING,
        suiteString: '\x03'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA2048-SHA256',
        bits: 2048,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: '\xF1RSA-PSS'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA3072-SHA256',
        bits: 3072,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: '\xF1RSA-PSS'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA4096-SHA384',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha384',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: '\xF2RSA-PSS'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA4096-SHA512',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha512',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: '\xF3RSA-PSS'
      };
    default:
      return null;
  }
}

