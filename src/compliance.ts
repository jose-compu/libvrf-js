// Licensed under the MIT license.

import { VRFType, isRSAType, isECType } from './types';

/**
 * Metadata describing interoperability and standards compliance for a VRF suite.
 */
export interface VRFSuiteInfo {
  type: VRFType;
  /** True when the suite matches RFC 9381 wire format and algorithms. */
  rfc9381Compliant: boolean;
  /** True when the suite can run in browser environments (WebCrypto). */
  browserSupported: boolean;
  /**
   * True when proofs/values are expected to match Microsoft libvrf (C++)
   * for the same keys and inputs. EC VRF in this port is not interoperable.
   */
  interoperableWithLibvrfCpp: boolean;
}

/**
 * Returns whether the given VRF type is RFC 9381 compliant in this library.
 * RSA-FDH and RSA-PSS-NOSALT suites follow RFC 9381; EC VRF uses a simplified
 * construction and is not RFC 9381 compliant (see README).
 */
export function isRFC9381Compliant(type: VRFType): boolean {
  return isRSAType(type);
}

/**
 * Returns suite metadata, or null for {@link VRFType.UNKNOWN}.
 */
export function getVRFSuiteInfo(type: VRFType): VRFSuiteInfo | null {
  if (type === VRFType.UNKNOWN) {
    return null;
  }

  const rsa = isRSAType(type);
  const ec = isECType(type);

  return {
    type,
    rfc9381Compliant: rsa,
    browserSupported: ec,
    interoperableWithLibvrfCpp: rsa,
  };
}
