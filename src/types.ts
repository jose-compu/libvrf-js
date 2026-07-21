// Licensed under the MIT license.

/**
 * Supported VRF suites.
 *
 * RSA-FDH and RSA-PSS-NOSALT follow RFC 9381 (Node.js).
 * {@link VRFType.EC_VRF_P256_SHA256_TAI} is a simplified browser-friendly construction
 * and is **not** RFC 9381 wire-compatible (see README).
 */
export enum VRFType {
  /** RSA-FDH, 2048-bit modulus, SHA-256. Proof π: 256 bytes; β: 32 bytes. */
  RSA_FDH_VRF_RSA2048_SHA256 = 'RSA_FDH_VRF_RSA2048_SHA256',
  /** RSA-FDH, 3072-bit modulus, SHA-256. Proof π: 384 bytes; β: 32 bytes. */
  RSA_FDH_VRF_RSA3072_SHA256 = 'RSA_FDH_VRF_RSA3072_SHA256',
  /** RSA-FDH, 4096-bit modulus, SHA-384. Proof π: 512 bytes; β: 48 bytes. */
  RSA_FDH_VRF_RSA4096_SHA384 = 'RSA_FDH_VRF_RSA4096_SHA384',
  /** RSA-FDH, 4096-bit modulus, SHA-512. Proof π: 512 bytes; β: 64 bytes. */
  RSA_FDH_VRF_RSA4096_SHA512 = 'RSA_FDH_VRF_RSA4096_SHA512',
  /** RSA-PSS with salt length 0, 2048-bit, SHA-256. Proof π: 256 bytes; β: 32 bytes. */
  RSA_PSS_NOSALT_VRF_RSA2048_SHA256 = 'RSA_PSS_NOSALT_VRF_RSA2048_SHA256',
  /** RSA-PSS with salt length 0, 3072-bit, SHA-256. Proof π: 384 bytes; β: 32 bytes. */
  RSA_PSS_NOSALT_VRF_RSA3072_SHA256 = 'RSA_PSS_NOSALT_VRF_RSA3072_SHA256',
  /** RSA-PSS with salt length 0, 4096-bit, SHA-384. Proof π: 512 bytes; β: 48 bytes. */
  RSA_PSS_NOSALT_VRF_RSA4096_SHA384 = 'RSA_PSS_NOSALT_VRF_RSA4096_SHA384',
  /** RSA-PSS with salt length 0, 4096-bit, SHA-512. Proof π: 512 bytes; β: 64 bytes. */
  RSA_PSS_NOSALT_VRF_RSA4096_SHA512 = 'RSA_PSS_NOSALT_VRF_RSA4096_SHA512',
  /**
   * Simplified EC VRF on P-256 / SHA-256 (browser WebCrypto).
   * SK: 32 bytes; PK: 33 bytes compressed; proof: 80 bytes; β: 32 bytes.
   * Not RFC 9381 interoperable.
   */
  EC_VRF_P256_SHA256_TAI = 'EC_VRF_P256_SHA256_TAI',
  /** Sentinel / uninitialized. */
  UNKNOWN = 'UNKNOWN'
}

/**
 * Whether `type` is any RSA-based suite (FDH or PSS).
 */
export function isRSAType(type: VRFType): boolean {
  return type === VRFType.RSA_FDH_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA512 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512;
}

/**
 * Whether `type` is an elliptic-curve suite.
 */
export function isECType(type: VRFType): boolean {
  return type === VRFType.EC_VRF_P256_SHA256_TAI;
}

/**
 * Whether `type` is RSA-FDH (RFC 9381).
 */
export function isRSAFDHType(type: VRFType): boolean {
  return type === VRFType.RSA_FDH_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA512;
}

/**
 * Whether `type` is RSA-PSS-NOSALT (RFC 9381).
 */
export function isRSAPSSType(type: VRFType): boolean {
  return type === VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512;
}

/**
 * String form of a {@link VRFType} enum value.
 */
export function vrfTypeToString(type: VRFType): string {
  return type.toString();
}
