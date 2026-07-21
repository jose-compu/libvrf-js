// Licensed under the MIT license.

/**
 * Machine-readable error codes for libvrf operations.
 */
export enum VRFErrorCode {
  /** Suite is unknown or not applicable to the API called. */
  INVALID_TYPE = 'INVALID_TYPE',
  /** Key generation or prime import failed. */
  KEY_GENERATION_FAILED = 'KEY_GENERATION_FAILED',
  /** Empty or malformed serialized key / proof bytes. */
  DESERIALIZATION_FAILED = 'DESERIALIZATION_FAILED',
  /** Sync API used in a browser; call the async variant instead. */
  BROWSER_SYNC_API = 'BROWSER_SYNC_API',
  /** Object used before successful initialization. */
  NOT_INITIALIZED = 'NOT_INITIALIZED',
  /** Proof generation failed. */
  PROOF_GENERATION_FAILED = 'PROOF_GENERATION_FAILED',
}

/**
 * Typed error thrown by {@link VRF} `*OrThrow` APIs.
 *
 * @example
 * ```ts
 * try {
 *   const sk = await VRF.createAsyncOrThrow(VRFType.EC_VRF_P256_SHA256_TAI);
 * } catch (e) {
 *   if (e instanceof VRFError) console.error(e.code);
 * }
 * ```
 */
export class VRFError extends Error {
  /** Machine-readable failure code. */
  readonly code: VRFErrorCode;
  /** Optional underlying cause. */
  readonly cause?: unknown;

  /**
   * @param message - Human-readable description.
   * @param code - {@link VRFErrorCode} for programmatic handling.
   * @param cause - Optional nested error.
   */
  constructor(message: string, code: VRFErrorCode, cause?: unknown) {
    super(message);
    this.name = 'VRFError';
    this.code = code;
    this.cause = cause;
  }
}
