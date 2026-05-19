// Licensed under the MIT license.

/**
 * Machine-readable error codes for libvrf operations.
 */
export enum VRFErrorCode {
  INVALID_TYPE = 'INVALID_TYPE',
  KEY_GENERATION_FAILED = 'KEY_GENERATION_FAILED',
  DESERIALIZATION_FAILED = 'DESERIALIZATION_FAILED',
  BROWSER_SYNC_API = 'BROWSER_SYNC_API',
  NOT_INITIALIZED = 'NOT_INITIALIZED',
  PROOF_GENERATION_FAILED = 'PROOF_GENERATION_FAILED',
}

/**
 * Typed error thrown by {@link VRF} `*OrThrow` APIs.
 */
export class VRFError extends Error {
  readonly code: VRFErrorCode;
  readonly cause?: unknown;

  constructor(message: string, code: VRFErrorCode, cause?: unknown) {
    super(message);
    this.name = 'VRFError';
    this.code = code;
    this.cause = cause;
  }
}
