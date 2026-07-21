// Licensed under the MIT license.

import { VRFType, isRSAType, isECType } from './types';
import { Proof, PublicKey, SecretKey } from './base';
import { ECSecretKey, ECProof, ECPublicKey } from './ec/ecvrf';
import { RSASecretKey, RSAProof, RSAPublicKey } from './rsa/rsavrf';
import { createNodeRsaFromPrimes } from './rsa/key-import';
import { isBrowser } from './utils';
import { VRFError, VRFErrorCode } from './errors';

/**
 * Static entry point for VRF key generation and (de)serialization.
 *
 * Prefer the `*OrThrow` variants when you want typed {@link VRFError} failures;
 * the non-throwing variants return `null` on failure.
 *
 * **Byte-length expectations (common cases):**
 * - EC (`EC_VRF_P256_SHA256_TAI`): SK raw scalar **32** bytes; PK compressed point **33** bytes;
 *   proof **80** bytes (`fLen`); β **32** bytes.
 * - RSA-2048: proof **256** bytes (modulus size); β = hash digest length (32 for SHA-256).
 * - RSA-3072: proof **384** bytes; RSA-4096: proof **512** bytes.
 * - RSA SK: PKCS#8 DER (variable length); RSA PK: SPKI DER (variable length).
 */
export class VRF {
  /**
   * Create a new VRF secret key (async — works in Node.js and browsers).
   *
   * @param type - Suite to generate (RSA or EC).
   * @returns Initialized {@link SecretKey}, or `null` on failure.
   * @see {@link createAsyncOrThrow}
   */
  static async createAsync(type: VRFType): Promise<SecretKey | null> {
    try {
      return await VRF.createAsyncOrThrow(type);
    } catch {
      return null;
    }
  }

  /**
   * Create a new VRF secret key; throws {@link VRFError} on failure.
   *
   * @param type - Suite to generate (RSA or EC).
   * @returns Initialized {@link SecretKey}.
   * @throws {VRFError} {@link VRFErrorCode.INVALID_TYPE} if `type` is unsupported.
   * @throws {VRFError} {@link VRFErrorCode.KEY_GENERATION_FAILED} if key material cannot be created.
   */
  static async createAsyncOrThrow(type: VRFType): Promise<SecretKey> {
    if (!isRSAType(type) && !isECType(type)) {
      throw new VRFError(`Unsupported VRF type: ${type}`, VRFErrorCode.INVALID_TYPE);
    }

    try {
      if (isRSAType(type)) {
        return new RSASecretKey(type);
      }

      const key = new ECSecretKey(type);
      await key.initializeAsync();
      if (!key.isInitialized()) {
        throw new VRFError('EC VRF key initialization failed', VRFErrorCode.KEY_GENERATION_FAILED);
      }
      return key;
    } catch (error) {
      if (error instanceof VRFError) {
        throw error;
      }
      throw new VRFError('VRF key creation failed', VRFErrorCode.KEY_GENERATION_FAILED, error);
    }
  }

  /**
   * Create a new VRF secret key (sync — **Node.js only**).
   * In browsers, use {@link createAsync} instead.
   *
   * @param type - Suite to generate (RSA or EC).
   * @returns Initialized {@link SecretKey}, or `null` on failure.
   * @see {@link createOrThrow}
   */
  static create(type: VRFType): SecretKey | null {
    try {
      return VRF.createOrThrow(type);
    } catch {
      return null;
    }
  }

  /**
   * Create a new VRF secret key (sync — **Node.js only**); throws {@link VRFError} on failure.
   *
   * @param type - Suite to generate (RSA or EC).
   * @returns Initialized {@link SecretKey}.
   * @throws {VRFError} {@link VRFErrorCode.BROWSER_SYNC_API} if called in a browser.
   * @throws {VRFError} {@link VRFErrorCode.INVALID_TYPE} if `type` is unsupported.
   * @throws {VRFError} {@link VRFErrorCode.KEY_GENERATION_FAILED} if key material cannot be created.
   */
  static createOrThrow(type: VRFType): SecretKey {
    if (isBrowser()) {
      throw new VRFError('Use VRF.createAsyncOrThrow() in browser environments', VRFErrorCode.BROWSER_SYNC_API);
    }

    if (!isRSAType(type) && !isECType(type)) {
      throw new VRFError(`Unsupported VRF type: ${type}`, VRFErrorCode.INVALID_TYPE);
    }

    try {
      if (isRSAType(type)) {
        return new RSASecretKey(type);
      }

      const key = new ECSecretKey(type);
      (key as unknown as { initializeSync(): void }).initializeSync();
      if (!key.isInitialized()) {
        throw new VRFError('EC VRF key initialization failed', VRFErrorCode.KEY_GENERATION_FAILED);
      }
      return key;
    } catch (error) {
      if (error instanceof VRFError) {
        throw error;
      }
      throw new VRFError('VRF key creation failed', VRFErrorCode.KEY_GENERATION_FAILED, error);
    }
  }

  /**
   * Create an RSA VRF secret key from prime factors `p` and `q` (big-endian unsigned).
   * Intended for RFC 9381 test vectors and importing trusted RSA keys.
   *
   * @param type - Must be an RSA VRF suite.
   * @param p - First prime factor (non-empty big-endian bytes).
   * @param q - Second prime factor (non-empty big-endian bytes).
   * @returns Initialized RSA {@link SecretKey}, or `null` on failure.
   * @see {@link createRsaFromPrimesOrThrow}
   */
  static createRsaFromPrimes(type: VRFType, p: Uint8Array, q: Uint8Array): SecretKey | null {
    try {
      return VRF.createRsaFromPrimesOrThrow(type, p, q);
    } catch {
      return null;
    }
  }

  /**
   * Create an RSA VRF secret key from prime factors; throws {@link VRFError} on failure.
   *
   * @param type - Must be an RSA VRF suite.
   * @param p - First prime factor (non-empty big-endian bytes).
   * @param q - Second prime factor (non-empty big-endian bytes).
   * @returns Initialized RSA {@link SecretKey}.
   * @throws {VRFError} {@link VRFErrorCode.INVALID_TYPE} if `type` is not RSA.
   * @throws {VRFError} {@link VRFErrorCode.KEY_GENERATION_FAILED} if primes are empty or key construction fails.
   */
  static createRsaFromPrimesOrThrow(type: VRFType, p: Uint8Array, q: Uint8Array): SecretKey {
    if (!isRSAType(type)) {
      throw new VRFError(`RSA primes import requires an RSA VRF type, got: ${type}`, VRFErrorCode.INVALID_TYPE);
    }
    if (p.length === 0 || q.length === 0) {
      throw new VRFError('RSA primes p and q must be non-empty', VRFErrorCode.KEY_GENERATION_FAILED);
    }

    try {
      const rsaKey = createNodeRsaFromPrimes(p, q);
      const sk = new RSASecretKey(type, rsaKey);
      if (!sk.isInitialized()) {
        throw new VRFError('RSA VRF key from primes is not initialized', VRFErrorCode.KEY_GENERATION_FAILED);
      }
      return sk;
    } catch (error) {
      if (error instanceof VRFError) {
        throw error;
      }
      throw new VRFError('Failed to create RSA VRF key from primes', VRFErrorCode.KEY_GENERATION_FAILED, error);
    }
  }

  /**
   * Deserialize a VRF proof from bytes.
   *
   * **Expected lengths:** EC P-256 proof **80** bytes; RSA proof = modulus byte length
   * (256 / 384 / 512 for 2048 / 3072 / 4096).
   *
   * @param type - Suite that produced the proof.
   * @param data - Serialized proof (must be non-empty).
   * @returns {@link Proof}, or `null` on failure.
   * @see {@link proofFromBytesOrThrow}
   */
  static proofFromBytes(type: VRFType, data: Uint8Array): Proof | null {
    try {
      return VRF.proofFromBytesOrThrow(type, data);
    } catch {
      return null;
    }
  }

  /**
   * Deserialize a VRF proof; throws {@link VRFError} on failure.
   *
   * @param type - Suite that produced the proof.
   * @param data - Serialized proof (must be non-empty; see {@link proofFromBytes} for lengths).
   * @returns Initialized {@link Proof}.
   * @throws {VRFError} {@link VRFErrorCode.INVALID_TYPE} if `type` is unsupported.
   * @throws {VRFError} {@link VRFErrorCode.DESERIALIZATION_FAILED} if `data` is empty or invalid.
   */
  static proofFromBytesOrThrow(type: VRFType, data: Uint8Array): Proof {
    if (!isECType(type) && !isRSAType(type)) {
      throw new VRFError(`Unsupported VRF type: ${type}`, VRFErrorCode.INVALID_TYPE);
    }

    if (data.length === 0) {
      throw new VRFError('Proof bytes must not be empty', VRFErrorCode.DESERIALIZATION_FAILED);
    }

    try {
      const proof: Proof = isECType(type) ? new ECProof() : new RSAProof();
      const success = proof.fromBytes(type, data);
      if (!success || !proof.isInitialized()) {
        throw new VRFError('Proof deserialization failed', VRFErrorCode.DESERIALIZATION_FAILED);
      }
      return proof;
    } catch (error) {
      if (error instanceof VRFError) {
        throw error;
      }
      throw new VRFError('Proof deserialization failed', VRFErrorCode.DESERIALIZATION_FAILED, error);
    }
  }

  /**
   * Deserialize a VRF public key from bytes.
   *
   * **Expected formats / lengths:**
   * - EC: compressed SEC1 point, **33** bytes (`0x02`/`0x03` prefix).
   * - RSA: SPKI DER (`pkcs8-public-der`), variable length.
   *
   * @param type - Suite for the public key.
   * @param data - Serialized public key (must be non-empty).
   * @returns {@link PublicKey}, or `null` on failure.
   * @see {@link publicKeyFromBytesOrThrow}
   */
  static publicKeyFromBytes(type: VRFType, data: Uint8Array): PublicKey | null {
    try {
      return VRF.publicKeyFromBytesOrThrow(type, data);
    } catch {
      return null;
    }
  }

  /**
   * Deserialize a VRF public key; throws {@link VRFError} on failure.
   *
   * @param type - Suite for the public key.
   * @param data - Serialized public key (must be non-empty; see {@link publicKeyFromBytes}).
   * @returns Initialized {@link PublicKey}.
   * @throws {VRFError} {@link VRFErrorCode.INVALID_TYPE} if `type` is unsupported.
   * @throws {VRFError} {@link VRFErrorCode.DESERIALIZATION_FAILED} if `data` is empty or invalid.
   */
  static publicKeyFromBytesOrThrow(type: VRFType, data: Uint8Array): PublicKey {
    if (!isECType(type) && !isRSAType(type)) {
      throw new VRFError(`Unsupported VRF type: ${type}`, VRFErrorCode.INVALID_TYPE);
    }

    if (data.length === 0) {
      throw new VRFError('Public key bytes must not be empty', VRFErrorCode.DESERIALIZATION_FAILED);
    }

    try {
      const publicKey: PublicKey = isECType(type) ? new ECPublicKey() : new RSAPublicKey();
      const success = publicKey.fromBytes(type, data);
      if (!success || !publicKey.isInitialized()) {
        throw new VRFError('Public key deserialization failed', VRFErrorCode.DESERIALIZATION_FAILED);
      }
      return publicKey;
    } catch (error) {
      if (error instanceof VRFError) {
        throw error;
      }
      throw new VRFError('Public key deserialization failed', VRFErrorCode.DESERIALIZATION_FAILED, error);
    }
  }

  /**
   * Serialize a secret key.
   *
   * **Formats:**
   * - RSA: PKCS#8 DER private key (variable length).
   * - EC: raw private scalar (**32** bytes for P-256).
   *
   * **Warning:** output is sensitive; never log or commit these bytes.
   *
   * @param secretKey - Initialized secret key.
   * @returns Serialized bytes, or `null` if the key is not initialized / has no exporter.
   */
  static secretKeyToBytes(secretKey: SecretKey): Uint8Array | null {
    if (!secretKey.isInitialized()) {
      return null;
    }
    if (isRSAType(secretKey.getType())) {
      const rsa = secretKey as RSASecretKey;
      if (typeof rsa.toBytes === 'function') {
        const bytes = rsa.toBytes();
        return bytes.length > 0 ? bytes : null;
      }
    }
    if (isECType(secretKey.getType())) {
      const ec = secretKey as ECSecretKey;
      if (typeof ec.toBytes === 'function') {
        const bytes = ec.toBytes();
        return bytes.length > 0 ? bytes : null;
      }
    }
    return null;
  }

  /**
   * Deserialize a secret key. Returns `null` on failure.
   *
   * **Formats:** same as {@link secretKeyToBytes}.
   * EC import uses the Node.js sync path; prefer {@link createAsync} in browsers.
   *
   * @param type - Suite for the secret key.
   * @param data - Serialized secret key (must be non-empty).
   * @returns {@link SecretKey}, or `null` on failure.
   * @see {@link secretKeyFromBytesOrThrow}
   */
  static secretKeyFromBytes(type: VRFType, data: Uint8Array): SecretKey | null {
    try {
      return VRF.secretKeyFromBytesOrThrow(type, data);
    } catch {
      return null;
    }
  }

  /**
   * Deserialize a secret key; throws {@link VRFError} on failure.
   *
   * @param type - Suite for the secret key.
   * @param data - Serialized secret key (must be non-empty; see {@link secretKeyToBytes}).
   * @returns Initialized {@link SecretKey}.
   * @throws {VRFError} {@link VRFErrorCode.INVALID_TYPE} if `type` is unsupported.
   * @throws {VRFError} {@link VRFErrorCode.DESERIALIZATION_FAILED} if `data` is empty or invalid.
   */
  static secretKeyFromBytesOrThrow(type: VRFType, data: Uint8Array): SecretKey {
    if (!isRSAType(type) && !isECType(type)) {
      throw new VRFError(`Unsupported VRF type: ${type}`, VRFErrorCode.INVALID_TYPE);
    }
    if (data.length === 0) {
      throw new VRFError('Secret key bytes must not be empty', VRFErrorCode.DESERIALIZATION_FAILED);
    }

    if (isRSAType(type)) {
      const sk = RSASecretKey.fromBytes(type, data);
      if (!sk) {
        throw new VRFError('RSA secret key deserialization failed', VRFErrorCode.DESERIALIZATION_FAILED);
      }
      return sk;
    }

    const sk = ECSecretKey.fromBytes(type, data);
    if (!sk) {
      throw new VRFError('EC secret key deserialization failed', VRFErrorCode.DESERIALIZATION_FAILED);
    }
    return sk;
  }
}
