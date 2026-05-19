// Licensed under the MIT license.

import { VRFType, isRSAType, isECType } from './types';
import { Proof, PublicKey, SecretKey } from './base';
import { ECSecretKey, ECProof, ECPublicKey } from './ec/ecvrf';
import { RSASecretKey, RSAProof, RSAPublicKey } from './rsa/rsavrf';
import { createNodeRsaFromPrimes } from './rsa/key-import';
import { isBrowser } from './utils';
import { VRFError, VRFErrorCode } from './errors';

/**
 * The main VRF class that encapsulates VRF operations. All methods are static.
 */
export class VRF {
  /**
   * Create a new VRF secret key (async - works in both Node.js and browsers).
   */
  static async createAsync(type: VRFType): Promise<SecretKey | null> {
    try {
      return await VRF.createAsyncOrThrow(type);
    } catch {
      return null;
    }
  }

  /**
   * Creates a new VRF secret key; throws {@link VRFError} on failure.
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
   * Creates a new VRF secret key for the specified VRF type.
   * For browsers and EC VRF, prefer using createAsync().
   * Returns the created secret key object, or null if key generation fails.
   */
  static create(type: VRFType): SecretKey | null {
    try {
      return VRF.createOrThrow(type);
    } catch {
      return null;
    }
  }

  /**
   * Creates a new VRF secret key; throws {@link VRFError} on failure.
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
   * Create an RSA VRF secret key from prime factors p and q (big-endian unsigned).
   * Used for RFC 9381 test vectors and importing trusted RSA keys.
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
   * Deserializes a VRF proof from a Uint8Array for the specified VRF type.
   */
  static proofFromBytes(type: VRFType, data: Uint8Array): Proof | null {
    try {
      return VRF.proofFromBytesOrThrow(type, data);
    } catch {
      return null;
    }
  }

  /**
   * Deserializes a VRF proof; throws {@link VRFError} on failure.
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
   * Deserializes a VRF public key from a Uint8Array for the specified VRF type.
   */
  static publicKeyFromBytes(type: VRFType, data: Uint8Array): PublicKey | null {
    try {
      return VRF.publicKeyFromBytesOrThrow(type, data);
    } catch {
      return null;
    }
  }

  /**
   * Deserializes a VRF public key; throws {@link VRFError} on failure.
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
   * Serialize a secret key. RSA: PKCS#8 DER; EC: raw private scalar.
   * Warning: output is sensitive; never log or commit these bytes.
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
   * Deserialize a secret key. Returns null on failure.
   * EC import uses the Node.js sync path; use createAsync in browsers.
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
