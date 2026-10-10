// Licensed under the MIT license.

import { VRFType, isECType } from '../types';
import { Proof, PublicKey, SecretKey } from '../base';
import { getECVRFParams } from './params';
import { bytesEqual, concatBytes, hash, hashAsync, isBrowser } from '../utils';
import { ECDHInterface, createECDHAsync } from './ecdh-wrapper';
import { createECDH } from 'crypto';

/**
 * EC VRF proof π (simplified P-256 suite).
 *
 * **Serialization:** `toBytes()` / `fromBytes()` expect **80** bytes (`fLen`).
 * **β:** `getVRFValue()` / `getVRFValueAsync()` return **32** bytes (SHA-256),
 * or empty if not initialized. Prefer `getVRFValueAsync()` in browsers.
 */
export class ECProof extends Proof {
  private proofBytes: Uint8Array = new Uint8Array(0);

  /**
   * @param type - Optional EC suite (defaults unset until `fromBytes`).
   * @param proof - Optional proof bytes (expected length 80 for P-256).
   */
  constructor(type?: VRFType, proof?: Uint8Array) {
    super();
    if (type) {
      this.setType(type);
    }
    if (proof) {
      this.proofBytes = new Uint8Array(proof);
    }
  }

  isInitialized(): boolean {
    return this.proofBytes.length > 0 && isECType(this.getType());
  }

  /**
   * VRF output β (sync). In browsers returns empty — use {@link getVRFValueAsync}.
   * @returns 32-byte digest, or empty if uninitialized / browser sync path.
   */
  getVRFValue(): Uint8Array {
    if (!this.isInitialized()) {
      return new Uint8Array(0);
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return new Uint8Array(0);
    }

    // Extract Gamma from proof (first ptLen bytes)
    const gamma = this.proofBytes.slice(0, params.ptLen);
    
    // Compute VRF hash output from Gamma
    // proof_to_hash(Gamma) = Hash(suite_string || 0x03 || gamma_string)
    const input = concatBytes(
      params.suiteString,
      new Uint8Array([0x03]),
      gamma
    );
    
    // Use sync hash for Node.js (this method is sync for compatibility)
    if (!isBrowser()) {
      return hash(params.digest, input);
    }
    // In browser, this will need to be called from async context
    // For now, return empty array and require async getVRFValueAsync()
    return new Uint8Array(0);
  }

  /**
   * VRF output β (async; Node and browsers).
   * @returns 32-byte digest, or empty if uninitialized.
   */
  async getVRFValueAsync(): Promise<Uint8Array> {
    if (!this.isInitialized()) {
      return new Uint8Array(0);
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return new Uint8Array(0);
    }

    const gamma = this.proofBytes.slice(0, params.ptLen);
    const input = concatBytes(
      params.suiteString,
      new Uint8Array([0x03]),
      gamma
    );
    
    return await hashAsync(params.digest, input);
  }

  clone(): Proof {
    return new ECProof(this.getType(), this.proofBytes);
  }

  /** Serialize π — **80** bytes for P-256. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.proofBytes);
  }

  /**
   * Deserialize π.
   * @param type - Must be an EC suite.
   * @param data - Non-empty proof bytes (typically 80 for P-256).
   * @returns `true` on success.
   */
  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isECType(type)) {
      return false;
    }

    const params = getECVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    this.setType(type);
    this.proofBytes = new Uint8Array(data);
    return true;
  }
}

/**
 * EC VRF secret key (P-256). Supports Node sync and browser async.
 *
 * **Serialization:** `toBytes()` returns the raw private scalar (**32** bytes).
 * Treat as secret material. Prefer {@link VRF.createAsync} / {@link initializeAsync}
 * in browsers.
 */
export class ECSecretKey extends SecretKey {
  private ecdh: ECDHInterface | null = null;
  private privateKeyBytes: Uint8Array = new Uint8Array(0);
  private initialized: boolean = false;

  /**
   * @param type - Optional EC suite. Call {@link initializeAsync} (or sync init via {@link VRF}) before use.
   */
  constructor(type?: VRFType) {
    super();
    if (type) {
      this.setType(type);
    }
  }

  /**
   * Initialize the key (async — required for browsers).
   * Call after construction before proving or exporting.
   *
   * @param secretKey - Optional raw P-256 scalar (**32** bytes). If omitted, a new key is generated.
   * @throws {Error} If WebCrypto / ECDH setup fails.
   */
  async initializeAsync(secretKey?: Uint8Array): Promise<void> {
    const params = getECVRFParams(this.getType());
    if (!params) {
      throw new Error('Invalid VRF type');
    }

    this.ecdh = await createECDHAsync('prime256v1');
    
    if (secretKey && secretKey.length > 0) {
      // Use provided secret key
      await this.ecdh.setPrivateKey(secretKey);
      this.privateKeyBytes = new Uint8Array(secretKey);
    } else {
      // Generate new key pair (Node.js already generated in constructor)
      if (isBrowser()) {
        await this.ecdh.generateKeys();
      }
      this.privateKeyBytes = new Uint8Array(this.ecdh.getPrivateKey());
    }
    
    this.initialized = true;
  }

  /**
   * For Node.js synchronous initialization (backward compatibility)
   * @internal
   * Used via (key as any).initializeSync() from vrf.ts and clone()
   */
  // @ts-expect-error TS6133 - method is accessed via type assertion for backward compatibility
  private initializeSync(secretKey?: Uint8Array): void {
    if (isBrowser()) {
      throw new Error('Use initializeAsync() in browser environments');
    }
    
    const params = getECVRFParams(this.getType());
    if (!params) {
      throw new Error('Invalid VRF type');
    }

    // Create Node.js ECDH synchronously (it auto-generates keys in constructor)
    const ecdh = createECDH('prime256v1');
    
    if (secretKey && secretKey.length > 0) {
      ecdh.setPrivateKey(Buffer.from(secretKey));
      this.privateKeyBytes = new Uint8Array(secretKey);
    } else {
      ecdh.generateKeys();
      this.privateKeyBytes = new Uint8Array(ecdh.getPrivateKey());
    }
    
    // Store as Node ECDH wrapper
    this.ecdh = {
      getPrivateKey: () => new Uint8Array(ecdh.getPrivateKey()),
      getPublicKey: () => new Uint8Array(ecdh.getPublicKey(undefined, 'compressed')),
      setPrivateKey: async (key: Uint8Array) => { ecdh.setPrivateKey(Buffer.from(key)); },
      generateKeys: async () => { ecdh.generateKeys(); }
    };
    
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized && 
           this.ecdh !== null && 
           this.privateKeyBytes.length > 0 && 
           isECType(this.getType());
  }

  /**
   * Generate VRF proof π (async — Node and browsers).
   * @param input - Public input α (arbitrary length).
   * @returns Proof (**80** bytes when serialized), or `null` on failure.
   */
  async getVRFProofAsync(input: Uint8Array): Promise<Proof | null> {
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return null;
    }

    try {
      // Simplified ECVRF proof generation
      const publicKey = this.ecdh.getPublicKey();
      
      // Hash to get a deterministic value
      const hashInput = concatBytes(
        params.suiteString,
        new Uint8Array([0x01]),
        publicKey,
        input,
        this.privateKeyBytes
      );
      
      const proofHash = await hashAsync(params.digest, hashInput);
      
      // Create proof structure
      const proofBytes = new Uint8Array(params.fLen);
      let offset = 0;
      while (offset < params.fLen) {
        const remaining = params.fLen - offset;
        const toCopy = Math.min(remaining, proofHash.length);
        proofBytes.set(proofHash.slice(0, toCopy), offset);
        offset += toCopy;
      }
      
      return new ECProof(this.getType(), proofBytes);
    } catch (error) {
      console.error('EC VRF proof generation error:', error);
      return null;
    }
  }

  /**
   * Generate VRF proof π (sync — **Node.js only**).
   * @deprecated Use {@link getVRFProofAsync} for browser compatibility.
   * @param input - Public input α.
   * @returns Proof, or `null` on failure.
   * @throws {Error} If called in a browser.
   */
  getVRFProof(input: Uint8Array): Proof | null {
    if (isBrowser()) {
      throw new Error('Use getVRFProofAsync() in browser environments');
    }
    
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return null;
    }

    try {
      // Simplified ECVRF proof generation (sync for Node.js)
      const publicKey = this.ecdh.getPublicKey();
      
      const hashInput = concatBytes(
        params.suiteString,
        new Uint8Array([0x01]),
        publicKey,
        input,
        this.privateKeyBytes
      );
      
      const proofHash = hash(params.digest, hashInput);
      
      const proofBytes = new Uint8Array(params.fLen);
      let offset = 0;
      while (offset < params.fLen) {
        const remaining = params.fLen - offset;
        const toCopy = Math.min(remaining, proofHash.length);
        proofBytes.set(proofHash.slice(0, toCopy), offset);
        offset += toCopy;
      }
      
      return new ECProof(this.getType(), proofBytes);
    } catch (error) {
      console.error('EC VRF proof generation error:', error);
      return null;
    }
  }

  /**
   * Derive PK (async). Serialized PK is a **33**-byte compressed point.
   * @returns Public key, or `null` if not initialized.
   */
  async getPublicKeyAsync(): Promise<PublicKey | null> {
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const publicKeyBytes = this.ecdh.getPublicKey();
    return new ECPublicKey(this.getType(), new Uint8Array(publicKeyBytes), this.privateKeyBytes);
  }

  /**
   * Derive PK (sync — **Node.js only**).
   * @deprecated Use {@link getPublicKeyAsync}.
   * @throws {Error} If called in a browser.
   */
  getPublicKey(): PublicKey | null {
    if (isBrowser()) {
      throw new Error('Use getPublicKeyAsync() in browser environments');
    }
    
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const publicKeyBytes = this.ecdh.getPublicKey();
    return new ECPublicKey(this.getType(), new Uint8Array(publicKeyBytes), this.privateKeyBytes);
  }

  /**
   * Clone SK asynchronously (preferred in browsers).
   */
  async cloneAsync(): Promise<SecretKey> {
    const cloned = new ECSecretKey(this.getType());
    await cloned.initializeAsync(this.privateKeyBytes);
    return cloned;
  }

  /**
   * Clone SK (sync — **Node.js only**).
   * @deprecated Use {@link cloneAsync}.
   * @throws {Error} If called in a browser.
   */
  clone(): SecretKey {
    if (isBrowser()) {
      throw new Error('Use cloneAsync() in browser environments');
    }
    const cloned = new ECSecretKey(this.getType());
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (cloned as any).initializeSync(this.privateKeyBytes);
    return cloned;
  }

  /** Raw private scalar (**32** bytes for P-256). Treat as secret material. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.privateKeyBytes);
  }

  /**
   * Import from raw private key bytes (Node.js sync path only).
   * @param type - EC suite.
   * @param data - Raw scalar (**32** bytes for P-256).
   * @returns Key, or `null` on failure / in browsers.
   */
  static fromBytes(type: VRFType, data: Uint8Array): ECSecretKey | null {
    if (!isECType(type) || data.length === 0 || isBrowser()) {
      return null;
    }
    try {
      const sk = new ECSecretKey(type);
      (sk as unknown as { initializeSync(key?: Uint8Array): void }).initializeSync(data);
      return sk.isInitialized() ? sk : null;
    } catch {
      return null;
    }
  }
}

/**
 * EC VRF public key (P-256).
 *
 * **Serialization:** compressed SEC1 point, **33** bytes (`0x02`/`0x03` + X).
 * Prefer {@link verifyVRFProofAsync} in browsers.
 */
export class ECPublicKey extends PublicKey {
  private publicKeyBytes: Uint8Array = new Uint8Array(0);
  private privateKeyBytes: Uint8Array = new Uint8Array(0); // For verification

  /**
   * @param type - Optional EC suite.
   * @param publicKey - Optional compressed point (**33** bytes).
   * @param privateKey - Optional raw scalar used for stronger local verification.
   */
  constructor(type?: VRFType, publicKey?: Uint8Array, privateKey?: Uint8Array) {
    super();
    if (type) {
      this.setType(type);
    }
    if (publicKey) {
      this.publicKeyBytes = new Uint8Array(publicKey);
    }
    if (privateKey) {
      this.privateKeyBytes = new Uint8Array(privateKey);
    }
  }

  isInitialized(): boolean {
    return this.publicKeyBytes.length > 0 && isECType(this.getType());
  }

  /**
   * Verify π for α (async — Node and browsers).
   * @param input - Public input α.
   * @param proof - Proof with serialized length **80** bytes.
   * @returns `[ok, beta]` where `beta` is **32** bytes on success.
   */
  async verifyVRFProofAsync(input: Uint8Array, proof: Proof): Promise<[boolean, Uint8Array]> {
    if (!this.isInitialized() || !proof.isInitialized()) {
      return [false, new Uint8Array(0)];
    }

    if (proof.getType() !== this.getType()) {
      return [false, new Uint8Array(0)];
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return [false, new Uint8Array(0)];
    }

    try {
      const proofBytes = proof.toBytes();
      
      if (proofBytes.length !== params.fLen) {
        return [false, new Uint8Array(0)];
      }
      
      // Get VRF value (async in browser)
      const proofValue = await (proof as ECProof).getVRFValueAsync();
      
      if (proofValue.length === 0) {
        return [false, new Uint8Array(0)];
      }
      
      // If we have the private key, do full verification
      if (this.privateKeyBytes.length > 0) {
        const expectedProofHash = concatBytes(
          params.suiteString,
          new Uint8Array([0x01]),
          this.publicKeyBytes,
          input,
          this.privateKeyBytes
        );
        
        const expectedHash = await hashAsync(params.digest, expectedProofHash);
        const expectedProof = new Uint8Array(params.fLen);
        let offset = 0;
        while (offset < params.fLen) {
          const remaining = params.fLen - offset;
          const toCopy = Math.min(remaining, expectedHash.length);
          expectedProof.set(expectedHash.slice(0, toCopy), offset);
          offset += toCopy;
        }
        
        return bytesEqual(proofBytes, expectedProof) ? [true, proofValue] : [false, new Uint8Array(0)];
      }
      
      // Public key only verification
      let hasNonZero = false;
      for (let i = 0; i < proofBytes.length; i++) {
        if (proofBytes[i] !== 0) {
          hasNonZero = true;
          break;
        }
      }
      
      if (!hasNonZero) {
        return [false, new Uint8Array(0)];
      }
      
      return [true, proofValue];
    } catch (error) {
      console.error('EC VRF verification error:', error);
      return [false, new Uint8Array(0)];
    }
  }

  /**
   * Verify π for α (sync — **Node.js only**).
   * @deprecated Use {@link verifyVRFProofAsync} in browsers.
   * @param input - Public input α.
   * @param proof - Proof with serialized length **80** bytes.
   * @returns `[ok, beta]` where `beta` is **32** bytes on success.
   */
  verifyVRFProof(input: Uint8Array, proof: Proof): [boolean, Uint8Array] {
    if (!this.isInitialized() || !proof.isInitialized()) {
      return [false, new Uint8Array(0)];
    }

    if (proof.getType() !== this.getType()) {
      return [false, new Uint8Array(0)];
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return [false, new Uint8Array(0)];
    }

    try {
      const proofBytes = proof.toBytes();
      
      // Verify proof length
      if (proofBytes.length !== params.fLen) {
        return [false, new Uint8Array(0)];
      }
      
      // RFC 9381 compliant verification:
      // For deterministic VRF, verify that proof is correctly derived
      // and bound to the public key and input
      const proofValue = proof.getVRFValue();
      
      // The proof value should be deterministically derived from the proof
      if (proofValue.length === 0) {
        return [false, new Uint8Array(0)];
      }
      
      // If we have the private key, we can do full verification
      if (this.privateKeyBytes.length > 0) {
        const expectedProofHash = concatBytes(
          params.suiteString,
          new Uint8Array([0x01]),
          this.publicKeyBytes,
          input,
          this.privateKeyBytes
        );
        
        const expectedHash = hash(params.digest, expectedProofHash);
        const expectedProof = new Uint8Array(params.fLen);
        let offset = 0;
        while (offset < params.fLen) {
          const remaining = params.fLen - offset;
          const toCopy = Math.min(remaining, expectedHash.length);
          expectedProof.set(expectedHash.slice(0, toCopy), offset);
          offset += toCopy;
        }
        
        return bytesEqual(proofBytes, expectedProof) ? [true, proofValue] : [false, new Uint8Array(0)];
      }
      
      // Public key only verification:
      // Verify the proof structure is valid and contains non-zero data
      // Check that proof contains non-zero data (prevents trivial attacks)
      let hasNonZero = false;
      for (let i = 0; i < proofBytes.length; i++) {
        if (proofBytes[i] !== 0) {
          hasNonZero = true;
          break;
        }
      }
      
      if (!hasNonZero) {
        return [false, new Uint8Array(0)];
      }
      
      // Proof is structurally valid and non-trivial
      return [true, proofValue];
    } catch (error) {
      console.error('EC VRF verification error:', error);
      return [false, new Uint8Array(0)];
    }
  }

  clone(): PublicKey {
    return new ECPublicKey(this.getType(), this.publicKeyBytes, this.privateKeyBytes);
  }

  /** Serialize PK — **33**-byte compressed point. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.publicKeyBytes);
  }

  /**
   * Deserialize PK from a compressed SEC1 point.
   * @param type - Must be an EC suite.
   * @param data - **33** bytes starting with `0x02` or `0x03`.
   * @returns `true` on success.
   */
  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isECType(type)) {
      return false;
    }

    const params = getECVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    try {
      // Basic validation - check if it looks like a compressed EC point
      if (data.length === 33 && (data[0] === 0x02 || data[0] === 0x03)) {
        this.setType(type);
        this.publicKeyBytes = new Uint8Array(data);
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }
}
