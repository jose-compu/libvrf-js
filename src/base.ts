// Licensed under the MIT license.

import { VRFType } from './types';

/**
 * Abstract base for any VRF object bound to a {@link VRFType}.
 */
export abstract class VRFObject {
  protected type: VRFType = VRFType.UNKNOWN;

  /**
   * Whether this object holds usable cryptographic material.
   */
  abstract isInitialized(): boolean;

  /**
   * VRF suite associated with this object.
   */
  getType(): VRFType {
    return this.type;
  }

  /**
   * Sets the VRF suite for this object.
   * @param type - Suite identifier.
   */
  protected setType(type: VRFType): void {
    this.type = type;
  }
}

/**
 * Objects that can produce a deep copy of themselves.
 */
export interface Clonable<T> {
  /**
   * Deep copy of this object.
   */
  clone(): T;
}

/**
 * Objects that support binary (de)serialization.
 */
export interface Serializable {
  /**
   * Serialize to bytes. Length and encoding depend on the concrete type
   * (see class JSDoc for EC vs RSA expectations).
   */
  toBytes(): Uint8Array;

  /**
   * Deserialize from bytes for the given suite.
   * @param type - VRF suite.
   * @param data - Serialized bytes (must be non-empty for success).
   * @returns `true` if deserialization succeeded and the object is initialized.
   */
  fromBytes(type: VRFType, data: Uint8Array): boolean;
}

/**
 * Abstract VRF proof π.
 *
 * **Serialized length (`toBytes`):**
 * - EC P-256: **80** bytes (`ECVRFParams.fLen`).
 * - RSA: modulus size in bytes (256 / 384 / 512 for 2048 / 3072 / 4096).
 *
 * **VRF output β (`getVRFValue`):** hash digest length for the suite
 * (32 for SHA-256, 48 for SHA-384, 64 for SHA-512). Empty array if not initialized.
 */
export abstract class Proof extends VRFObject implements Clonable<Proof>, Serializable {
  /**
   * VRF output β associated with this proof.
   * @returns Digest-sized bytes, or empty if not initialized.
   */
  abstract getVRFValue(): Uint8Array;

  /** Deep copy of this proof. */
  abstract clone(): Proof;

  /** Serialize π (see class docs for expected length). */
  abstract toBytes(): Uint8Array;

  /**
   * Deserialize π from bytes.
   * @param type - Suite that produced the proof.
   * @param data - Proof bytes (non-empty).
   */
  abstract fromBytes(type: VRFType, data: Uint8Array): boolean;
}

/**
 * Abstract VRF public key PK.
 *
 * **Serialized format (`toBytes` / `fromBytes`):**
 * - EC: compressed SEC1 point, **33** bytes.
 * - RSA: SPKI DER (`pkcs8-public-der`), variable length.
 */
export abstract class PublicKey extends VRFObject implements Clonable<PublicKey>, Serializable {
  /**
   * Verify proof π for public input α.
   * @param input - Public input α (arbitrary length).
   * @param proof - Proof π for the same suite.
   * @returns `[ok, beta]` — on failure `ok` is false and `beta` is empty.
   */
  abstract verifyVRFProof(input: Uint8Array, proof: Proof): [boolean, Uint8Array];

  /** Deep copy of this public key. */
  abstract clone(): PublicKey;

  /** Serialize PK (see class docs for format / length). */
  abstract toBytes(): Uint8Array;

  /**
   * Deserialize PK from bytes.
   * @param type - Suite for the key.
   * @param data - Public key bytes (non-empty).
   */
  abstract fromBytes(type: VRFType, data: Uint8Array): boolean;
}

/**
 * Abstract VRF secret key SK.
 *
 * Prefer suite-specific async APIs on {@link ECSecretKey} in browsers.
 * Input α may be any length; empty input is allowed by the API.
 */
export abstract class SecretKey extends VRFObject implements Clonable<SecretKey> {
  /**
   * Prove: produce π for public input α (sync; Node.js for EC).
   * @param input - Public input α.
   * @returns Proof, or `null` on failure.
   */
  abstract getVRFProof(input: Uint8Array): Proof | null;

  /**
   * Derive the corresponding public key.
   * @returns Public key, or `null` if not initialized.
   */
  abstract getPublicKey(): PublicKey | null;

  /** Deep copy of this secret key. */
  abstract clone(): SecretKey;
}
