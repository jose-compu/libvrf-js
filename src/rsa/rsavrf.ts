// Licensed under the MIT license.

import NodeRSA from 'node-rsa';
import { VRFType, isRSAType, isRSAFDHType, isRSAPSSType } from '../types';
import { Proof, PublicKey, SecretKey } from '../base';
import { getRSAVRFParams, RSAVRFParams } from './params';
import { privateEncrypt, publicDecrypt, constants } from 'crypto';
import {
  constructRsaFdhTbs,
  constructRsaPssTbs,
  generateMgf1SaltFromRsaKey,
  rsaProofToHash,
  rsaPssNoSaltSign,
  rsaPssNoSaltVerify,
} from './rfc9381';

/**
 * RSA VRF Proof implementation
 */
export class RSAProof extends Proof {
  private proofBytes: Uint8Array = new Uint8Array(0);

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
    return this.proofBytes.length > 0 && isRSAType(this.getType());
  }

  getVRFValue(): Uint8Array {
    if (!this.isInitialized()) {
      return new Uint8Array(0);
    }

    const params = getRSAVRFParams(this.getType());
    if (!params) {
      return new Uint8Array(0);
    }

    return rsaProofToHash(params, this.proofBytes);
  }

  clone(): Proof {
    return new RSAProof(this.getType(), this.proofBytes);
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.proofBytes);
  }

  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isRSAType(type)) {
      return false;
    }

    const params = getRSAVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    this.setType(type);
    this.proofBytes = new Uint8Array(data);
    return true;
  }
}

/**
 * RSA VRF Secret Key implementation
 */
export class RSASecretKey extends SecretKey {
  private rsaKey: NodeRSA | undefined = undefined;
  private mgf1Salt: Uint8Array = new Uint8Array(0);

  constructor(type?: VRFType, rsaKey?: NodeRSA) {
    super();
    if (type) {
      this.setType(type);
      const params = getRSAVRFParams(type);
      if (params) {
        if (rsaKey) {
          this.rsaKey = rsaKey;
        } else {
          // Generate new RSA key pair
          this.rsaKey = new NodeRSA({ b: params.bits });
          this.rsaKey.setOptions({
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
          });
        }
        
        this.mgf1Salt = generateMgf1SaltFromRsaKey(this.rsaKey);
      }
    }
  }

  isInitialized(): boolean {
    return this.rsaKey !== undefined && 
           this.mgf1Salt.length > 0 &&
           isRSAType(this.getType());
  }

  getVRFProof(input: Uint8Array): Proof | null {
    if (!this.isInitialized() || !this.rsaKey) {
      return null;
    }

    const params = getRSAVRFParams(this.getType());
    if (!params) {
      return null;
    }

    try {
      let proof: Uint8Array;
      
      if (isRSAFDHType(this.getType())) {
        proof = this.rsaFDHProve(input, params);
      } else if (isRSAPSSType(this.getType())) {
        proof = this.rsaPSSProve(input, params);
      } else {
        return null;
      }
      
      return new RSAProof(this.getType(), proof);
    } catch (error) {
      console.error('RSA VRF proof generation error:', error);
      return null;
    }
  }

  getPublicKey(): PublicKey | null {
    if (!this.isInitialized() || !this.rsaKey) {
      return null;
    }

    return new RSAPublicKey(this.getType(), this.rsaKey, this.mgf1Salt);
  }

  clone(): SecretKey {
    if (!this.rsaKey) {
      return new RSASecretKey(this.getType());
    }
    
    // Clone RSA key
    const keyData = this.rsaKey.exportKey('pkcs1-private');
    const clonedKey = new NodeRSA();
    clonedKey.importKey(keyData, 'pkcs1-private');
    
    return new RSASecretKey(this.getType(), clonedKey);
  }

  /** PKCS#8 DER private key. Treat as secret material. */
  toBytes(): Uint8Array {
    if (!this.rsaKey) {
      return new Uint8Array(0);
    }
    return new Uint8Array(this.rsaKey.exportKey('pkcs8-private-der'));
  }

  /** Import from PKCS#8 DER private key bytes. */
  static fromBytes(type: VRFType, data: Uint8Array): RSASecretKey | null {
    if (!isRSAType(type) || data.length === 0) {
      return null;
    }
    try {
      const rsaKey = new NodeRSA();
      rsaKey.importKey(Buffer.from(data), 'pkcs8-private-der');
      rsaKey.setOptions({ encryptionScheme: 'pkcs1', signingScheme: 'pkcs1' });
      const sk = new RSASecretKey(type, rsaKey);
      return sk.isInitialized() ? sk : null;
    } catch {
      return null;
    }
  }

  private rsaFDHProve(input: Uint8Array, params: RSAVRFParams): Uint8Array {
    if (!this.rsaKey) {
      throw new Error('RSA key not initialized');
    }

    const tbs = constructRsaFdhTbs(params, this.mgf1Salt, input);
    const pem = this.rsaKey.exportKey('pkcs8-private-pem') as string;
    const signature = privateEncrypt(
      { key: pem, padding: constants.RSA_NO_PADDING },
      Buffer.from(tbs)
    );
    return new Uint8Array(signature);
  }

  private rsaPSSProve(input: Uint8Array, params: RSAVRFParams): Uint8Array {
    if (!this.rsaKey) {
      throw new Error('RSA key not initialized');
    }

    const tbs = constructRsaPssTbs(params, this.mgf1Salt, input);
    return rsaPssNoSaltSign(tbs, this.rsaKey, params.digest);
  }
}

/**
 * RSA VRF Public Key implementation
 */
export class RSAPublicKey extends PublicKey {
  private rsaKey: NodeRSA | undefined = undefined;
  private mgf1Salt: Uint8Array = new Uint8Array(0);

  constructor(type?: VRFType, rsaKey?: NodeRSA, mgf1Salt?: Uint8Array) {
    super();
    if (type) {
      this.setType(type);
    }
    if (rsaKey) {
      this.rsaKey = rsaKey;
      this.mgf1Salt = mgf1Salt ? new Uint8Array(mgf1Salt) : generateMgf1SaltFromRsaKey(rsaKey);
    } else if (mgf1Salt) {
      this.mgf1Salt = new Uint8Array(mgf1Salt);
    }
  }

  isInitialized(): boolean {
    return this.rsaKey !== undefined && 
           this.mgf1Salt.length > 0 && 
           isRSAType(this.getType());
  }

  verifyVRFProof(input: Uint8Array, proof: Proof): [boolean, Uint8Array] {
    if (!this.isInitialized() || !proof.isInitialized()) {
      return [false, new Uint8Array(0)];
    }

    if (proof.getType() !== this.getType()) {
      return [false, new Uint8Array(0)];
    }

    const params = getRSAVRFParams(this.getType());
    if (!params) {
      return [false, new Uint8Array(0)];
    }

    try {
      const proofBytes = proof.toBytes();
      let valid = false;

      if (isRSAFDHType(this.getType())) {
        valid = this.rsaFDHVerify(input, proofBytes, params);
      } else if (isRSAPSSType(this.getType())) {
        valid = this.rsaPSSVerify(input, proofBytes, params);
      }

      if (valid) {
        const vrfValue = proof.getVRFValue();
        return [true, vrfValue];
      }

      return [false, new Uint8Array(0)];
    } catch (error) {
      console.error('RSA VRF verification error:', error);
      return [false, new Uint8Array(0)];
    }
  }

  clone(): PublicKey {
    if (!this.rsaKey) {
      return new RSAPublicKey(this.getType());
    }
    
    const keyData = this.rsaKey.exportKey('pkcs8-public');
    const clonedKey = new NodeRSA();
    clonedKey.importKey(keyData, 'pkcs8-public');
    
    return new RSAPublicKey(this.getType(), clonedKey, this.mgf1Salt);
  }

  toBytes(): Uint8Array {
    if (!this.rsaKey) {
      return new Uint8Array(0);
    }
    
    // Export public key in SPKI DER format
    const exported = this.rsaKey.exportKey('pkcs8-public-der');
    return new Uint8Array(exported);
  }

  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isRSAType(type)) {
      return false;
    }

    const params = getRSAVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    try {
      const key = new NodeRSA();
      key.importKey(Buffer.from(data), 'pkcs8-public-der');
      
      this.rsaKey = key;
      this.setType(type);
      this.mgf1Salt = generateMgf1SaltFromRsaKey(key);
      
      return true;
    } catch {
      return false;
    }
  }

  private rsaFDHVerify(input: Uint8Array, proofBytes: Uint8Array, params: RSAVRFParams): boolean {
    try {
      if (!this.rsaKey) {
        return false;
      }

      const pem = this.rsaKey.exportKey('pkcs8-public-pem') as string;
      const verifiedBytes = publicDecrypt(
        { key: pem, padding: constants.RSA_NO_PADDING },
        Buffer.from(proofBytes)
      );
      const expectedTbs = constructRsaFdhTbs(params, this.mgf1Salt, input);
      return bytesEqual(new Uint8Array(verifiedBytes), expectedTbs);
    } catch {
      // Invalid proofs may be out of range for the modulus (OpenSSL RSA_NO_PADDING)
      return false;
    }
  }

  private rsaPSSVerify(input: Uint8Array, proofBytes: Uint8Array, params: RSAVRFParams): boolean {
    try {
      if (!this.rsaKey) {
        return false;
      }

      const tbs = constructRsaPssTbs(params, this.mgf1Salt, input);
      return rsaPssNoSaltVerify(proofBytes, tbs, this.rsaKey, params.digest);
    } catch (error) {
      console.error('RSA-PSS verify error:', error);
      return false;
    }
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
