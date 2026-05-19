// Licensed under the MIT license.
// RSA VRF primitives aligned with Microsoft libvrf / RFC 9381.

import NodeRSA from 'node-rsa';
import { sign, verify, constants } from 'crypto';
import { concatBytes, hash, i2osp } from '../utils';
import { RSAVRFParams } from './params';

/** Strip leading zero bytes (OpenSSL BN_num_bytes / I2OSP minimal length). */
export function normalizeModulusBytes(modulus: Buffer): Buffer {
  let start = 0;
  while (start < modulus.length - 1 && modulus[start] === 0) {
    start++;
  }
  return modulus.subarray(start);
}

/**
 * MGF1 salt = I2OSP(4, nLen) || I2OSP(n, nLen) per libvrf generate_mgf1_salt().
 */
export function generateMgf1SaltFromModulus(modulus: Buffer): Uint8Array {
  const n = normalizeModulusBytes(modulus);
  const nLen = n.length;
  const salt = new Uint8Array(4 + nLen);
  salt[0] = (nLen >> 24) & 0xff;
  salt[1] = (nLen >> 16) & 0xff;
  salt[2] = (nLen >> 8) & 0xff;
  salt[3] = nLen & 0xff;
  salt.set(n, 4);
  return salt;
}

export function generateMgf1SaltFromRsaKey(rsaKey: NodeRSA): Uint8Array {
  // node-rsa: "components" exports private material; public-only keys need "components-public"
  const components = (
    rsaKey.isPrivate()
      ? rsaKey.exportKey('components')
      : rsaKey.exportKey('components-public')
  ) as { n: Buffer };
  return generateMgf1SaltFromModulus(Buffer.from(components.n));
}

/** Standard MGF1 (RFC 8017): Hash(seed || I2OSP(counter, 4)). */
export function mgf1(seed: Uint8Array, maskLen: number, digest: string): Uint8Array {
  const hLen = hash(digest, new Uint8Array(0)).length;
  if (maskLen > 0xffffffff * hLen) {
    throw new Error('Mask too long');
  }

  const result = new Uint8Array(maskLen);
  let offset = 0;
  let counter = 0;

  while (offset < maskLen) {
    const counterBytes = i2osp(BigInt(counter), 4);
    const hashOutput = hash(digest, concatBytes(seed, counterBytes));
    const copyLen = Math.min(hashOutput.length, maskLen - offset);
    result.set(hashOutput.slice(0, copyLen), offset);
    offset += copyLen;
    counter++;
  }

  return result;
}

/**
 * RSA-FDH TBS: leading zero byte + MGF1(suite_string || 0x01 || mgf1_salt || data, nLen - 1).
 */
export function constructRsaFdhTbs(
  params: RSAVRFParams,
  mgf1Salt: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const suiteBytes = new TextEncoder().encode(params.suiteString);
  const seed = concatBytes(suiteBytes, new Uint8Array([0x01]), mgf1Salt, data);
  const nLen = params.bits / 8;
  const tbs = new Uint8Array(nLen);
  tbs.set(mgf1(seed, nLen - 1, params.digest), 1);
  return tbs;
}

/** RSA-PSS-NOSALT message: suite_string || 0x01 || mgf1_salt || data. */
export function constructRsaPssTbs(
  params: RSAVRFParams,
  mgf1Salt: Uint8Array,
  data: Uint8Array
): Uint8Array {
  const suiteBytes = new TextEncoder().encode(params.suiteString);
  return concatBytes(suiteBytes, new Uint8Array([0x01]), mgf1Salt, data);
}

/** proof_to_hash: Hash(suite_string || 0x02 || proof). */
export function rsaProofToHash(params: RSAVRFParams, proofBytes: Uint8Array): Uint8Array {
  const suiteBytes = new TextEncoder().encode(params.suiteString);
  return hash(params.digest, concatBytes(suiteBytes, new Uint8Array([0x02]), proofBytes));
}

export function rsaPssNoSaltSign(tbs: Uint8Array, rsaKey: NodeRSA, digest: string): Uint8Array {
  const pem = rsaKey.exportKey('pkcs8-private-pem') as string;
  const signature = sign(digest, Buffer.from(tbs), {
    key: pem,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 0,
  });
  return new Uint8Array(signature);
}

export function rsaPssNoSaltVerify(
  signature: Uint8Array,
  tbs: Uint8Array,
  rsaKey: NodeRSA,
  digest: string
): boolean {
  const pem = rsaKey.exportKey('pkcs8-public-pem') as string;
  return verify(
    digest,
    Buffer.from(tbs),
    {
      key: pem,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 0,
    },
    Buffer.from(signature)
  );
}
