// Licensed under the MIT license.

import NodeRSA from 'node-rsa';

function modInverse(a: bigint, m: bigint): bigint {
  let oldR = a;
  let r = m;
  let oldS = 1n;
  let s = 0n;

  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }

  if (oldR !== 1n) {
    throw new Error('Value is not invertible modulo m');
  }

  return ((oldS % m) + m) % m;
}

function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

function bigintToBuffer(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Build a NodeRSA private key from RSA prime factors (RFC 9381 test vectors).
 */
export function createNodeRsaFromPrimes(p: Uint8Array, q: Uint8Array): NodeRSA {
  const pBig = BigInt(`0x${Buffer.from(p).toString('hex')}`);
  const qBig = BigInt(`0x${Buffer.from(q).toString('hex')}`);
  const e = 65537n;
  const n = pBig * qBig;
  const pMinus1 = pBig - 1n;
  const qMinus1 = qBig - 1n;
  const g = gcd(pMinus1, qMinus1);
  const lcm = (pMinus1 / g) * qMinus1;
  const d = modInverse(e, lcm);
  const dmp1 = d % pMinus1;
  const dmq1 = d % qMinus1;
  const coeff = modInverse(qBig, pBig);

  const key = new NodeRSA();
  key.importKey(
    {
      n: bigintToBuffer(n),
      e: bigintToBuffer(e),
      d: bigintToBuffer(d),
      p: Buffer.from(p),
      q: Buffer.from(q),
      dmp1: bigintToBuffer(dmp1),
      dmq1: bigintToBuffer(dmq1),
      coeff: bigintToBuffer(coeff),
    },
    'components'
  );
  key.setOptions({
    encryptionScheme: 'pkcs1',
    signingScheme: 'pkcs1',
  });
  return key;
}
