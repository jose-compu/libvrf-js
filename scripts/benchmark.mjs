#!/usr/bin/env node
/**
 * Quick VRF benchmark: prove + verify per type.
 * Usage: npm run benchmark
 */
import { VRF, VRFType } from '../dist/index.js';

const TYPES = [
  VRFType.RSA_FDH_VRF_RSA2048_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
  VRFType.EC_VRF_P256_SHA256_TAI,
];

const INPUT = new TextEncoder().encode('benchmark-input');
const ROUNDS = 5;

function ms(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

for (const type of TYPES) {
  const t0 = process.hrtime.bigint();
  const sk = VRF.create(type);
  const keygenMs = ms(t0);
  if (!sk) {
    console.log(`${type}: keygen FAILED`);
    continue;
  }
  const pk = sk.getPublicKey();

  let proveTotal = 0;
  let verifyTotal = 0;
  let proof;

  for (let i = 0; i < ROUNDS; i++) {
    const t1 = process.hrtime.bigint();
    proof = sk.getVRFProof(INPUT);
    proveTotal += ms(t1);

    const t2 = process.hrtime.bigint();
    pk.verifyVRFProof(INPUT, proof);
    verifyTotal += ms(t2);
  }

  console.log(
    `${type}: keygen=${keygenMs.toFixed(0)}ms prove=${(proveTotal / ROUNDS).toFixed(2)}ms verify=${(verifyTotal / ROUNDS).toFixed(2)}ms`
  );
}
