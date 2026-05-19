#!/usr/bin/env node
/**
 * Smoke-test the browser UMD bundle with a mocked window + WebCrypto (Node crypto.webcrypto).
 */
import fs from 'fs';
import path from 'path';
import vm from 'vm';
import { webcrypto } from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const bundlePath = path.join(__dirname, '..', 'dist', 'browser', 'libvrf.min.js');

if (!fs.existsSync(bundlePath)) {
  console.error('Missing browser bundle. Run: npm run build:browser');
  process.exit(1);
}

const code = fs.readFileSync(bundlePath, 'utf8');
const sandbox = {
  window: { crypto: webcrypto },
  crypto: webcrypto,
  self: {},
  console,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  ArrayBuffer,
  atob: globalThis.atob,
  btoa: globalThis.btoa,
  Buffer: undefined,
};

sandbox.globalThis = sandbox;
sandbox.self = sandbox;

vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: bundlePath });
const libvrf = sandbox.libvrf;

if (!libvrf?.VRF) {
  console.error('libvrf global not found after loading bundle');
  process.exit(1);
}

const run = async () => {
  const type = libvrf.VRFType.EC_VRF_P256_SHA256_TAI;
  const sk = await libvrf.VRF.createAsync(type);
  if (!sk?.isInitialized?.()) {
    throw new Error('createAsync did not return initialized secret key');
  }

  const pk = await sk.getPublicKeyAsync();
  const input = new TextEncoder().encode('browser-ci-smoke');
  const proof = await sk.getVRFProofAsync(input);
  const [ok, value] = await pk.verifyVRFProofAsync(input, proof);

  if (!ok || !value?.length) {
    throw new Error('verifyVRFProofAsync failed');
  }

  console.log('browser-smoke: OK');
  console.log('vrf-value-bytes:', value.length);
};

run().catch((err) => {
  console.error('browser-smoke: FAILED', err);
  process.exit(1);
});
