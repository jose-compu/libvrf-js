import { readFileSync } from 'fs';
import { privateEncrypt, publicDecrypt, constants } from 'crypto';
import { VRF, VRFType } from '../dist/index.js';
import { constructRsaFdhTbs, generateMgf1SaltFromRsaKey } from '../dist/rsa/rfc9381.js';
import { getRSAVRFParams } from '../dist/rsa/params.js';
import { createNodeRsaFromPrimes } from '../dist/rsa/key-import.js';

function hex(h) {
  const n = h.length % 2 ? `0${h}` : h;
  return new Uint8Array(Buffer.from(n, 'hex'));
}

const v = JSON.parse(readFileSync('./tests/fixtures/rsa-rfc9381-vectors.json', 'utf8'))[0];
const type = VRFType.RSA_FDH_VRF_RSA2048_SHA256;
const params = getRSAVRFParams(type);
const key = createNodeRsaFromPrimes(hex(v.p), hex(v.q));
const mgf1Salt = generateMgf1SaltFromRsaKey(key);
const alpha = hex(v.alpha);
const tbs = constructRsaFdhTbs(params, mgf1Salt, alpha);
const privPem = key.exportKey('pkcs8-private-pem');
const pubPem = key.exportKey('pkcs8-public-pem');

const sigOpenSSL = privateEncrypt(
  { key: privPem, padding: constants.RSA_NO_PADDING },
  Buffer.from(tbs)
);

const expected = hex(v.proof);
console.log('openssl sig == expected', Buffer.compare(sigOpenSSL, Buffer.from(expected)) === 0);

const sk = VRF.createRsaFromPrimes(type, hex(v.p), hex(v.q));
const ourProof = sk.getVRFProof(alpha).toBytes();
console.log('our proof == expected', Buffer.compare(Buffer.from(ourProof), Buffer.from(expected)) === 0);
console.log('our proof == openssl', Buffer.compare(Buffer.from(ourProof), sigOpenSSL) === 0);

const recovered = publicDecrypt(
  { key: pubPem, padding: constants.RSA_NO_PADDING },
  Buffer.from(expected)
);
console.log('expected proof decrypts to tbs', Buffer.compare(recovered, Buffer.from(tbs)) === 0);
console.log('tbs head', Buffer.from(tbs).toString('hex').slice(0, 64));
console.log('rec head', recovered.toString('hex').slice(0, 64));
const comps = key.exportKey('components');
console.log('n bytes', comps.n.length, 'p', comps.p.length, 'q', comps.q.length);
