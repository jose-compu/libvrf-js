// Licensed under the MIT license.

/**
 * libvrf — Verifiable Random Functions for Node.js and browsers.
 *
 * A VRF maps a secret key and public input α to a unique pseudorandom output β
 * and a proof π. Only the key holder produces π; anyone with the public key verifies it.
 *
 * RSA-FDH and RSA-PSS-NOSALT follow RFC 9381. EC VRF uses a simplified
 * construction and is not RFC 9381 compliant (see README).
 *
 * @packageDocumentation
 */

// Export main VRF class
export { VRF } from './vrf';

export { VRFError, VRFErrorCode } from './errors';
export { isRFC9381Compliant, getVRFSuiteInfo } from './compliance';
export type { VRFSuiteInfo } from './compliance';

// Export base classes and interfaces
export { 
  VRFObject, 
  Clonable, 
  Serializable, 
  Proof, 
  PublicKey, 
  SecretKey 
} from './base';

// Export types
export { 
  VRFType, 
  isRSAType, 
  isECType, 
  isRSAFDHType, 
  isRSAPSSType,
  vrfTypeToString 
} from './types';

// Export EC VRF classes
export { ECProof, ECSecretKey, ECPublicKey } from './ec/ecvrf';
export { getECVRFParams } from './ec/params';

// Export RSA VRF classes
export { RSAProof, RSASecretKey, RSAPublicKey } from './rsa/rsavrf';
export { getRSAVRFParams } from './rsa/params';

// Export utilities
export { 
  hexToBytes, 
  bytesToHex, 
  concatBytes, 
  bytesEqual 
} from './utils';

