// Licensed under the MIT license.

/**
 * libvrf - Verifiable Random Functions for Node.js and browsers
 * 
 * A Verifiable Random Function (VRF) is a cryptographic public-key primitive that,
 * from a secret key and a given input, produces a unique pseudorandom output,
 * along with a proof that the output was correctly computed.
 * 
 * RSA-FDH and RSA-PSS-NOSALT VRFs follow RFC 9381. EC VRF uses a simplified
 * construction and is not RFC 9381 compliant (see README).
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

