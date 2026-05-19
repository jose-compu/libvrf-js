// Licensed under the MIT license.

import { VRFType, isRFC9381Compliant, getVRFSuiteInfo } from '../src';

describe('VRF compliance metadata', () => {
  test('RSA suites are RFC 9381 compliant', () => {
    expect(isRFC9381Compliant(VRFType.RSA_FDH_VRF_RSA2048_SHA256)).toBe(true);
    expect(isRFC9381Compliant(VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256)).toBe(true);
  });

  test('EC suite is not RFC 9381 compliant in this port', () => {
    expect(isRFC9381Compliant(VRFType.EC_VRF_P256_SHA256_TAI)).toBe(false);
  });

  test('UNKNOWN has no suite info', () => {
    expect(getVRFSuiteInfo(VRFType.UNKNOWN)).toBeNull();
  });

  test('EC suite info marks browser support and no C++ interop', () => {
    const info = getVRFSuiteInfo(VRFType.EC_VRF_P256_SHA256_TAI);
    expect(info).toEqual({
      type: VRFType.EC_VRF_P256_SHA256_TAI,
      rfc9381Compliant: false,
      browserSupported: true,
      interoperableWithLibvrfCpp: false,
    });
  });

  test('RSA suite info marks C++ interop', () => {
    const info = getVRFSuiteInfo(VRFType.RSA_FDH_VRF_RSA2048_SHA256);
    expect(info?.interoperableWithLibvrfCpp).toBe(true);
    expect(info?.browserSupported).toBe(false);
  });
});
