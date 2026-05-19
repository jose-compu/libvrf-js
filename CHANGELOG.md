# Changelog

All notable changes to this project are documented in this file.

## [1.1.0] - 2026-05-19

### Added

- `isRFC9381Compliant()` and `getVRFSuiteInfo()` for suite metadata
- `VRFError`, `VRFErrorCode`, and `*OrThrow` APIs on `VRF`
- RFC 9381 RSA-FDH cross-vector tests (Microsoft libvrf fixtures)
- `VRF.createRsaFromPrimes()` for test vectors and trusted key import
- `VRF.secretKeyToBytes()` / `VRF.secretKeyFromBytes()` (treat output as secret)
- Browser CI smoke test (`npm run test:browser-smoke`)
- `npm run test:full` for slow RSA 3072/4096 matrix
- `npm run benchmark` for prove/verify timing
- Dependabot configuration

### Fixed

- RSA-FDH/PSS aligned with Microsoft libvrf (suite strings, MGF1 salt, RFC 9381 TBS)
- RSA public key import (`components-public` for MGF1 salt)
- Honest README and package description (EC VRF not RFC 9381 interoperable)

### Changed

- Default `npm test` uses a fast matrix (2048 RSA + EC); full matrix is optional
