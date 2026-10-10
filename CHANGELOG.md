# Changelog

All notable changes to this project are documented in this file.

## [1.2.1] - 2026-10-10

### Changed

- Dev dependencies within the current major: `@types/node` 20.19.43, `ts-jest` 29.4.14, `ts-loader` 9.6.2, `webpack` 5.111.1
- Left on the current major: ESLint 8, TypeScript 5, `typescript-eslint` 6, `webpack-cli` 5, `node-rsa` 1, `@types/jest` 29

## [1.2.0] - 2026-10-10

### Changed

- `bytesEqual` uses `crypto.timingSafeEqual` for equal-length buffers (length mismatch still returns immediately)

### Added

- Property tests (`fast-check`): serialize round-trips and tampered-proof rejection (EC and RSA-2048)
- Deserialization fuzz: `proofFromBytes` / `publicKeyFromBytes` return `null` or throw `VRFError` only

## [1.1.1] - 2026-07-21

### Added

- JSDoc on public APIs with `@throws`, `@param`/`@returns`, and byte-length expectations (closes #37)

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
