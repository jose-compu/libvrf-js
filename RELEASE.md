# Release Guide

## Release History

### v1.1.0 (2026-05-19)

**R1 — Trust & quality**

- RFC 9381 RSA-FDH/PSS aligned with Microsoft libvrf; cross-vector tests
- `VRFError`, `*OrThrow`, `isRFC9381Compliant()`, `getVRFSuiteInfo()`
- Secret-key serde, fast CI test matrix, browser smoke, coverage gate, Dependabot
- Honest docs: EC VRF is simplified and not RFC 9381 wire-compatible

**Breaking for RSA callers:** proofs and VRF values change (correctness fix vs prior releases).

### v1.0.5 (2024-12-XX)

**Node.js 18.x Compatibility Fixes**

- Fixed ESLint errors for Node.js 18.x compatibility:
  - Replaced `@ts-ignore` with `@ts-expect-error` in `src/ec/ecvrf.ts` (line 150)
  - Replaced `require('crypto')` with proper ES6 import statement (line 162)
  - Fixed `any` type warnings in `src/ec/ecdh-wrapper.ts` (lines 110, 173) with proper eslint-disable comments
  - Fixed `any` type warning in `src/ec/ecvrf.ts` (line 325) with proper eslint-disable comment
  - Added `@ts-expect-error` directive for unused private method `initializeSync` (line 152)

All tests passing (46 tests). Linting clean.

## Setup

### 1. NPM authentication (pick one or use both)

#### Option A — Trusted publishing (recommended)

Avoids expiring tokens. On npm:

1. Open https://www.npmjs.com/package/libvrf/access
2. **Publishing access** → **Add GitHub Actions trusted publisher**
3. Match the repo that runs `.github/workflows/publish.yml` (e.g. `jose-compu/libvrf-js`)
4. Workflow filename: `publish.yml`, environment: *(leave empty)*

The publish workflow requests OIDC (`id-token: write`) and runs `npm publish --provenance`.

#### Option B — `NPM_TOKEN` secret (fallback)

If publish fails with **`npm error code E404`** on `PUT`, npm usually means **not authenticated as the package owner** (expired/revoked token or read-only token).

1. Create a **Granular Access Token** at https://www.npmjs.com/settings/jose-blockchain/tokens  
   - Permissions: **Read and write** for package `libvrf` (or all packages)  
   - If 2FA is enabled: token type **Automation** (or enable bypass for publish)
2. Set the GitHub secret on the repo that runs releases:

```bash
gh secret set NPM_TOKEN --repo jose-compu/libvrf-js --body "npm_xxxxxxxx"
```

Verify locally:

```bash
npm whoami --registry https://registry.npmjs.org
# must print: jose-blockchain
```

### Publish from your Mac with `npm login` (no access tokens)

npm asks for OTP on **every** `npm publish` when you use **web login** (`auth-type=web`). Use **legacy login** instead.

**1. npm account — 2FA mode must be “Authorization only”**

- https://www.npmjs.com/settings/profile  
- Two-Factor Authentication → **Authorization only** (not “Authorization and publishing”)  
- Or CLI: `npm profile enable-2fa auth-only`

**2. Fresh login (legacy, not web)**

```bash
npm logout
npm login --auth-type=legacy
# OTP once here at login only
npm whoami   # jose-blockchain
```

**3. Publish**

```bash
cd libvrf-js
npm run build
npm test
npm publish --access public
```

No OTP at publish time if step 1–2 are correct. If you still get OTP, you are still on web auth — run `npm logout` and `npm login --auth-type=legacy` again (do not use browser login).

Check 2FA mode: `npm profile get` → `two-factor auth: auth-only`

## Creating a Release

### Option 1: Using GitHub CLI (Recommended)

```bash
# 1. Update version in package.json first
npm version patch  # or minor, major

# 2. Build and test
npm run build
npm test

# 3. Commit and push
git add .
git commit -m "Release v$(node -p "require('./package.json').version")"
git push origin main
git push --tags

# 4. Create GitHub release
gh release create v$(node -p "require('./package.json').version") \
  --title "v$(node -p "require('./package.json').version")" \
  --notes "Release v$(node -p "require('./package.json').version")"
```

The GitHub Actions workflow will automatically publish to NPM when the release is created.

### Option 2: Manual Release

1. Update version in `package.json`
2. Build and test: `npm run build && npm test`
3. Commit and push changes
4. Create tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
5. Push tag: `git push origin v1.0.0`
6. Create release on GitHub (web UI or CLI)
7. The workflow will automatically publish to NPM

## Workflow

### Publish failed with `E404` on `npm publish`

- npm returns **404** (not 403) when the token is missing, expired, or not allowed to publish `libvrf`.
- **Fix:** rotate `NPM_TOKEN` (Option B) and/or enable trusted publishing (Option A).
- If trusted publishing is enabled, an **expired** `NPM_TOKEN` can still break publish — update or remove that secret.

### Re-run publish for an existing release

```bash
gh workflow run publish.yml --repo jose-compu/libvrf-js
# or re-publish from Actions → Publish to NPM → Run workflow
# or delete the GitHub release tag and recreate after fixing auth
```

## Workflow

The `.github/workflows/publish.yml` workflow automatically:
- Triggers when a GitHub release is created
- Builds the project
- Runs tests
- Publishes to NPM (if tests pass)

