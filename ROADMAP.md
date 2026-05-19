# libvrf-js Roadmap

Brainstorm backlog for improvements and features. Each item has **category tags** and a **roadmap phase**.

## Tag legend

| Tag | Meaning |
|-----|---------|
| `crypto` | Cryptographic correctness / algorithms |
| `interop` | RFC 9381 / C++ libvrf / cross-implementation compatibility |
| `browser` | WebCrypto, CDN, browser bundle |
| `api` | Public API shape and ergonomics |
| `dx` | Developer experience (errors, types, tooling) |
| `test` | Tests, vectors, fuzzing |
| `perf` | Performance and bundle size |
| `security` | Hardening, audits, side channels |
| `infra` | CI/CD, releases, packaging |
| `docs` | Documentation and examples |
| `deps` | Dependencies and supply chain |
| `breaking` | Likely semver-major change |

## Roadmap phases

| Phase | Target | Theme |
|-------|--------|--------|
| **R1** | v1.1.x | Trust & quality — honest docs, broader tests, CI hardening |
| **R2** | v1.2.x | Compliance — RFC 9381 EC VRF, standard test vectors |
| **R3** | v2.0.x | Platform — browser parity, more suites, modern packaging |
| **R4** | v3.x+ | Ecosystem — WASM, interop tooling, optional extensions |

---

## R1 — v1.1.x (Trust & quality)

| ID | Item | Tags | Priority |
|----|------|------|----------|
| R1-01 | Align `package.json` / README description with reality (EC VRF is **not** RFC 9381 compliant today) | `docs`, `breaking` | P0 |
| R1-02 | Export explicit `isRFC9381Compliant(type)` (or suite metadata) so callers can branch safely | `api`, `interop` | P1 |
| R1-03 | Replace silent `null` returns with typed errors (`VRFError` + codes: invalid type, bad bytes, not initialized) | `api`, `dx` | P1 |
| R1-04 | Run full test matrix for **all** `VRFType` values in CI (not only representative sample) | `test`, `infra` | P1 |
| R1-05 | Add cross-check tests vs C++ libvrf for RSA-FDH / RSA-PSS (generate vectors once, commit fixtures) | `test`, `interop` | P1 |
| R1-06 | Browser CI job: build bundle + headless smoke test (`examples/browser.html` or Playwright) | `test`, `browser`, `infra` | P1 |
| R1-07 | Coverage gate in CI (threshold on `src/`, exclude generated `dist/`) | `test`, `infra` | P2 |
| R1-08 | Dependabot / npm audit workflow; document supported Node LTS window | `infra`, `security`, `deps` | P2 |
| R1-09 | `CHANGELOG.md` linked from releases (auto from conventional commits optional) | `docs`, `infra` | P2 |
| R1-10 | Secret-key import/export API (`secretKeyFromBytes` / `toBytes`) with clear security warnings | `api`, `security` | P2 |
| R1-11 | Consistent async surface: document when sync EC paths return empty in browser; deprecate foot-guns | `api`, `browser`, `docs` | P2 |
| R1-12 | Benchmark script (ops/s per type, keygen vs prove vs verify) for regression tracking | `perf`, `infra` | P3 |

---

## R2 — v1.2.x (Compliance & interop)

| ID | Item | Tags | Priority |
|----|------|------|----------|
| R2-01 | **Full RFC 9381 ECVRF-P256-SHA256-TAI** (replace simplified construction) | `crypto`, `interop`, `breaking` | P0 |
| R2-02 | RFC 9381 official test vectors in `tests/fixtures/` (prove + verify + negative cases) | `test`, `interop` | P0 |
| R2-03 | Proof wire format compatible with C++ libvrf and other RFC implementations | `interop`, `breaking` | P0 |
| R2-04 | Migration guide: v1 EC proofs → v2 (breaking change communication) | `docs`, `breaking` | P1 |
| R2-05 | Optional `VRFType` alias preserving legacy EC behavior behind `EC_VRF_P256_SHA256_TAI_LEGACY` | `api`, `interop` | P2 |
| R2-06 | Constant-time comparisons audit (`bytesEqual`, bigint paths) | `security`, `crypto` | P1 |
| R2-07 | Property-based tests (e.g. fast-check): round-trip serialize, verify rejects tampered proofs | `test` | P2 |
| R2-08 | Fuzz targets for `proofFromBytes` / `publicKeyFromBytes` (jsfuzz or CI cron) | `test`, `security` | P2 |

---

## R3 — v2.0.x (Platform expansion)

| ID | Item | Tags | Priority |
|----|------|------|----------|
| R3-01 | Additional EC suites: P-384, P-521 (RFC 9381 ciphersuites) | `crypto`, `interop` | P1 |
| R3-02 | Browser RSA VRF via WebCrypto (or document permanent Node-only stance) | `browser`, `crypto` | P2 |
| R3-03 | Tree-shakeable ESM: per-algorithm entry points (`libvrf/ec`, `libvrf/rsa`) | `perf`, `api` | P1 |
| R3-04 | Reduce browser bundle size (externalize crypto, analyze webpack stats) | `perf`, `browser` | P2 |
| R3-05 | `deno` / `bun` compatibility tests in CI matrix | `infra`, `test` | P2 |
| R3-06 | Dual-package exports cleanup (`exports` conditions, `import`/`require` types) | `infra`, `dx` | P2 |
| R3-07 | Replace or wrap `node-rsa` with native `crypto` RSA where possible | `deps`, `security` | P2 |
| R3-08 | Streaming / large-input API (chunked hash for VRF input domain) | `api`, `perf` | P3 |
| R3-09 | Hardware key support hooks (WebCrypto non-extractable keys, PKCS#11 doc only) | `api`, `security` | P3 |

---

## R4 — v3.x+ (Ecosystem)

| ID | Item | Tags | Priority |
|----|------|------|----------|
| R4-01 | Optional WASM build wrapping C++ libvrf for guaranteed interop + performance | `interop`, `perf`, `deps` | P2 |
| R4-02 | CLI: `libvrf prove/verify` for debugging and ops | `dx` | P3 |
| R4-03 | JSON/CBOR canonical encoding helpers for proofs and keys | `api`, `interop` | P3 |
| R4-04 | Published security audit / third-party review badge | `security`, `docs` | P2 |
| R4-05 | Integration examples: Chainlink VRF patterns, Solana/ed25519 VRF research (if in scope) | `docs` | P3 |
| R4-06 | `@libvrf/core` + thin platform packages (`node`, `browser`) monorepo split | `infra`, `breaking` | P3 |

---

## Backlog (unscheduled)

| ID | Item | Tags |
|----|------|------|
| B-01 | TypeScript strict mode + eliminate remaining `@ts-expect-error` in EC path | `dx`, `crypto` |
| B-02 | JSDoc on all public methods with `@throws` and byte-length expectations | `docs`, `dx` |
| B-03 | GitHub issue templates (bug, feature, security) | `infra` |
| B-04 | SBOM on publish (CycloneDX) | `security`, `infra` |
| B-05 | Subresource Integrity (SRI) hashes for CDN builds in README | `browser`, `docs` |
| B-06 | Ed25519 / X25519 VRF research (not in RFC 9381 today; track IETF drafts) | `crypto` |
| B-07 | Web Workers example for batch verify | `browser`, `docs` |
| B-08 | OpenSSF Scorecard badge + best practices | `security`, `infra` |

---

## Suggested execution order (next 3 releases)

1. **v1.1.0** — R1-01, R1-03, R1-04, R1-05, R1-06 (quality + honesty, no crypto break)
2. **v1.2.0** — R2-01, R2-02, R2-03, R2-04 (RFC compliance; **major** if EC wire format changes)
3. **v2.0.0** — R3-01, R3-03, R3-06 (new suites + packaging; coordinate with R2 breaking changes if combined)

---

## How to use this doc

- Pick items by phase when planning milestones.
- Open GitHub issues with labels matching tags (`crypto`, `interop`, etc.).
- Mark done items with PR link in a short “Completed” section below when shipped.

### Completed

_(none yet — move items here with version and PR link when merged)_
