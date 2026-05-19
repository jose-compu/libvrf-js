#!/usr/bin/env bash
# Create GitHub issues from ROADMAP.md. Run from repo root: ./scripts/create-roadmap-issues.sh
set -euo pipefail

create_issue() {
  local id="$1"
  local title="$2"
  local body="$3"
  shift 3
  local labels=("$@")
  local label_args=()
  for l in "${labels[@]}"; do
    label_args+=(--label "$l")
  done
  echo "Creating $id ..."
  gh issue create --title "${id}: ${title}" --body "$body" "${label_args[@]}"
}

# R1 — v1.1.x
create_issue "R1-01" "Align package.json and README with RFC compliance reality" \
  "EC VRF in this port is not RFC 9381 compliant. Update \`package.json\` description, README limitations, and badges so callers are not misled.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p0 docs breaking enhancement

create_issue "R1-02" "Export isRFC9381Compliant() and getVRFSuiteInfo()" \
  "Add public helpers so integrators can branch on RFC 9381 compliance, browser support, and C++ libvrf interoperability per VRF type.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p1 api interop enhancement

create_issue "R1-03" "VRFError and *OrThrow APIs" \
  "Replace silent \`null\` returns with typed \`VRFError\` (codes: invalid type, deserialization failed, key generation failed, etc.). Keep legacy null-return methods for compatibility; add \`createOrThrow\`, \`proofFromBytesOrThrow\`, etc.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p1 api dx enhancement

create_issue "R1-04" "Fast default test matrix; optional full matrix script" \
  "Default \`npm test\` should use a fast representative sample (2048 RSA + EC). Add \`npm run test:full\` for all VRF types without blocking CI on slow 4096-bit keygen.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p1 test infra enhancement

create_issue "R1-05" "RFC 9381 RSA-FDH cross-vector tests" \
  "Commit fixtures from Microsoft libvrf / RFC 9381 Appendix A. Verify prove + verify + beta for RSA-FDH suites using keys from primes.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p1 test interop enhancement

create_issue "R1-06" "Browser CI: build bundle + smoke test" \
  "CI job: \`npm run build:browser\` then \`npm run test:browser-smoke\` (EC VRF via WebCrypto mock).

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p1 test browser infra enhancement

create_issue "R1-07" "Coverage gate in CI" \
  "Enforce Jest coverage thresholds on \`src/\` in CI.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p2 test infra enhancement

create_issue "R1-08" "Dependabot and npm audit workflow" \
  "Add Dependabot config and document supported Node LTS versions.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p2 infra security deps enhancement

create_issue "R1-09" "CHANGELOG.md for releases" \
  "Add CHANGELOG.md and link from release notes.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p2 docs infra enhancement

create_issue "R1-10" "Secret key import/export API" \
  "Add \`secretKeyFromBytes\` / \`toBytes\` with clear security documentation.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p2 api security enhancement

create_issue "R1-11" "Document async EC API and browser foot-guns" \
  "Document when sync EC paths are unsafe in browser; align README with async-only browser usage.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p2 api browser docs enhancement

create_issue "R1-12" "VRF benchmark script" \
  "Add script to measure keygen / prove / verify ops per VRF type for regression tracking.

Ref: [ROADMAP.md](ROADMAP.md#r1--v11x-trust--quality)" \
  roadmap-r1 priority-p3 perf infra enhancement

# R2 — v1.2.x
create_issue "R2-01" "Full RFC 9381 ECVRF-P256-SHA256-TAI" \
  "Replace simplified EC construction with full RFC 9381 ECVRF. Breaking change for EC wire format.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p0 crypto interop breaking enhancement

create_issue "R2-02" "RFC 9381 EC official test vectors" \
  "Add EC test vectors from RFC 9381 / C++ libvrf in \`tests/fixtures/\`.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p0 test interop enhancement

create_issue "R2-03" "EC proof wire format compatible with C++ libvrf" \
  "Align EC proof serialization with Microsoft libvrf and other RFC 9381 implementations.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p0 interop breaking enhancement

create_issue "R2-04" "Migration guide for EC VRF breaking change" \
  "Document migration from v1 simplified EC proofs to RFC-compliant v2.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p1 docs breaking enhancement

create_issue "R2-05" "Optional EC_VRF_P256_SHA256_TAI_LEGACY type" \
  "Preserve legacy EC behavior behind explicit legacy VRF type alias.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p2 api interop enhancement

create_issue "R2-06" "Constant-time comparison audit" \
  "Audit \`bytesEqual\` and bigint code paths for side-channel resistance.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p1 security crypto enhancement

create_issue "R2-07" "Property-based tests (fast-check)" \
  "Round-trip serialize, verify rejects tampered proofs.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p2 test enhancement

create_issue "R2-08" "Fuzz proofFromBytes and publicKeyFromBytes" \
  "Add fuzz targets in CI or cron.

Ref: [ROADMAP.md](ROADMAP.md#r2--v12x-compliance--interop)" \
  roadmap-r2 priority-p2 test security enhancement

# R3 — v2.0.x
create_issue "R3-01" "Additional EC suites (P-384, P-521)" \
  "Implement RFC 9381 EC ciphersuites beyond P-256.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p1 crypto interop enhancement

create_issue "R3-02" "Browser RSA VRF or document Node-only" \
  "Either implement RSA VRF in browser via WebCrypto or document permanent Node-only stance.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p2 browser crypto enhancement

create_issue "R3-03" "Tree-shakeable ESM entry points" \
  "Per-algorithm exports: \`libvrf/ec\`, \`libvrf/rsa\`.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p1 perf api enhancement

create_issue "R3-04" "Reduce browser bundle size" \
  "Analyze webpack bundle; externalize where possible.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p2 perf browser enhancement

create_issue "R3-05" "Deno and Bun CI compatibility" \
  "Add compatibility tests to CI matrix.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p2 infra test enhancement

create_issue "R3-06" "Dual-package exports cleanup" \
  "Clean \`exports\` conditions for import/require/types.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p2 infra dx enhancement

create_issue "R3-07" "Replace node-rsa with native crypto where possible" \
  "Reduce dependency on node-rsa for RSA operations.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p2 deps security enhancement

create_issue "R3-08" "Streaming / large-input VRF API" \
  "Support chunked hashing for large VRF inputs.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p3 api perf enhancement

create_issue "R3-09" "Hardware key support hooks" \
  "Document or hook WebCrypto non-extractable keys / PKCS#11 patterns.

Ref: [ROADMAP.md](ROADMAP.md#r3--v20x-platform-expansion)" \
  roadmap-r3 priority-p3 api security enhancement

# R4 — v3.x+
create_issue "R4-01" "Optional WASM build (C++ libvrf)" \
  "WASM wrapper for guaranteed interop and performance.

Ref: [ROADMAP.md](ROADMAP.md#r4--v3x-ecosystem)" \
  roadmap-r4 priority-p2 interop perf deps enhancement

create_issue "R4-02" "CLI prove/verify tool" \
  "Command-line debugging utility.

Ref: [ROADMAP.md](ROADMAP.md#r4--v3x-ecosystem)" \
  roadmap-r4 priority-p3 dx enhancement

create_issue "R4-03" "JSON/CBOR encoding helpers" \
  "Canonical encoding for proofs and keys.

Ref: [ROADMAP.md](ROADMAP.md#r4--v3x-ecosystem)" \
  roadmap-r4 priority-p3 api interop enhancement

create_issue "R4-04" "Third-party security audit" \
  "Published security review.

Ref: [ROADMAP.md](ROADMAP.md#r4--v3x-ecosystem)" \
  roadmap-r4 priority-p2 security docs enhancement

create_issue "R4-05" "Integration examples (Chainlink, etc.)" \
  "Research and document integration patterns.

Ref: [ROADMAP.md](ROADMAP.md#r4--v3x-ecosystem)" \
  roadmap-r4 priority-p3 docs enhancement

create_issue "R4-06" "Monorepo split (@libvrf/core)" \
  "Split core vs node vs browser packages.

Ref: [ROADMAP.md](ROADMAP.md#r4--v3x-ecosystem)" \
  roadmap-r4 priority-p3 infra breaking enhancement

# Backlog
create_issue "B-01" "TypeScript strict mode in EC path" \
  "Eliminate remaining @ts-expect-error in EC VRF.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog dx crypto enhancement

create_issue "B-02" "JSDoc on all public APIs" \
  "Add @throws and byte-length expectations.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog docs dx enhancement

create_issue "B-03" "GitHub issue templates" \
  "Add bug, feature, and security issue templates.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog infra enhancement

create_issue "B-04" "SBOM on publish" \
  "CycloneDX SBOM in release pipeline.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog security infra enhancement

create_issue "B-05" "SRI hashes for CDN builds" \
  "Document Subresource Integrity for browser bundle in README.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog browser docs enhancement

create_issue "B-06" "Ed25519 / X25519 VRF research" \
  "Track IETF drafts; not in RFC 9381 today.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog crypto enhancement

create_issue "B-07" "Web Workers batch verify example" \
  "Browser example for parallel verify.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog browser docs enhancement

create_issue "B-08" "OpenSSF Scorecard" \
  "Adopt OpenSSF best practices badge.

Ref: [ROADMAP.md](ROADMAP.md#backlog-unscheduled)" \
  backlog security infra enhancement

echo "Done."
