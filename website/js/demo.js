const btn = document.getElementById('runBtn');
const resultsEl = document.getElementById('results');
const detailsHeading = document.getElementById('detailsHeading');
const runLogEl = document.getElementById('runLog');
const errorBox = document.getElementById('errorBox');
const steps = document.querySelectorAll('.step');

function hex(bytes, max = 48) {
  const h = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return h.length > max ? h.slice(0, max) + '…' : h;
}

function setStep(name, state) {
  const el = document.querySelector(`.step[data-step="${name}"]`);
  if (!el) return;
  el.classList.remove('active', 'done');
  if (state) el.classList.add(state);
}

function resetSteps() {
  steps.forEach((s) => s.classList.remove('active', 'done'));
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function clearRunLog() {
  runLogEl.innerHTML = '';
}

/** Terminal-style line + plain-English meaning (what you asked for). */
function logStep(line, meaning, extra) {
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML =
    `<div class="log-line">${line}</div>` +
    `<div class="log-meaning">${meaning}</div>` +
    (extra ? `<div class="log-extra mono">${extra}</div>` : '');
  runLogEl.appendChild(entry);
  entry.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.classList.remove('hidden');
  logStep('✗ Error', msg);
}

function hideError() {
  errorBox.classList.add('hidden');
}

btn.addEventListener('click', async () => {
  hideError();
  resultsEl.classList.add('hidden');
  if (detailsHeading) detailsHeading.classList.add('hidden');
  resetSteps();
  clearRunLog();
  btn.disabled = true;

  try {
    if (!globalThis.libvrf?.VRF) {
      throw new Error(
        'libvrf bundle not found. Build the site with: npm run website:build'
      );
    }

    const { VRF, VRFType } = libvrf;
    const type = VRFType.EC_VRF_P256_SHA256_TAI;
    const inputText = document.getElementById('input').value;
    const alpha = new TextEncoder().encode(inputText);

    logStep(
      `Input α = "${inputText}"`,
      '<strong>Input α</strong> — public challenge. Everyone must use the same bytes to verify. Not secret.',
      `${alpha.length} bytes · hex ${hex(alpha)}`
    );

    setText('out-alpha-len', `${alpha.length} bytes`);
    setText('out-alpha-hex', hex(alpha));

    setStep('sk', 'active');
    logStep(
      'Creating secret key…',
      '<strong>Secret key (SK)</strong> — private P-256 key. Only the prover holds this. Used in <code>getVRFProofAsync</code>.'
    );
    const sk = await VRF.createAsync(type);
    if (!sk?.isInitialized?.()) {
      throw new Error('Secret key (SK) failed to initialize');
    }
    const skBytes = sk.toBytes?.() ?? new Uint8Array(0);
    setText('out-sk-status', 'Generated (new key this run)');
    setText('out-sk-bytes', skBytes.length ? hex(skBytes, 64) : '(held inside library)');
    setStep('sk', 'done');

    setStep('pk', 'active');
    logStep(
      'Deriving public key…',
      '<strong>Public key (PK)</strong> — derived from SK. Safe to publish. Verifiers need PK, not SK.',
      skBytes.length ? `SK preview: ${hex(skBytes, 32)}` : undefined
    );
    const pk = await sk.getPublicKeyAsync();
    if (!pk?.isInitialized?.()) {
      throw new Error('Public key (PK) derivation failed');
    }
    const pkBytes = pk.toBytes();
    setText('out-pk-size', `${pkBytes.length} bytes (DER SPKI)`);
    setText('out-pk-hex', hex(pkBytes));
    setStep('pk', 'done');

    setStep('prove', 'active');
    logStep(
      'Proving…',
      '<strong>Proof π</strong> — computed with SK + α. Proves “I know a valid β for this input” without revealing SK.'
    );
    const t0 = performance.now();
    const proof = await sk.getVRFProofAsync(alpha);
    const proveMs = (performance.now() - t0).toFixed(1);
    if (!proof?.isInitialized?.()) {
      throw new Error('Proof π generation failed');
    }
    const proofBytes = proof.toBytes();
    setText('out-proof-size', `${proofBytes.length} bytes`);
    setText('out-prove-ms', `${proveMs} ms`);
    setText('out-proof-hex', hex(proofBytes));
    setStep('prove', 'done');

    setStep('verify', 'active');
    logStep(
      'Verifying…',
      '<strong>Verify</strong> — checks π against PK and α. No secret key needed. Returns success + VRF output β.'
    );
    const t1 = performance.now();
    const [ok, beta] = await pk.verifyVRFProofAsync(alpha, proof);
    const verifyMs = (performance.now() - t1).toFixed(1);
    if (!ok) {
      throw new Error('Verification failed — π does not match α under this PK');
    }
    setText('out-verify-ok', 'Yes — π is valid for this α');
    setText('out-verify-ms', `${verifyMs} ms`);
    setText('out-beta-hex', hex(beta, 128));
    setStep('verify', 'done');

    logStep(
      '✓ Proof verified',
      '<strong>Success</strong> — π is valid. The verifier accepts that β was produced correctly from α under PK.'
    );
    logStep(
      `Prove: ${proveMs} ms · Verify: ${verifyMs} ms`,
      '<strong>Timing</strong> — prove needs SK (slower crypto); verify only checks π (usually faster).'
    );
    logStep(
      `Proof size: ${proofBytes.length} bytes`,
      '<strong>Proof π (size)</strong> — wire bytes you would send to a verifier alongside α.'
    );
    logStep(
      `VRF value β: ${hex(beta, 64)}`,
      '<strong>VRF output β</strong> — deterministic pseudorandom hash for this (SK, α). Same inputs → same β. Use as seed / lottery / leader election.',
      `Full β (${beta.length} bytes): ${hex(beta, 128)}`
    );

    resultsEl.classList.remove('hidden');
    if (detailsHeading) detailsHeading.classList.remove('hidden');
  } catch (err) {
    showError(err?.message || String(err));
  } finally {
    btn.disabled = false;
  }
});
