const btn = document.getElementById('runBtn');
const resultsEl = document.getElementById('results');
const detailsHeading = document.getElementById('detailsHeading');
const runLogEl = document.getElementById('runLog');
const errorBox = document.getElementById('errorBox');
const steps = document.querySelectorAll('.step');

function tr(key, vars = {}) {
  const full = `demoRun.${key}`;
  if (window.libvrfI18n?.t) return window.libvrfI18n.t(full, vars);
  return full;
}

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
  logStep(tr('error'), msg);
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
      throw new Error(tr('bundleMissing'));
    }

    const { VRF, VRFType } = libvrf;
    const type = VRFType.EC_VRF_P256_SHA256_TAI;
    const inputText = document.getElementById('input').value;
    const alpha = new TextEncoder().encode(inputText);

    logStep(
      tr('inputLine', { text: inputText }),
      tr('inputMean'),
      tr('bytesHex', { len: alpha.length, hex: hex(alpha) })
    );

    setText('out-alpha-len', `${alpha.length} bytes`);
    setText('out-alpha-hex', hex(alpha));

    setStep('sk', 'active');
    logStep(tr('creatingSk'), tr('creatingSkMean'));
    const sk = await VRF.createAsync(type);
    if (!sk?.isInitialized?.()) {
      throw new Error(tr('skFail'));
    }
    const skBytes = sk.toBytes?.() ?? new Uint8Array(0);
    setText('out-sk-status', tr('skStatus'));
    setText('out-sk-bytes', skBytes.length ? hex(skBytes, 64) : tr('skInternal'));
    setStep('sk', 'done');

    setStep('pk', 'active');
    logStep(
      tr('derivingPk'),
      tr('derivingPkMean'),
      skBytes.length ? tr('skPreview', { hex: hex(skBytes, 32) }) : undefined
    );
    const pk = await sk.getPublicKeyAsync();
    if (!pk?.isInitialized?.()) {
      throw new Error(tr('pkFail'));
    }
    const pkBytes = pk.toBytes();
    setText('out-pk-size', tr('pkSize', { len: pkBytes.length }));
    setText('out-pk-hex', hex(pkBytes));
    setStep('pk', 'done');

    setStep('prove', 'active');
    logStep(tr('proving'), tr('provingMean'));
    const t0 = performance.now();
    const proof = await sk.getVRFProofAsync(alpha);
    const proveMs = (performance.now() - t0).toFixed(1);
    if (!proof?.isInitialized?.()) {
      throw new Error(tr('proofFail'));
    }
    const proofBytes = proof.toBytes();
    setText('out-proof-size', tr('proofSize', { len: proofBytes.length }));
    setText('out-prove-ms', tr('proveMs', { ms: proveMs }));
    setText('out-proof-hex', hex(proofBytes));
    setStep('prove', 'done');

    setStep('verify', 'active');
    logStep(tr('verifying'), tr('verifyingMean'));
    const t1 = performance.now();
    const [ok, beta] = await pk.verifyVRFProofAsync(alpha, proof);
    const verifyMs = (performance.now() - t1).toFixed(1);
    if (!ok) {
      throw new Error(tr('verifyFail'));
    }
    setText('out-verify-ok', tr('verifyOk'));
    setText('out-verify-ms', tr('proveMs', { ms: verifyMs }));
    setText('out-beta-hex', hex(beta, 128));
    setStep('verify', 'done');

    logStep(tr('verified'), tr('verifiedMean'));
    logStep(
      tr('timingLine', { prove: proveMs, verify: verifyMs }),
      tr('timingMean')
    );
    logStep(
      tr('proofSizeLine', { len: proofBytes.length }),
      tr('proofSizeMean')
    );
    logStep(
      tr('betaLine', { hex: hex(beta, 64) }),
      tr('betaMean'),
      tr('betaFull', { len: beta.length, hex: hex(beta, 128) })
    );

    resultsEl.classList.remove('hidden');
    if (detailsHeading) detailsHeading.classList.remove('hidden');
  } catch (err) {
    showError(err?.message || String(err));
  } finally {
    btn.disabled = false;
  }
});
