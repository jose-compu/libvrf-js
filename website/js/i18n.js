/**
 * Browser locale for libvrf-js static site (en, fr, es, ja).
 */
(function () {
  const SUPPORTED = ['en', 'fr', 'es', 'ja'];
  const STORAGE_KEY = 'libvrf-lang';

  let strings = {};
  let fallback = {};

  function get(obj, path) {
    return path.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), obj);
  }

  function t(key, vars = {}) {
    let s = get(strings, key) ?? get(fallback, key) ?? key;
    if (typeof s !== 'string') return key;
    for (const [k, v] of Object.entries(vars)) {
      s = s.replace(new RegExp(`\\{\\{${k}\\}\\}`, 'g'), String(v));
    }
    return s;
  }

  function resolveLocale() {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && SUPPORTED.includes(saved)) return saved;
    const langs = navigator.languages?.length
      ? navigator.languages
      : [navigator.language || 'en'];
    for (const raw of langs) {
      const code = raw.split('-')[0].toLowerCase();
      if (SUPPORTED.includes(code)) return code;
    }
    return 'en';
  }

  async function loadLocale(code) {
    const res = await fetch(`locales/${code}.json`);
    if (!res.ok) throw new Error(`locale ${code}`);
    return res.json();
  }

  function apply(root = document) {
    root.querySelectorAll('[data-i18n]').forEach((el) => {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val !== key) el.textContent = val;
    });

    root.querySelectorAll('[data-i18n-html]').forEach((el) => {
      const key = el.getAttribute('data-i18n-html');
      const val = t(key);
      if (val !== key) el.innerHTML = val;
    });

    root.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = t(key);
      if (val !== key) el.placeholder = val;
    });

    root.querySelectorAll('[data-i18n-title]').forEach((el) => {
      const key = el.getAttribute('data-i18n-title');
      const val = t(key);
      if (val !== key) el.title = val;
    });

    const metaDesc = document.querySelector('meta[name="description"]');
    const desc = t('meta.description');
    if (metaDesc && desc !== 'meta.description') metaDesc.setAttribute('content', desc);

    const page = document.documentElement.getAttribute('data-page');
    document.title = t(page === 'demo' ? 'demo.metaTitle' : 'meta.title');
    document.documentElement.lang = currentLocale;

    const langSel = document.getElementById('langSelect');
    if (langSel) langSel.setAttribute('aria-label', t('lang.label'));
  }

  let currentLocale = 'en';

  async function setLocale(code, { persist = true } = {}) {
    if (!SUPPORTED.includes(code)) code = 'en';
    currentLocale = code;
    if (persist) localStorage.setItem(STORAGE_KEY, code);
    if (!fallback || !Object.keys(fallback).length) {
      fallback = await loadLocale('en');
    }
    strings = code === 'en' ? fallback : await loadLocale(code);
    apply();
    const sel = document.getElementById('langSelect');
    if (sel) {
      sel.value = code;
      sel.setAttribute('aria-label', t('lang.label'));
    }
    document.dispatchEvent(new CustomEvent('libvrf:locale', { detail: { locale: code } }));
  }

  async function init() {
    document.documentElement.classList.add('i18n-pending');
    currentLocale = resolveLocale();
    fallback = await loadLocale('en');
    strings = currentLocale === 'en' ? fallback : await loadLocale(currentLocale).catch(() => fallback);
    if (currentLocale !== 'en' && strings === fallback) currentLocale = 'en';

    apply();

    const sel = document.getElementById('langSelect');
    if (sel) {
      sel.value = currentLocale;
      sel.addEventListener('change', () => setLocale(sel.value));
    }

    document.documentElement.classList.remove('i18n-pending');
    document.documentElement.classList.add('i18n-ready');
  }

  window.libvrfI18n = { t, setLocale, getLocale: () => currentLocale, init };
  document.addEventListener('DOMContentLoaded', () => init().catch(console.error));
})();
