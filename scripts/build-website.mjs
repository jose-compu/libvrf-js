#!/usr/bin/env node
/**
 * Copy browser bundle into website/assets for GitHub Pages.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = path.join(root, 'dist', 'browser', 'libvrf.min.js');
const destDir = path.join(root, 'website', 'assets');
const dest = path.join(destDir, 'libvrf.min.js');

if (!fs.existsSync(src)) {
  console.error('Missing dist/browser/libvrf.min.js — run: npm run build:browser');
  process.exit(1);
}

fs.mkdirSync(destDir, { recursive: true });
fs.copyFileSync(src, dest);
console.log('website: copied', path.relative(root, src), '→', path.relative(root, dest));
