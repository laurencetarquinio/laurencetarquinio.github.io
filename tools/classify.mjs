// Seals every essay behind the classified lock.
//
// Plaintext sources live in posts-src/ (gitignored, never pushed). For each
// one, the subtitle and body are encrypted with AES-256-GCM under a key
// derived from the clearance code (PBKDF2-SHA256), and the sealed page is
// written to posts/. Titles, dates and read times stay public.
//
//   CLASSIFIED_PASSWORD='...' node tools/classify.mjs

import { readdir, readFile, writeFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'posts-src');
const OUT = path.join(ROOT, 'posts');
const ITERATIONS = 310000;

// Same normalization as classified.js: case and surrounding spaces don't matter.
const code = (process.env.CLASSIFIED_PASSWORD || '').trim().toUpperCase();
if (!code) {
  console.error('Set CLASSIFIED_PASSWORD to the clearance code.');
  process.exit(1);
}

const subtle = webcrypto.subtle;
const enc = new TextEncoder();
const toB64 = bytes => Buffer.from(bytes).toString('base64');
const fromB64 = s => new Uint8Array(Buffer.from(s, 'base64'));

async function deriveKey(salt, usage, iterations = ITERATIONS) {
  const material = await subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

async function seal(plaintext) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt, 'encrypt');
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  return { v: 1, iter: ITERATIONS, salt: toB64(salt), iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

async function unseal(sealed) {
  const key = await deriveKey(fromB64(sealed.salt), 'decrypt', sealed.iter);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(sealed.iv) }, key, fromB64(sealed.ct));
  return new TextDecoder().decode(pt);
}

const TAPE_WORDS = ['Classified', 'Clearance required', 'Do not distribute', 'Eyes only'];

function tape(extraClass = '') {
  const set = Array.from({ length: 4 }, () => TAPE_WORDS.map(w => `<span>${w}</span>`).join('')).join('');
  return `<div class="tape${extraClass ? ' ' + extraClass : ''}" aria-hidden="true"><div class="tape-track">${set}${set}</div></div>`;
}

const TOP_TAPE = `<div class="tape-wrap" role="img" aria-label="Classified file">${tape()}</div>`;

const DOSSIER = `      <section class="dossier" id="dossier" aria-labelledby="dossier-title">
        <div class="dossier-sheet" aria-hidden="true">
          <i></i><i></i><i></i><i></i><i></i><i></i><i></i>
          ${tape('tape-x1')}
          ${tape('tape-x2')}
        </div>
        <div class="dossier-inner">
          <p class="dossier-stamp" aria-hidden="true">Top Secret</p>
          <h2 class="dossier-title" id="dossier-title">Clearance required</h2>
          <p class="dossier-copy">This file is classified. Enter your clearance code to decrypt it.</p>
          <form class="dossier-form" id="dossier-form" method="dialog" autocomplete="off">
            <label class="dossier-label" for="clearance">Clearance code</label>
            <div class="dossier-row">
              <span class="dossier-prompt" aria-hidden="true">$</span>
              <input id="clearance" type="password" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" required>
              <button type="submit" disabled>Decrypt</button>
            </div>
            <p class="dossier-status" id="dossier-status" role="status" aria-live="polite"></p>
          </form>
          <noscript><p class="dossier-status">JavaScript is required to decrypt this file.</p></noscript>
        </div>
      </section>`;

// Replace exactly one match, or fail loudly. Matches are counted with a
// global copy of the pattern, since a non-global replace stops at the first.
// A function replacer keeps "$" in the inserted markup from being read as a
// substitution pattern.
function replaceOnce(html, pattern, fn, label, file) {
  const hits = (html.match(new RegExp(pattern.source, 'g')) || []).length;
  if (hits !== 1) throw new Error(`${file}: expected one ${label}, found ${hits}`);
  return html.replace(pattern, fn);
}

const files = (await readdir(SRC)).filter(f => f.endsWith('.html')).sort();
if (!files.length) throw new Error('posts-src/ is empty');

// Every published essay needs a plaintext source, or it would be skipped
// and could ship unsealed.
const orphans = (await readdir(OUT)).filter(f => f.endsWith('.html') && !files.includes(f));
if (orphans.length) throw new Error(`posts/ has files with no posts-src/ source: ${orphans.join(', ')}`);

// Guard against a mistyped code silently re-keying the whole archive.
const existing = [];
for (const f of files) {
  const m = (await readFile(path.join(OUT, f), 'utf8').catch(() => '')).match(/id="classified-payload">([^<]+)</);
  if (m) existing.push(JSON.parse(m[1]));
}
if (existing.length && process.env.REKEY !== '1') {
  try {
    await unseal(existing[0]);
  } catch {
    console.error('That code does not open the current archive. To change the code on purpose, rerun with REKEY=1.');
    process.exit(1);
  }
}

for (const file of files) {
  let html = await readFile(path.join(SRC, file), 'utf8');
  if (html.includes('classified-payload')) throw new Error(`${file}: source is already sealed`);

  const bodyRe = /(<div class="post-body container">)([\s\S]*?)(<\/div>\s*<div class="post-end-mark)/;
  const subRe = /<p class="post-subtitle">([\s\S]*?)<\/p>/;
  const body = html.match(bodyRe);
  if (!body) throw new Error(`${file}: post body not found`);
  const sub = html.match(subRe);

  const plaintext = JSON.stringify({ sub: sub ? sub[1].trim() : null, body: body[2] });
  const sealed = await seal(plaintext);
  if ((await unseal(sealed)) !== plaintext) throw new Error(`${file}: round trip failed`);

  html = replaceOnce(html, bodyRe, (m, open, inner, close) => `${open}\n${DOSSIER}\n    ${close}`, 'post body', file);
  if (sub) {
    html = replaceOnce(html, subRe, () => '<p class="post-subtitle redacted" aria-hidden="true"></p>', 'subtitle', file);
  }
  html = replaceOnce(html, /<meta name="description" content="[^"]*">/,
    () => '<meta name="description" content="Classified. Clearance code required to read this file.">', 'meta description', file);
  html = replaceOnce(html, /<link rel="stylesheet" href="\.\.\/styles\.css">/,
    m => `${m}\n  <link rel="stylesheet" href="../classified.css">`, 'stylesheet link', file);
  html = replaceOnce(html, /<\/nav>/, m => `${m}\n  ${TOP_TAPE}`, 'nav', file);
  html = replaceOnce(html, /<script src="\.\.\/script\.js"><\/script>/,
    m => `<script type="application/json" id="classified-payload">${JSON.stringify(sealed)}</script>\n  <script src="../classified.js"></script>\n  ${m}`,
    'script tag', file);

  // Nothing readable may survive into the published page: probe every
  // paragraph and heading of the plaintext against the output.
  const probes = [...body[2].matchAll(/<(p|h2|h3|blockquote)[^>]*>([\s\S]*?)<\/\1>/g)]
    .map(m => m[2].trim())
    .filter(t => t.length >= 12);
  if (sub) probes.push(sub[1].trim());
  if (probes.length < 3) throw new Error(`${file}: too few probes to verify sealing`);
  for (const probe of probes) {
    if (html.includes(probe)) throw new Error(`${file}: plaintext leaked: "${probe.slice(0, 60)}"`);
  }
  if (html.toUpperCase().includes(code)) throw new Error(`${file}: clearance code leaked`);

  await writeFile(path.join(OUT, file), html);
  console.log(`sealed  ${file}`);
}

// The code must not appear in anything git would publish, in any case.
const publishable = execFileSync('git', ['ls-files', '-co', '--exclude-standard'], { cwd: ROOT, encoding: 'utf8' })
  .split('\n').filter(Boolean);
for (const f of publishable) {
  const text = await readFile(path.join(ROOT, f), 'utf8').catch(() => '');
  if (text.toUpperCase().includes(code)) throw new Error(`clearance code appears in ${f}; remove it before publishing`);
}

console.log(`\n${files.length} files sealed; ${publishable.length} publishable files checked for the code.`);
