/**
 * Regenerate rules/gitleaks.json from the upstream gitleaks config.
 *
 *   node scripts/build-gitleaks.mjs                 # fetch from jsdelivr
 *   node scripts/build-gitleaks.mjs ./gitleaks.toml # local snapshot
 *
 * The upstream file is MIT (Copyright (c) 2019 Zachary Rice); see NOTICE.
 * Go/RE2 supports a few constructs JS RegExp does not, so the regexes are
 * downgraded here and every one is compiled before it is written out.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'rules', 'gitleaks.json');
const DEFAULT_SOURCE = 'https://cdn.jsdelivr.net/gh/gitleaks/gitleaks@master/config/gitleaks.toml';
const SOURCE_ARG = process.argv[2];

const LOOSE_IDS = new Set([
  'curl-auth-header', 'curl-auth-user', 'generic-api-key',
  'jwt-base64', 'kubernetes-secret-yaml',
]);
const SPECIAL = {
  '1password': '1Password', oauth: 'OAuth', api: 'API', jwt: 'JWT', aws: 'AWS',
  gcp: 'GCP', id: 'ID', url: 'URL', ssh: 'SSH', tls: 'TLS', ip: 'IP',
  json: 'JSON', yaml: 'YAML', pem: 'PEM', sql: 'SQL', cli: 'CLI', ui: 'UI',
  pkcs: 'PKCS', hmac: 'HMAC', sha: 'SHA', ssl: 'SSL', gpg: 'GPG', rsa: 'RSA',
  oidc: 'OIDC', saml: 'SAML', smtp: 'SMTP', pdf: 'PDF', ca: 'CA',
};

function friendlyName(id) {
  return String(id).split(/[-_]/).map((word) => {
    if (SPECIAL[word]) return SPECIAL[word];
    return word.charAt(0).toUpperCase() + word.slice(1);
  }).join(' ');
}

function convert(regex) {
  const needI = /\(\?i\)|\(\?i:/.test(regex);
  const src = regex
    .replace(/\(\?i\)/g, '')
    .replace(/\(\?i:/g, '(?:')
    .replace(/\(\?-i:/g, '(?:')
    .replace(/\(\?P</g, '(?<')
    .split('(?s:.)').join('[\\s\\S]')
    .split('(?s:').join('(?:');
  return { regex: src, flags: 'gd' + (needI ? 'i' : ''), approx: /\(\?-i:/.test(regex) };
}

function parseBlocks(text) {
  const chunks = text.split(/^\[\[rules\]\][ \t]*$/m).slice(1);
  return chunks.map((chunk) => chunk.split(/^\[\[/m)[0]);
}

function field(block, name) {
  const m = new RegExp('^' + name + '\\s*=\\s*([^\\n]+)', 'm').exec(block);
  return m ? m[1].trim() : null;
}

function quoted(block, name) {
  const m = new RegExp('^' + name + '\\s*=\\s*"([^"]*)"', 'm').exec(block);
  return m ? m[1] : null;
}

function tripleQuoted(block, name) {
  const m = new RegExp('^' + name + "\\s*=\\s*'''([\\s\\S]*?)'''", 'm').exec(block);
  return m ? m[1] : null;
}

let text;
if (SOURCE_ARG) {
  text = fs.readFileSync(path.resolve(SOURCE_ARG), 'utf8');
} else {
  const res = await fetch(DEFAULT_SOURCE);
  if (!res.ok) throw new Error(`fetch failed: ${res.status}`);
  text = await res.text();
}

const blocks = parseBlocks(text);
const rules = [];
const skipped = [];
for (const block of blocks) {
  const id = quoted(block, 'id');
  if (!id) continue;
  const raw = tripleQuoted(block, 'regex');
  if (!raw) {
    skipped.push({ id, reason: tripleQuoted(block, 'path') ? 'path-only rule (no text regex)' : 'no regex' });
    continue;
  }
  const kwBlock = /^keywords\s*=\s*\[([\s\S]*?)\]/m.exec(block);
  const keywords = kwBlock ? [...kwBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : [];
  const entropyRaw = field(block, 'entropy');
  const groupRaw = field(block, 'secretGroup');
  const c = convert(raw);
  try {
    new RegExp(c.regex, c.flags);
  } catch (error) {
    skipped.push({ id, reason: `compile: ${error.message.slice(0, 80)}` });
    continue;
  }
  const tier = c.approx ? 'approx' : LOOSE_IDS.has(id) ? 'loose' : 'core';
  rules.push({
    id,
    name: friendlyName(id),
    regex: c.regex,
    flags: c.flags,
    group: groupRaw ? Number(groupRaw) : 0,
    keywords,
    entropy: entropyRaw ? Number(entropyRaw) : null,
    approx: c.approx,
    tier,
    defaultOn: tier === 'core',
  });
}

const payload = {
  source: 'gitleaks/gitleaks config/gitleaks.toml',
  license: 'MIT',
  generatedAt: new Date().toISOString(),
  total: blocks.length,
  compiled: rules.length,
  skipped,
  rules,
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${JSON.stringify(payload, null, 2)}\n`);
const tiers = rules.reduce((acc, r) => ({ ...acc, [r.tier]: (acc[r.tier] || 0) + 1 }), {});
console.log(`blocks=${blocks.length} compiled=${rules.length} skipped=${skipped.length}`);
console.log('tiers:', JSON.stringify(tiers));
console.log('with keywords:', rules.filter((r) => r.keywords.length).length,
  '| with entropy:', rules.filter((r) => r.entropy !== null).length);
console.log('bytes:', fs.statSync(OUT).size, '->', OUT);
