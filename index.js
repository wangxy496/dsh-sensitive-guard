/**
 * Host half of dsh-sensitive-guard — WorkBuddy-style 敏感保护 for DSH.
 *
 * Ingress: `agent/pre-step` (user messages) and `tools/post-execute` (tool
 * results) replace detected credentials with stable `<SG_hex12>` placeholders
 * before anything is committed to the session log, so model context never
 * carries plaintext. The plaintext goes into a local AES-256-GCM vault.
 *
 * Egress: the platform's `tools/pre-execute` only allows allow/deny/cancel/ask
 * (no argument rewrite), so secret use at execution time goes through
 * `sensitive_guard_export`, which writes the plaintext to a 0600 file the
 * command consumes (`$(cat …)`). Exported files expire after EXPORT_TTL_MS.
 *
 * Human reveal happens in Settings via `POST /guard/reveal`, which is
 * same-origin checked, audited, and restricted to loopback by default. LAN
 * access is opt-in through `allowCidrs` in rules.json, and even then the Host
 * header must be an IP literal (blocks DNS rebinding) and POSTs must be JSON
 * (forces a CORS preflight the server never answers). `/guard/vault` carries
 * the 8-char preview, so it gets the same gate; tool output deliberately
 * carries no preview at all, since tool results land in model context.
 *
 * `llm/stream` scrubs outbound `text-delta` chunks as a backstop for log
 * content written before this plugin existed. It must stay an async generator:
 * the host `yield*`s its return value.
 */

import { execFileSync } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import { isIP } from 'node:net';
import os from 'node:os';
import path from 'node:path';

const VAULT_ROUTE = '/guard/vault';
const REVEAL_ROUTE = '/guard/reveal';
const SETTINGS_ROUTE = '/guard/settings';
const PLUGIN_VERSION = '0.4.0';

/** Stable placeholder form: <SG_ + 12 hex chars of HMAC(vault.key, plaintext) + >. */
const PH_EXACT = /^<SG_[0-9a-f]{12}>$/;
const PH_HINT = '<SG_';
const HASH_EXACT = /^[0-9a-f]{12}$/;

/**
 * Prose rules capture the rest of the token, so a trailing Chinese particle or
 * punctuation mark rides along: "我的密码是 123456吗" would vault `123456吗` and
 * hand the particle back on export, with a different hash than the bare secret.
 * Stripped only by rules that opt in (`trimTail`), and only while something
 * worth masking is left.
 */
const TAIL_JUNK = /(?:[?？!！。.，,;；:：、'"`“”‘’()（）[\]【】《》「」『』]|[吗呢啊吧呀嘛哦呗啦么哈]+)$/u;

/**
 * Vendor prefixes are not the secret — the tail is. Keeping `sk-` / `ghp_` in
 * place keeps the sentence readable and tells you which service leaked, while
 * the placeholder covers only the part that actually authenticates.
 */
const KEEP_PREFIX = /^(sk_live_|sk_test_|rk_live_|rk_test_|pk_live_|pk_test_|sk-|sk_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|npm_|hf_|AKIA|ASIA|xox[abprs]-|AIza|whsec_|SG\.)/;

/** Prefix to leave in the text; empty when nothing meaningful remains to mask. */
function prefixOf(value) {
  if (typeof value !== 'string') return '';
  const m = KEEP_PREFIX.exec(value);
  if (!m) return '';
  return value.length - m[0].length >= 6 ? m[0] : '';
}

/** Preview keeps at most the first 8 chars, and only for long values. */
const PREVIEW_MIN = 20;
/** Vault growth cap; least-recently-hit entries are evicted past this. */
const MAX_VAULT_ENTRIES = 500;
/** Coalesce vault writes — every capture used to rewrite the whole file. */
const PERSIST_DEBOUNCE_MS = 250;
/** Exported plaintext files expire; they are the only plaintext on disk. */
const EXPORT_TTL_MS = 15 * 60 * 1000;
/** Per-string scan window: a blocking regex over a huge blob would stall the host. */
const MAX_SCAN_CHARS = 200000;

/* ---------------------------------------------------------------- vault -- */

let dataDir_ = null;
function dataDir() {
  if (dataDir_) return dataDir_;
  const profileDir = process.env.DSH_PROFILE_DIR;
  const base = profileDir
    || (process.env.DSH_PROFILE
      ? path.join(process.env.DSH_HOME || path.join(os.homedir(), '.dsh'), 'profiles', process.env.DSH_PROFILE)
      : null)
    || path.join(process.env.DSH_HOME || path.join(os.homedir(), '.dsh'));
  dataDir_ = path.join(base, 'sensitive-guard');
  return dataDir_;
}

const vault = { key: null, entries: new Map(), byPh: new Map(), loaded: false, keyError: null };
const stats = {
  maskedValues: 0, maskedRuns: 0, outboundScrubs: 0, reveals: 0, exports: 0,
  failOpen: 0, evicted: 0, exportCleanups: 0,
};
const audit = [];
let lastError = null;

/**
 * Protection can be paused from Settings. Two shapes:
 *   - `until` a timestamp (auto-resumes, survives a restart)
 *   - `untilRestart` (deliberately not persisted — a restart re-arms the guard)
 */
const pause = { until: 0, untilRestart: false };

function pauseFile() { return path.join(dataDir(), 'pause.json'); }

function loadPause() {
  try {
    const raw = JSON.parse(fs.readFileSync(pauseFile(), 'utf8'));
    // `untilRestart` is deliberately not restored: a restart re-arms the guard.
    if (raw && Number.isFinite(raw.until) && raw.until > Date.now()) pause.until = raw.until;
  } catch { /* no pause file yet */ }
}

function persistPause() {
  try {
    fs.mkdirSync(dataDir(), { recursive: true });
    fs.writeFileSync(pauseFile(), JSON.stringify({ until: pause.until }), { mode: 0o600 });
  } catch (error) {
    lastError = `pause persist: ${String((error && error.message) || error)}`;
  }
}

/** @returns remaining ms while paused, 0 when protection is active. */
function pausedMs() {
  if (pause.untilRestart) return Number.POSITIVE_INFINITY;
  return Math.max(0, pause.until - Date.now());
}

function vaultFile() { return path.join(dataDir(), 'vault.json'); }
function keyFile() { return path.join(dataDir(), 'vault.key'); }
function rulesFile() { return path.join(dataDir(), 'rules.json'); }

let keyAclWarned = false;

/** POSIX mode bits are a no-op on Windows — tighten the DACL explicitly there. */
function hardenFilePermissions(file) {
  try { fs.chmodSync(file, 0o600); } catch { /* best effort */ }
  if (process.platform !== 'win32') return;
  const user = process.env.USERNAME;
  if (!user) return;
  try {
    execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${user}:F`], { stdio: 'ignore', windowsHide: true });
  } catch (error) {
    if (!keyAclWarned) {
      keyAclWarned = true;
      lastError = `vault.key ACL: ${String((error && error.message) || error)}`;
    }
  }
}

function loadKey() {
  if (vault.key) return vault.key;
  try {
    fs.mkdirSync(dataDir(), { recursive: true });
    try {
      const raw = fs.readFileSync(keyFile());
      if (raw.length !== 32) throw new Error('vault.key is not 32 bytes');
      vault.key = raw;
    } catch (error) {
      if (error && error.code !== 'ENOENT') throw error;
      const fresh = randomBytes(32);
      try {
        fs.writeFileSync(keyFile(), fresh, { flag: 'wx', mode: 0o600 });
        vault.key = fresh;
      } catch (writeError) {
        // Another process created the key between our read and write: adopt it
        // instead of failing open for the rest of the session.
        if (!writeError || writeError.code !== 'EEXIST') throw writeError;
        const raw = fs.readFileSync(keyFile());
        if (raw.length !== 32) throw new Error('vault.key is not 32 bytes');
        vault.key = raw;
      }
    }
    hardenFilePermissions(keyFile());
    return vault.key;
  } catch (error) {
    vault.keyError = String((error && error.message) || error);
    return null;
  }
}

function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', loadKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return `v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
}

function decrypt(payload) {
  const [tag, ivB64, tagB64, ctB64] = String(payload).split(':');
  if (tag !== 'v1') throw new Error('unknown vault version');
  const decipher = createDecipheriv('aes-256-gcm', loadKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]).toString('utf8');
}

/** Internal vault key. Never exposed: the placeholder used to be derived from
 * this, which made short/low-entropy secrets reversible by offline dictionary.
 */
function hashOf(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 12);
}

/**
 * Placeholder = HMAC-SHA256(vault.key, plaintext)[:12]. Deterministic, so the
 * same secret always gets the same code, but offline brute force no longer
 * works without the local key — a six-digit password could previously be
 * recovered from the code in ~100ms.
 */
function placeholderOf(value) {
  return `<SG_${createHmac('sha256', loadKey()).update(value, 'utf8').digest('hex').slice(0, 12)}>`;
}

function loadVault() {
  if (vault.loaded) return;
  vault.loaded = true;
  try {
    const raw = JSON.parse(fs.readFileSync(vaultFile(), 'utf8'));
    for (const entry of Array.isArray(raw && raw.entries) ? raw.entries : []) {
      if (!entry || typeof entry.enc !== 'string') continue;
      if (typeof entry.hash !== 'string' || !HASH_EXACT.test(entry.hash)) continue;
      if (typeof entry.ph !== 'string' || !PH_EXACT.test(entry.ph)) continue;
      vault.entries.set(entry.hash, entry);
      vault.byPh.set(entry.ph, entry.hash);
      // Pre-0.4.0 codes were sha256(plaintext)[:12]. Keep every historical
      // alias resolvable so old conversations can still unlock their chips.
      for (const alias of Array.isArray(entry.aliases) ? entry.aliases : []) {
        if (typeof alias === 'string' && PH_EXACT.test(alias)) vault.byPh.set(alias, entry.hash);
      }
    }
  } catch (error) {
    if (error && error.code !== 'ENOENT') lastError = `vault load: ${String(error.message || error)}`;
  }
}

let persistTimer = null;

function persistVault(immediate) {
  if (!immediate) {
    if (persistTimer) return;
    persistTimer = setTimeout(() => { persistTimer = null; persistVault(true); }, PERSIST_DEBOUNCE_MS);
    if (typeof persistTimer.unref === 'function') persistTimer.unref();
    return;
  }
  try {
    fs.mkdirSync(dataDir(), { recursive: true });
    const payload = JSON.stringify({ version: 1, entries: [...vault.entries.values()] });
    const tmp = `${vaultFile()}.tmp`;
    fs.writeFileSync(tmp, payload, { mode: 0o600 });
    fs.renameSync(tmp, vaultFile());
  } catch (error) {
    lastError = `vault persist: ${String((error && error.message) || error)}`;
  }
}

/** Evict least-recently-hit entries so the vault cannot grow without bound. */
function trimVault() {
  if (vault.entries.size <= MAX_VAULT_ENTRIES) return;
  const ordered = [...vault.entries.values()]
    .sort((a, b) => String(a.lastHitAt || a.createdAt).localeCompare(String(b.lastHitAt || b.createdAt)));
  for (let i = 0; i < ordered.length && vault.entries.size > MAX_VAULT_ENTRIES; i += 1) {
    const victim = ordered[i];
    vault.entries.delete(victim.hash);
    vault.byPh.delete(victim.ph);
    stats.evicted += 1;
    noteAudit('evict', { ph: victim.ph });
  }
}

function noteAudit(kind, extra) {
  audit.push({ at: new Date().toISOString(), kind, ...extra });
  if (audit.length > 200) audit.splice(0, audit.length - 200);
}

/** Map plaintext → stable placeholder, encrypting into the vault on first sight. */
function remember(plaintext, rule, origin, label) {
  loadVault();
  const hash = hashOf(plaintext);
  const ph = placeholderOf(plaintext);
  const existing = vault.entries.get(hash);
  if (existing) {
    existing.hits = (existing.hits || 0) + 1;
    existing.lastHitAt = new Date().toISOString();
    // Upgrade a pre-0.4.0 entry in place. The old code stays in `aliases` and
    // in byPh, so chips already written into old session logs still resolve.
    if (existing.ph !== ph) {
      const aliases = Array.isArray(existing.aliases) ? existing.aliases.slice() : [];
      if (!aliases.includes(existing.ph)) aliases.push(existing.ph);
      existing.aliases = aliases;
      existing.ph = ph;
      vault.byPh.set(ph, hash);
      for (const alias of aliases) vault.byPh.set(alias, hash);
      noteAudit('recode', { ph });
      persistVault();
    }
    return existing.ph;
  }
  const entry = {
    hash,
    ph,
    aliases: [],
    enc: encrypt(plaintext),
    prefix: prefixOf(plaintext),
    preview: plaintext.length >= PREVIEW_MIN ? `${plaintext.slice(0, 8)}…` : '',
    rule: String(rule || 'unknown'),
    label: String(label || rule || 'unknown'),
    origin: String(origin || 'unknown'),
    createdAt: new Date().toISOString(),
    hits: 1,
    lastHitAt: new Date().toISOString(),
  };
  vault.entries.set(hash, entry);
  vault.byPh.set(ph, hash);
  stats.maskedValues += 1;
  noteAudit('capture', { ph, rule: entry.rule, origin: entry.origin });
  trimVault();
  persistVault();
  return ph;
}

/** Metadata for the Settings UI — may carry the 8-char preview. */
function entryView(entry) {
  return {
    ph: entry.ph,
    aliases: Array.isArray(entry.aliases) ? entry.aliases.slice() : [],
    preview: entry.preview,
    rule: entry.rule,
    label: entry.label || entry.rule,
    origin: entry.origin,
    createdAt: entry.createdAt,
    lastHitAt: entry.lastHitAt,
    hits: entry.hits || 1,
  };
}

/**
 * Metadata safe to hand a model. Deliberately drops `preview`: the first 8
 * characters of a secret are still secret, and a tool result lands in exactly
 * the context this plugin exists to keep clean.
 */
function entryViewForModel(entry) {
  return {
    ph: entry.ph,
    rule: entry.rule,
    origin: entry.origin,
    createdAt: entry.createdAt,
    lastHitAt: entry.lastHitAt,
    hits: entry.hits || 1,
  };
}

/* ---------------------------------------------------------------- rules -- */

/**
 * Field names are stronger evidence than value shape: a tool result carrying
 * {"password": "..."} is a credential even when the value has no vendor prefix.
 * Whole name segments only, so `author`, `tokenizer`, `secretary` stay clean.
 */
const SENSITIVE_KEY_WORDS = new Set([
  'password', 'passwd', 'pwd', 'passphrase', 'pass', 'secret', 'token',
  'apikey', 'accesskey', 'clientsecret', 'credential', 'credentials',
  'auth', 'authorization', 'privatekey', 'dsn', 'connectionstring',
  'accesstoken', 'refreshtoken', 'sessionkey', 'appkey', 'appsecret',
]);
const KEY_NEGATIVE = /(?:hint|policy|count|length|type|name|label|description|enabled|required|expiry|expires|ttl|url|path|example|placeholder|regex|pattern|schema|comment|help|text|title|error|message|status|state|flag|version|format|kind|mode|index|size|boolean|number|id|ids|list|map|set)$/i;
const PLACEHOLDER_VALUE = /^(?:null|undefined|nil|none|n\/a|na|true|false|yes|no|unknown|empty|redacted|masked|hidden|placeholder|example|sample|dummy|fake|test|demo|todo|fixme|tbd|not[_-]?set[_-]?(?:yet)?|changeme|change[_-]?me|your[_-]?(?:password|passwd|token|key|secret|api[_-]?key)[_-]?(?:here)?|(?:password|passwd|secret|token|api[_-]?key)[_-]?(?:here|placeholder|example)?|x{2,}|\*{2,}|\.{2,}|-{2,}|\?{2,}|0{3,}|<[^>]{1,40}>|\$\{[^}]{1,60}\}|\{\{[^}]{1,60}\}\}|\$[A-Z_][A-Z0-9_]*|%\(?[a-z_]+\)?s)$/i;

/** Values that are documentation, placeholders or template variables, not secrets. */
function isPlaceholderValue(value) {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v.length < 3 || v.includes(PH_HINT)) return true;
  return PLACEHOLDER_VALUE.test(v);
}

function isSensitiveKey(key) {
  if (typeof key !== 'string' || key.length > 64 || isIdentifierKey(key)) return false;
  if (KEY_NEGATIVE.test(key)) return false;
  if (/(密码|口令|密钥|令牌|凭证|私钥)/.test(key)) return true;
  const parts = key.toLowerCase().replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[^a-z0-9]+/).filter(Boolean);
  return parts.some((part) => SENSITIVE_KEY_WORDS.has(part));
}

function labelForKey(key) {
  const k = String(key).toLowerCase();
  if (/pass|密码|口令/.test(k)) return '密码';
  if (/token|令牌|jwt|bearer|auth/.test(k)) return '令牌';
  if (/key|secret|密钥|凭证|credential|dsn|connection/.test(k)) return '密钥';
  return '其它';
}

/** "key": "value" inside a JSON *string*. Only ingress gets these hits. */
const STRUCT_FIELD_RE = /"(?<key>[A-Za-z0-9_.\-]{1,64})"\s*:\s*"(?<value>[^"\\]{1,200})"/gd;

function structuralHits(text) {
  const out = [];
  STRUCT_FIELD_RE.lastIndex = 0;
  let match;
  while ((match = STRUCT_FIELD_RE.exec(text)) !== null) {
    const key = match.groups && match.groups.key;
    const value = match.groups && match.groups.value;
    const range = match.indices && match.indices.groups && match.indices.groups.value;
    if (!key || !value || !range) continue;
    if (!isSensitiveKey(key) || isPlaceholderValue(value)) continue;
    out.push({ offset: range[0], end: range[1], value, rule: 'structured-field', label: labelForKey(key) });
  }
  return out;
}

const BUILTIN_RULES = [
  { id: 'openai-key', group: 0, re: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  // A pasted key whose display soft-wrapped: the prefix and the tail land on
  // different lines, so every single-line rule misses it. `squash` joins the
  // halves back into one value before it reaches the vault.
  { id: 'wrapped-key', group: 1, squash: true, re: /\b((?:sk-|sk_|ghp_|glpat-|npm_|hf_|AKIA|ASIA|AIza|whsec_)[A-Za-z0-9_-]{0,32}[ \t]*(?:\r\n|\r|\n)[ \t]*[A-Za-z0-9_-]{12,})/g },
  { id: 'openai-live', group: 0, re: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { id: 'github-token', group: 0, re: /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b/g },
  { id: 'gitlab-token', group: 0, re: /\bglpat-[A-Za-z0-9_-]{16,}\b/g },
  { id: 'npm-token', group: 0, re: /\bnpm_[A-Za-z0-9]{16,}\b/g },
  { id: 'hf-token', group: 0, re: /\bhf_[A-Za-z0-9]{16,}\b/g },
  { id: 'aws-key', group: 0, re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'slack-token', group: 0, re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'google-key', group: 0, re: /\bAIza[0-9A-Za-z_-]{30,}\b/g },
  { id: 'stripe-key', group: 0, re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { id: 'sendgrid-key', group: 0, re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
  { id: 'segment-secret', group: 0, re: /\bwhsec_[A-Za-z0-9]{16,}\b/g },
  { id: 'jwt', group: 0, re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: 'private-key-block', group: 0, re: /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]{8,}?-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----/g },
  { id: 'keyword-assign', group: 3, re: /\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret)(\s*[=:]\s*["']?)([^\s"',;)}\]]{8,})/gi },
  // Prose form: people write "我的 api key 是 sk-…" far more often than they
  // write `api_key=…`. Chinese separators and keywords are included because the
  // assign-only rule silently missed every sentence-shaped secret. The optional
  // `[A-Za-z_]{0,12}` tail catches env-style names such as SECRET_KEY or
  // DB_PASSWORD_HASH, where `secret` is glued to a suffix by an underscore.
  { id: 'keyword-prose', group: 2, trimTail: true, re: /(password|passwd|pwd|secret|token|api[\s_-]?key|apikey|access[\s_-]?key|client[\s_-]?secret|密码|口令|密钥|令牌|凭证|私钥)[A-Za-z_]{0,12}\s*(?:[:=：]|是|为|就是|is)\s*["'`]?([^\s"'`,;)}\]，。、；：！？（）【】《》「」『』“”‘’…]{8,})/gi },
  // Chinese prose gets a lower floor: "我的密码是 123456" is a real secret and
  // six-digit passwords are common. English prose keeps 8 so that sentences like
  // "the secret is hidden" are not masked on the word "hidden".
  { id: 'keyword-prose-cn', group: 2, trimTail: true, re: /(密码|口令|密钥|令牌|凭证|私钥)\s*(?:[:=：]|是|为|就是)\s*["'`]?([^\s"'`,;)}\]，。、；：！？（）【】《》「」『』“”‘’…]{6,})/gi },
  // Opaque bearer credentials have no vendor prefix and no `key: value` shape.
  { id: 'bearer-token', group: 1, re: /\bBearer\s+([A-Za-z0-9\-._~+/]{12,}={0,2})/gi },
  // Command-line passwords. Scoped to clients whose `-p` / `-a` really means a
  // password, so `docker -p 8080:80` and `-path` never match.
  { id: 'cli-password', group: 1, re: /\b(?:mysql|mysqldump|mysqladmin|redis-cli|mongo|mongosh)\b[^\n]{0,80}?\s(?:-p|--password[= ]|-a)\s*["']?([^\s"'`-]\S{3,})/gi },
  { id: 'url-password', group: 1, re: /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s/:@?#]{1,256}:([^\s/?@#]{6,})@/gi },
];

/**
 * `d` gives exact group offsets. Recovering an offset with
 * `match[0].indexOf(value)` picks the wrong place whenever the value also
 * occurs earlier in the match (a URL whose password repeats the user name).
 */
function withIndices(re) {
  return re.flags.includes('d') ? re : new RegExp(re.source, `${re.flags}d`);
}

// Compiling these at module scope means a bad regex would throw during import,
// before `apply` can catch anything. Keep it contained and fall back to the
// location-recovery path (indexOf) for whatever fails.
try {
  for (const rule of BUILTIN_RULES) rule.re = withIndices(rule.re);
} catch (error) {
  console.warn('[sensitive-guard] rule precompile failed:', error && error.message);
}

let fileRules = { list: [], outboundScrub: true, entropy: false, entropyThreshold: 4.5, allowCidrs: [], error: null, mtime: 0, checkedAt: 0 };

function reloadRules(force) {
  const now = Date.now();
  if (!force && now - fileRules.checkedAt < 2000) return;
  fileRules.checkedAt = now;
  let stat;
  try { stat = fs.statSync(rulesFile()); } catch { return; }
  if (!force && stat.mtimeMs === fileRules.mtime) return;
  fileRules.mtime = stat.mtimeMs;
  try {
    const raw = JSON.parse(fs.readFileSync(rulesFile(), 'utf8'));
    const list = [];
    for (const item of Array.isArray(raw && raw.extraRules) ? raw.extraRules : []) {
      if (!item || typeof item.pattern !== 'string') continue;
      try {
        list.push({
          id: String(item.id || 'custom'),
          group: Number.isInteger(item.group) ? item.group : 0,
          re: withIndices(new RegExp(item.pattern, typeof item.flags === 'string' ? item.flags.replace(/[gyd]/g, '') + 'g' : 'g')),
        });
      } catch { /* skip invalid user rule */ }
    }
    fileRules.list = list;
    fileRules.outboundScrub = raw && raw.outboundScrub === false ? false : true;
    fileRules.entropy = raw && raw.entropy === true;
    fileRules.entropyThreshold = raw && Number.isFinite(raw.entropyThreshold) ? raw.entropyThreshold : 4.5;
    fileRules.disabled = new Set(Array.isArray(raw && raw.disabled) ? raw.disabled.map(String) : []);
    // Opt-in LAN exposure for the reveal routes. Empty (the default) keeps them
    // loopback-only. Entries are CIDRs, e.g. ["192.168.0.0/16"].
    const wanted = Array.isArray(raw && raw.allowCidrs) ? raw.allowCidrs.map((item) => String(item).trim()) : [];
    const accepted = wanted.filter((item) => parseCidr(item) !== null);
    const rejected = wanted.filter((item) => parseCidr(item) === null);
    fileRules.allowCidrs = accepted;
    fileRules.error = null;
    if (rejected.length > 0) {
      fileRules.error = `allowCidrs 忽略无效项: ${rejected.join(', ')}（需形如 192.168.0.0/16，且不接受 /0）`;
    }
  } catch (error) {
    fileRules.error = String((error && error.message) || error);
  }
}

function disabledSet() {
  return fileRules.disabled instanceof Set ? fileRules.disabled : new Set();
}

function activeRules() {
  reloadRules(false);
  const disabled = disabledSet();
  return [...BUILTIN_RULES, ...fileRules.list].filter((rule) => !disabled.has(rule.id));
}

/* -------------------------------------------------------------- scrubbing -- */

/** Shannon entropy in bits per character — high for random-looking blobs. */
function shannon(value) {
  const freq = new Map();
  for (const ch of value) freq.set(ch, (freq.get(ch) || 0) + 1);
  let bits = 0;
  for (const n of freq.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * Opt-in entropy detection for unprefixed blobs (a random token pasted with no
 * context). Off by default: base64 images, file hashes and UUIDs all score high
 * and would be masked for no reason. Enable with `"entropy": true` in rules.json.
 */
function entropyHits(text) {
  const out = [];
  const re = /[A-Za-z0-9+/=_-]{24,}/g;
  const threshold = Number.isFinite(fileRules.entropyThreshold) ? fileRules.entropyThreshold : 4.5;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[0].includes(PH_HINT)) continue;
    if (shannon(m[0]) >= threshold) {
      out.push({ offset: m.index, end: m.index + m[0].length, value: m[0], rule: 'high-entropy', label: 'secret' });
    }
  }
  return out;
}

/** Non-overlapping hits: [{offset, end, value, rule}]. Already-masked values are skipped. */
function findHits(text, origin) {
  // A pathological custom rule can backtrack for minutes on a huge blob, and this
  // runs synchronously inside a hook — cap the window rather than freeze the host.
  const scan = text.length > MAX_SCAN_CHARS ? text.slice(0, MAX_SCAN_CHARS) : text;
  const hits = [];
  for (const rule of activeRules()) {
    rule.re.lastIndex = 0;
    let match;
    while ((match = rule.re.exec(scan)) !== null) {
      if (match[0].length === 0) { rule.re.lastIndex += 1; continue; }
      const raw = match[rule.group];
      if (typeof raw !== 'string') continue;
      // A key that got soft-wrapped when pasted carries a line break inside it.
      // `squash` joins it back so the vault hashes the clean value and the
      // placeholder stays identical to the unwrapped capture.
      const value = rule.squash ? raw.replace(/\s+/g, '') : raw;
      if (value.length < 6) continue;
      if (value.includes(PH_HINT)) continue;
      const range = match.indices && match.indices[rule.group];
      const offset = range ? range[0] : match.index + match[0].indexOf(raw);
      let end = range ? range[1] : offset + raw.length;
      // Trim after the offsets are known, so the placeholder covers only the
      // secret and the particle stays as readable text.
      let trimmed = value;
      if (rule.trimTail) {
        let prev;
        do { prev = trimmed; trimmed = trimmed.replace(TAIL_JUNK, ''); } while (trimmed !== prev);
        if (trimmed.length < 6) continue;
        end -= value.length - trimmed.length;
      }
      // The keyword group (when the rule has one) says *what* leaked — password /
      // token / key — which the rule id alone cannot express for keyword-prose.
      const label = rule.group > 1 && typeof match[1] === 'string' ? match[1] : rule.id;
      hits.push({ offset, end, value: trimmed, rule: rule.id, label });
    }
  }
  // A field name is strong evidence for user input and tool output, but a model
  // writing an example JSON is not a leak. Keep structural hits off the
  // outbound backstop so the model's own examples are not scrambled.
  if (origin !== 'outbound') {
    for (const hit of structuralHits(scan)) hits.push(hit);
  }
  if (fileRules.entropy) {
    for (const hit of entropyHits(scan)) hits.push(hit);
  }
  hits.sort((a, b) => a.offset - b.offset || b.end - a.end);
  const kept = [];
  let last = -1;
  for (const hit of hits) {
    if (hit.offset >= last) { kept.push(hit); last = hit.end; }
  }
  return kept;
}

function scrubText(text, origin) {
  if (typeof text !== 'string' || text.length < 6) return [text, false];
  const hits = findHits(text, origin);
  if (!hits.length) return [text, false];
  let out = '';
  let cursor = 0;
  let maskedAny = false;
  for (const hit of hits) {
    // Obvious documentation placeholders win over every rule, including
    // structural field names.
    if (isPlaceholderValue(hit.value)) continue;
    out += text.slice(cursor, hit.offset);
    maskedAny = true;
    try {
      // Leave the vendor prefix in the sentence; only the authenticating tail
      // becomes a placeholder. The vault still keys on the complete value.
      const head = prefixOf(hit.value);
      if (head) out += head;
      out += remember(hit.value, hit.rule, origin, hit.label);
      stats.maskedRuns += 1;
    } catch (error) {
      lastError = `capture: ${String((error && error.message) || error)}`;
      stats.failOpen += 1;
      out += hit.value; // vault unavailable: fail open (context keeps plaintext)
    }
    cursor = hit.end;
  }
  out += text.slice(cursor);
  return [out, maskedAny];
}

/** Identifier-shaped keys carry handles, not secrets; rewriting one breaks lookups. */
function isIdentifierKey(key) {
  if (typeof key !== 'string') return false;
  return key === 'id' || key === 'uuid' || key === 'guid' || /(?:Id|ID|_id)$/.test(key);
}

/**
 * Rebuild plain objects/arrays with strings scrubbed; identifier keys are never
 * touched and non-plain instances are returned unchanged.
 */
function scrubDeep(value, origin, key) {
  if (typeof value === 'string') {
    if (isIdentifierKey(key)) return [value, false];
    const [scrubbed, did] = scrubText(value, origin);
    if (did) return [scrubbed, true];
    // Already-parsed objects: the field name is the strongest signal and the
    // value may be a short password with no vendor prefix at all. Never do
    // this on outbound text — a model's example JSON is not a leak.
    if (origin !== 'outbound' && key && isSensitiveKey(key) && !isPlaceholderValue(value)) {
      try {
        const ph = remember(value, 'structured-field', origin, labelForKey(key));
        stats.maskedRuns += 1;
        return [ph, true];
      } catch (error) {
        lastError = `capture: ${String((error && error.message) || error)}`;
        stats.failOpen += 1;
      }
    }
    return [value, false];
  }
  if (Array.isArray(value)) {
    let changed = false;
    const next = value.map((item) => {
      const [v, ch] = scrubDeep(item, origin, key);
      if (ch) changed = true;
      return v;
    });
    return [changed ? next : value, changed];
  }
  if (value && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return [value, false];
    let changed = false;
    const next = {};
    for (const [k, v] of Object.entries(value)) {
      const [nv, ch] = scrubDeep(v, origin, k);
      if (ch) changed = true;
      next[k] = nv;
    }
    return [changed ? next : value, changed];
  }
  return [value, false];
}

/* ----------------------------------------------------------------- hooks -- */

/** Last pre-step invocation, exposed via /guard/vault while diagnosing. */
const debugPre = { at: 0, stage: 'never', msgs: -1, isArray: false, keys: null, kind: null, changed: false, error: null };

function attachHooks(ctx) {
  // Ingress A: user messages entering the step (before the log commit).
  ctx.on('agent/pre-step', async (payload, next) => {
    debugPre.at = Date.now();
    debugPre.stage = 'entered';
    debugPre.keys = payload && typeof payload === 'object' ? Object.keys(payload) : null;
    debugPre.isArray = Boolean(payload && Array.isArray(payload.messages));
    debugPre.msgs = payload && Array.isArray(payload.messages) ? payload.messages.length : -1;
    let decision;
    try {
      decision = await next();
      debugPre.kind = decision && decision.kind;
    } catch (error) {
      debugPre.stage = 'next-threw';
      debugPre.error = String((error && error.message) || error);
      throw error;
    }
    try {
      // A rejected step never enters the log; rewriting its messages would only
      // corrupt the shape the loop reads back.
      if (!decision || decision.kind !== 'enter') { debugPre.stage = 'skip:kind'; return decision; }
      if (pausedMs() > 0) { debugPre.stage = 'skip:paused'; return decision; }
      if (!payload || !Array.isArray(payload.messages)) { debugPre.stage = 'skip:shape'; return decision; }
      let changed = false;
      const messages = payload.messages.map((message) => {
        if (!message || typeof message !== 'object') return message;
        const [content, did] = scrubDeep(message.content, 'user');
        if (!did) return message;
        changed = true;
        return { ...message, content };
      });
      debugPre.changed = changed;
      debugPre.stage = changed ? 'masked' : 'skip:no-hit';
      if (!changed) return decision;
      return { ...decision, messages };
    } catch (error) {
      debugPre.stage = 'threw';
      debugPre.error = String((error && error.message) || error);
      lastError = `pre-step: ${String((error && error.message) || error)}`;
      return decision;
    }
  });

  // Ingress B: tool results entering the log / model context.
  // `next()` resolves to `{ kind: "accept" }` with no `content` of its own — the
  // accepted decision only carries `content` when some listener replaces it. The
  // text to scrub therefore lives in `result.content`.
  ctx.on('tools/post-execute', async (exec, result, next) => {
    const decision = await next();
    try {
      if (!decision || decision.kind !== 'accept') return decision;
      if (pausedMs() > 0) return decision;
      if (Object.hasOwn(decision, 'value')) return decision;
      const source = decision.content !== undefined ? decision.content : (result && result.content);
      if (source === undefined) return decision;
      const [content, did] = scrubDeep(source, 'tool');
      if (!did) return decision;
      return { ...decision, content };
    } catch (error) {
      lastError = `post-execute: ${String((error && error.message) || error)}`;
      return decision;
    }
  });

  // Backstop: scrub outbound text deltas for content logged before this plugin
  // existed. Never rewrites the stored log.
  //
  // `llm/stream` is a stream waterfall: the host does `yield* stream(...)` and
  // consumes the return value as an async iterable. An `async function` here
  // returns a Promise, which kills the whole turn with
  // "yield* (intermediate value) is not async iterable" — so this listener MUST
  // be an async generator. Only `text` deltas are touched: rewriting a tool-call
  // chunk would hand the tool a placeholder instead of its real arguments.
  ctx.on('llm/stream', async function* (options, next) {
    let stream;
    try {
      stream = next();
    } catch (error) {
      lastError = `llm/stream: ${String((error && error.message) || error)}`;
      return;
    }
    if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') {
      lastError = 'llm/stream: downstream listener did not return an async iterable';
      return;
    }
    if (pausedMs() > 0 || !fileRules.outboundScrub) {
      yield* stream;
      return;
    }
    try { reloadRules(false); } catch { /* rules file is optional */ }
    if (pausedMs() > 0 || !fileRules.outboundScrub) {
      yield* stream;
      return;
    }
    let scrubbed = 0;
    for await (const chunk of stream) {
      let out = chunk;
      if (fileRules.outboundScrub && chunk && typeof chunk.text === 'string'
        && (chunk.type === 'text-delta' || chunk.type === 'reasoning-delta')) {
        try {
          const [text, changed] = scrubText(chunk.text, 'outbound');
          if (changed) { out = { ...chunk, text }; scrubbed += 1; }
        } catch (error) {
          lastError = `llm/stream: ${String((error && error.message) || error)}`;
        }
      }
      yield out;
    }
    if (scrubbed > 0) stats.outboundScrubs += scrubbed;
  });
}

/* ---------------------------------------------------------------- tools -- */

const STATUS_OUTPUT = {
  type: 'object',
  additionalProperties: false,
  properties: {
    summary: { type: 'string' },
    entries: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ph: { type: 'string', description: '上下文占位符' },
          rule: { type: 'string', description: '命中的规则 id' },
          origin: { type: 'string', description: '首次捕获来源' },
          createdAt: { type: 'string' },
          lastHitAt: { type: 'string' },
          hits: { type: 'number' },
        },
        required: ['ph', 'rule', 'createdAt', 'hits'],
      },
    },
    stats: { type: 'object' },
    dataDir: { type: 'string' },
    lastError: { type: 'string' },
    version: { type: 'string' },
  },
  required: ['summary', 'entries', 'stats', 'dataDir', 'version'],
};

const EXPORT_OUTPUT = {
  type: 'object',
  additionalProperties: false,
  properties: {
    path: { type: 'string', description: '明文文件路径（0600）' },
    note: { type: 'string' },
  },
  required: ['path', 'note'],
};

/**
 * Delete exported plaintext older than the TTL. Export files are the only
 * plaintext this plugin ever writes to disk, so they must not accumulate.
 */
function sweepExports(dir) {
  let removed = 0;
  try {
    const now = Date.now();
    for (const name of fs.readdirSync(dir)) {
      if (!name.endsWith('.txt')) continue;
      const full = path.join(dir, name);
      try {
        if (now - fs.statSync(full).mtimeMs > EXPORT_TTL_MS) { fs.unlinkSync(full); removed += 1; }
      } catch { /* raced with another sweep */ }
    }
  } catch { /* directory not created yet */ }
  if (removed > 0) {
    stats.exportCleanups += removed;
    noteAudit('export-sweep', { removed });
  }
  return removed;
}

/**
 * @param view — entry projector; defaults to the UI view (with preview). Pass
 * `entryViewForModel` for anything that can end up in model context.
 */
function snapshot(view) {
  loadVault();
  const project = typeof view === 'function' ? view : entryView;
  return {
    entries: [...vault.entries.values()]
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
      .map(project),
    stats: { ...stats, vaultEntries: vault.entries.size },
    dataDir: dataDir(),
    lastError: lastError || vault.keyError || fileRules.error || null,
  };
}

function registerTools(ctx) {
  ctx.effect(() => ctx.tools.register({
    name: 'sensitive_guard_status',
    description: '查看「敏感保护」的运行状态：保管库条目的元数据（占位符、命中规则、来源、时间、命中次数）、计数统计与错误。返回值不含任何明文字符，也不含明文片段。',
    parameters: {},
    output: {
      schema: STATUS_OUTPUT,
      render(_args, value) {
        return [{ type: 'text', text: value.summary }];
      },
    },
    async execute() {
      const snap = snapshot(entryViewForModel);
      const rules = activeRules();
      return {
        summary: `敏感保护 v${PLUGIN_VERSION}：保管库 ${snap.entries.length} 条，规则 ${rules.length} 条（内置 ${BUILTIN_RULES.length} + 自定义 ${fileRules.list.length}），累计遮挡 ${stats.maskedValues} 个值，出网补洗 ${stats.outboundScrubs} 次，失败放行 ${stats.failOpen} 次${snap.lastError ? `，最近错误：${snap.lastError}` : ''}。`,
        entries: snap.entries,
        stats: snap.stats,
        dataDir: snap.dataDir,
        lastError: snap.lastError || '',
        version: PLUGIN_VERSION,
      };
    },
  }), 'sensitive-guard: status tool');

  ctx.effect(() => ctx.tools.register({
    name: 'sensitive_guard_export',
    description: '把一条被遮挡的敏感数据（<SG_ 占位符）导出为本机 0600 权限的明文文件，供命令执行时引用（如 --password "$(cat <path>)"、source <path>）。明文只写入该文件，不会进入会话上下文。仅在确实需要用凭据执行操作时调用；每次导出都会记入审计。',
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        placeholder: { type: 'string', description: '保管库占位符，形如 <SG_012345abcdef>' },
      },
      required: ['placeholder'],
    },
    output: {
      schema: EXPORT_OUTPUT,
      render(_args, value) {
        return [{ type: 'text', text: `${value.path}\n${value.note}` }];
      },
    },
    async execute(args) {
      const ph = String((args && args.placeholder) || '').trim();
      if (!PH_EXACT.test(ph)) throw new Error(`占位符格式不正确：<SG_12位十六进制>，收到 ${ph.slice(0, 40)}`);
      loadVault();
      const hash = vault.byPh.get(ph);
      const entry = hash && vault.entries.get(hash);
      if (!entry) throw new Error('保管库中没有该占位符');
      const plaintext = decrypt(entry.enc);
      const dir = path.join(dataDir(), 'exports');
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const swept = sweepExports(dir);
      const file = path.join(dir, `${ph.slice(4, -1)}.txt`);
      fs.writeFileSync(file, plaintext, { mode: 0o600 });
      hardenFilePermissions(file);
      stats.exports += 1;
      entry.lastHitAt = new Date().toISOString();
      noteAudit('export', { ph });
      persistVault(true);
      return {
        path: file,
        note: `明文仅存在于该文件，${Math.round(EXPORT_TTL_MS / 60000)} 分钟内有效（下次导出时自动清理${swept > 0 ? `，本次已清理 ${swept} 个过期文件` : ''}）；用完也可立即删除。会话上下文里不会出现明文。每次导出都会记入审计。`,
      };
    },
  }), 'sensitive-guard: export tool');
}

/* --------------------------------------------------------------- routes -- */

function sendJson(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

/** Parse an IPv4 literal into 4 bytes; null when malformed. */
function ipv4Bytes(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    const n = Number(parts[i]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

/** Parse an IPv6 literal into 16 bytes, expanding `::` and embedded IPv4. */
function ipv6Bytes(input) {
  if (isIP(input) !== 6) return null;
  const ip = String(input);
  const gap = ip.indexOf('::');
  const head = gap === -1 ? ip : ip.slice(0, gap);
  const tail = gap === -1 ? '' : ip.slice(gap + 2);

  const groups = (part) => (part.length === 0 ? [] : part.split(':'));
  const expandV4 = (list) => {
    if (list.length === 0) return list;
    const last = list[list.length - 1];
    if (!last.includes('.')) return list;
    const b = ipv4Bytes(last);
    if (b === null) return null;
    return [...list.slice(0, -1), ((b[0] << 8) | b[1]).toString(16), ((b[2] << 8) | b[3]).toString(16)];
  };

  const h = expandV4(groups(head));
  const t = expandV4(groups(tail));
  if (h === null || t === null) return null;
  const all = gap === -1 ? h : [...h, ...new Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  if (all.length !== 8) return null;

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i += 1) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(all[i])) return null;
    const v = parseInt(all[i], 16);
    out[i * 2] = v >> 8;
    out[i * 2 + 1] = v & 0xff;
  }
  return out;
}

/** IPv4 → 4 bytes, IPv6 → 16 bytes, anything else → null. */
function ipBytes(ip) {
  return ipv4Bytes(ip) || ipv6Bytes(ip);
}

/**
 * Normalize a socket address: drop the `::ffff:` v4-mapped prefix and the
 * `%zone` suffix, so `::ffff:192.168.1.5` matches `192.168.0.0/16`.
 */
function normalizeIp(address) {
  if (typeof address !== 'string' || address.length === 0) return '';
  let ip = address;
  if (ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4) ip = ip.slice(7);
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  return ip;
}

/** `{ base, bits }` for a valid CIDR, null otherwise. `/0` is refused: it would
 *  expose the reveal routes to the whole internet, never a deliberate choice. */
function parseCidr(cidr) {
  const text = String(cidr || '').trim();
  const slash = text.lastIndexOf('/');
  if (slash === -1) return null;
  const base = normalizeIp(text.slice(0, slash));
  const bytes = ipBytes(base);
  if (bytes === null) return null;
  const bits = Number(text.slice(slash + 1));
  const max = bytes.length * 8;
  if (!Number.isInteger(bits) || bits < 1 || bits > max) return null;
  return { base: bytes, bits };
}

function cidrContains(cidr, ip) {
  const net = parseCidr(cidr);
  if (net === null) return false;
  const target = ipBytes(normalizeIp(ip));
  if (target === null || target.length !== net.base.length) return false;
  const fullBytes = Math.floor(net.bits / 8);
  for (let i = 0; i < fullBytes; i += 1) {
    if (target[i] !== net.base[i]) return false;
  }
  const rest = net.bits % 8;
  if (rest === 0) return true;
  const mask = 0xff << (8 - rest) & 0xff;
  return (target[fullBytes] & mask) === (net.base[fullBytes] & mask);
}

/**
 * How this request reached us:
 *   'loopback'   — same machine (always allowed)
 *   'lan'        — matched an explicit `allowCidrs` entry in rules.json
 *   'restricted' — non-loopback without an allowCidrs match: no plaintext, no
 *                  8-char preview, no state changes. The vault route still
 *                  answers so Settings can explain itself instead of showing a
 *                  bare "failed to load".
 *   null         — no peer address at all
 *
 * These routes emit plaintext or previews, so exposure past loopback is opt-in
 * and empty by default: the web server may bind 0.0.0.0, and without the
 * default any LAN peer could POST its way to a full secret.
 */
function accessLevel(req) {
  const ip = remoteIp(req);
  if (ip === '127.0.0.1' || ip === '::1') return 'loopback';
  if (ip.length === 0) return null;
  let list = [];
  try { reloadRules(false); list = fileRules.allowCidrs || []; } catch { list = []; }
  for (const cidr of list) {
    if (cidrContains(cidr, ip)) return 'lan';
  }
  return 'restricted';
}

function remoteIp(req) {
  return normalizeIp(req && req.socket && req.socket.remoteAddress);
}

/**
 * The narrowest block that would admit this peer, so the rejection message can
 * carry a ready-to-paste config instead of leaving the user to work it out.
 */
function suggestCidr(ip) {
  const v4 = ipv4Bytes(ip);
  if (v4 !== null) return `${v4[0]}.${v4[1]}.${v4[2]}.0/24`;
  const v6 = ipv6Bytes(ip);
  if (v6 !== null) {
    const g = [];
    for (let i = 0; i < 4; i += 1) g.push(((v6[i * 2] << 8) | v6[i * 2 + 1]).toString(16));
    return `${g.join(':')}::/64`;
  }
  return '';
}

/**
 * For non-loopback access the Host header must be an IP literal. DNS rebinding
 * needs a domain name, and `sameOriginOk` cannot tell a rebound request from a
 * real one — both send a matching Origin and Host.
 */
function hostHeaderOk(req, level) {
  if (level === 'loopback') return true;
  const raw = String(req.headers.host || '');
  if (raw.length === 0) return false;
  let name = raw;
  if (name.startsWith('[')) {
    const end = name.indexOf(']');
    if (end === -1) return false;
    name = name.slice(1, end);
  } else if (name.indexOf(':') === name.lastIndexOf(':')) {
    name = name.split(':')[0];
  }
  return normalizeIp(name).length > 0 && isIP(normalizeIp(name)) !== 0;
}

/**
 * A cross-site `text/plain` POST needs no preflight; requiring JSON forces one,
 * and this server never answers preflights. Loopback is exempt so local tools
 * keep working.
 */
function jsonPostOk(req, level) {
  if (level === 'loopback') return true;
  return /^application\/json\b/i.test(String(req.headers['content-type'] || ''));
}

/**
 * Single entry gate for the three routes. Returns the level so callers can
 * branch, or null after having already sent the rejection.
 *
 * `allowRestricted` lets the vault route answer read-only metadata to an
 * unauthorized peer (no preview, no plaintext) so the UI can explain the
 * situation. Reveal and settings keep the hard 403.
 */
function guard(req, res, { origin = false, allowRestricted = false } = {}) {
  const level = accessLevel(req);
  if (level === null) {
    sendJson(res, 403, { error: 'no-peer-address' });
    return null;
  }
  if (level === 'restricted') {
    if (allowRestricted) return level;
    sendJson(res, 403, {
      error: 'not-allowed',
      hint: '这台机器不是服务的本机：默认只允许本机回环。要在这里查看明文，二选一——在服务所在机器的浏览器打开 127.0.0.1，或在该机器 rules.json 里加 allowCidrs。',
      suggested: suggestCidr(remoteIp(req)),
      host: String(req.headers.host || ''),
    });
    return null;
  }
  if (!hostHeaderOk(req, level)) { sendJson(res, 403, { error: 'bad-host' }); return null; }
  if (origin && !sameOriginOk(req)) { sendJson(res, 403, { error: 'cross-origin' }); return null; }
  return level;
}

function sameOriginOk(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function registerRoutes(ctx) {
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: VAULT_ROUTE,
    handler: async (req, res) => {
      const level = guard(req, res, { allowRestricted: true });
      if (level === null) return;
      if (req.method !== 'GET' && req.method !== 'HEAD') { sendJson(res, 405, { error: 'method' }); return; }
      const snap = snapshot();
      // A peer outside the allowlist gets structure only: placeholders, rule
      // ids, timestamps, hit counts. `preview` is 8 plaintext characters, so it
      // is dropped — the point of the page is knowing what is protected, not
      // seeing it.
      const restricted = level === 'restricted';
      const entries = restricted
        ? snap.entries.map(({ preview, ...rest }) => rest)
        : snap.entries;
      sendJson(res, 200, {
        ok: true,
        version: PLUGIN_VERSION,
        placeholderFormat: '<SG_十六进制>',
        restricted,
        entries,
        audit: restricted ? [] : [...audit].reverse(),
        stats: snap.stats,
        dataDir: snap.dataDir,
        lastError: snap.lastError,
        outboundScrub: fileRules.outboundScrub,
        rules: { builtin: BUILTIN_RULES.length, custom: fileRules.list.length, error: fileRules.error },
        // Tells the UI whether this page is being served over LAN (allowCidrs).
        access: {
          level,
          allowCidrs: (fileRules.allowCidrs || []).slice(),
          suggested: restricted ? suggestCidr(remoteIp(req)) : null,
          host: String(req.headers.host || ''),
        },
        debug: restricted ? undefined : { pre: { ...debugPre } },
      });
    },
  }), 'sensitive-guard: vault route');

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: REVEAL_ROUTE,
    handler: async (req, res) => {
      const level = guard(req, res, { origin: true });
      if (level === null) return;
      if (req.method !== 'POST') { sendJson(res, 405, { error: 'method' }); return; }
      if (!jsonPostOk(req, level)) { sendJson(res, 403, { error: 'content-type' }); return; }
      let body;
      try { body = JSON.parse(await readBody(req, 4096) || '{}'); } catch { sendJson(res, 400, { error: 'bad-json' }); return; }
      const ph = String(body && body.placeholder || '').trim();
      if (!PH_EXACT.test(ph)) { sendJson(res, 400, { error: 'bad-placeholder' }); return; }
      loadVault();
      const hash = vault.byPh.get(ph);
      const entry = hash && vault.entries.get(hash);
      if (!entry) { sendJson(res, 404, { error: 'not-found' }); return; }
      try {
        const plaintext = decrypt(entry.enc);
        const prefix = typeof entry.prefix === 'string' ? entry.prefix : '';
        // `tail` is for the inline chip: the prefix already sits in the message
        // text, so repeating it would read as `sk-sk-…`. `plaintext` stays whole
        // for the Settings page and for export.
        const tail = prefix && plaintext.startsWith(prefix) ? plaintext.slice(prefix.length) : plaintext;
        stats.reveals += 1;
        entry.lastHitAt = new Date().toISOString();
        noteAudit('reveal', { ph });
        persistVault();
        sendJson(res, 200, { placeholder: ph, plaintext, body: tail, prefix, rule: entry.rule });
      } catch (error) {
        sendJson(res, 500, { error: String((error && error.message) || error) });
      }
    },
  }), 'sensitive-guard: reveal route');

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: SETTINGS_ROUTE,
    handler: async (req, res) => {
      const level = guard(req, res, { origin: true });
      if (level === null) return;
      const shape = () => {
        const ms = pausedMs();
        const finite = Number.isFinite(ms);
        return {
          paused: ms > 0,
          untilRestart: pause.untilRestart,
          until: finite && ms > 0 ? Date.now() + ms : null,
          remainingMs: finite ? ms : null,
        };
      };

      if (req.method === 'GET' || req.method === 'HEAD') {
        sendJson(res, 200, shape());
        return;
      }
      if (req.method !== 'POST') { sendJson(res, 405, { error: 'method' }); return; }
      if (!jsonPostOk(req, level)) { sendJson(res, 403, { error: 'content-type' }); return; }

      let body;
      try { body = JSON.parse(await readBody(req, 2048) || '{}'); } catch { sendJson(res, 400, { error: 'bad-json' }); return; }
      const action = String((body && body.action) || '');

      if (action === 'resume') {
        pause.until = 0;
        pause.untilRestart = false;
        persistPause();
        noteAudit('resume', {});
      } else if (action === 'pause') {
        if (body.untilRestart === true) {
          pause.untilRestart = true;
          pause.until = 0;
        } else {
          const minutes = Number(body.minutes);
          // Clamp: a typo must not silently disable protection for a week.
          const safe = Number.isFinite(minutes) && minutes > 0 && minutes <= 1440
            ? Math.round(minutes)
            : 30;
          pause.untilRestart = false;
          pause.until = Date.now() + safe * 60000;
        }
        persistPause();
        noteAudit('pause', { untilRestart: pause.untilRestart, until: pause.until || null });
      } else {
        sendJson(res, 400, { error: 'unknown-action' });
        return;
      }

      sendJson(res, 200, shape());
    },
  }), 'sensitive-guard: settings route');
}

/* ----------------------------------------------------------------- apply -- */

// `webServer` used to be a hard dependency of the whole plugin, so a profile
// without it silently disabled scrubbing as well. Only `tools` is required now;
// the routes attach when a web server exists.
export const inject = ['tools'];

export function apply(ctx) {
  // Host-side twin of the client guard. A throwing apply leaves the plugin half
  // registered (hooks without tools, or the reverse), which is worse than being
  // plainly off — contain it and report through status instead.
  try {
    try { reloadRules(true); } catch { /* rules file is optional */ }
    loadPause();
    attachHooks(ctx);
    registerTools(ctx);
    ctx.inject(['webServer'], (webCtx) => { registerRoutes(webCtx); });
  } catch (error) {
    lastError = `apply: ${String((error && error.message) || error)}`;
    console.warn('[sensitive-guard] host plugin disabled after error:', error && error.message);
  }
}
