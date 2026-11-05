/**
 * Self-check for dsh-sensitive-guard. Runs entirely offline against a temporary
 * data directory, so it never touches a real vault.
 *
 *   node test.mjs
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath, pathToFileURL } from 'node:url';

// fileURLToPath is the only portable way: on Windows the URL pathname is
// `/D:/…` and stripping the slash yields a relative path on POSIX hosts.
const ROOT = path.dirname(fileURLToPath(import.meta.url));
const TEMP_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-test-'));
process.env.DSH_HOME = TEMP_HOME;

let failed = 0;
function check(name, condition, detail) {
  if (condition) {
    console.log(`  ok    ${name}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${name}${detail ? `  (${detail})` : ''}`);
  }
}

const SECRET = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123';

/* ---------------------------------------------------------------- host -- */

const mod = await import(pathToFileURL(path.join(ROOT, 'index.js')).href);
const listeners = new Map();
const tools = new Map();
const routes = new Map();
const ctx = {
  on(name, fn) {
    if (!listeners.has(name)) listeners.set(name, []);
    listeners.get(name).push(fn);
  },
  effect(fn) { try { fn(); } catch { /* registration probe */ } return () => {}; },
  tools: { register(t) { tools.set(t.name, t); return () => {}; } },
  webServer: { register(r) { routes.set(r.path, r); return () => {}; } },
  inject(_deps, cb) { cb(ctx); },
};

mod.apply(ctx);

console.log('host registration');
check('inject is [tools]', JSON.stringify(mod.inject) === '["tools"]');
check('two tools registered', tools.size === 2, [...tools.keys()].join(','));
check('two routes registered', routes.size === 3, [...routes.keys()].join(','));
check('three hooks registered', listeners.size === 3, [...listeners.keys()].join(','));

const pre = listeners.get('agent/pre-step')[0];
const post = listeners.get('tools/post-execute')[0];
const streamFn = listeners.get('llm/stream')[0];

console.log('ingress');
const entered = await pre(
  { messages: [{ role: 'user', content: `我的 api key 是 ${SECRET}` }] },
  async () => ({ kind: 'enter', messages: [] }),
);
const masked = entered.messages[0].content;
check('user message masked', masked.includes('<SG_'), masked);
check('vendor prefix kept', masked.includes('sk-<SG_'), masked);
const ph = (masked.match(/<SG_[0-9a-f]{12}>/) || [])[0];

const rejected = { kind: 'reject', reason: 'blocked' };
const passedThrough = await pre({ messages: [{ content: SECRET }] }, async () => rejected);
check('reject decision untouched', passedThrough === rejected);

const posted = await post({}, { content: [{ type: 'text', text: `t=${SECRET}` }] }, async () => ({ kind: 'accept' }));
check('tool result masked', posted.content[0].text.includes('<SG_'));

const urlOut = (await pre(
  { messages: [{ content: 'https://alice123:alice123@example.com/x' }] },
  async () => ({ kind: 'enter', messages: [] }),
)).messages[0].content;
check('url password offset exact', urlOut.startsWith('https://alice123:<SG_'), urlOut);

const cliOut = (await pre(
  { messages: [{ content: 'mysql -uroot -pabc12345 -h 127.0.0.1' }] },
  async () => ({ kind: 'enter', messages: [] }),
)).messages[0].content;
check('cli password masked', cliOut.includes('<SG_'), cliOut);

const dockerText = 'docker run -p 8080:80 nginx';
const dockerOut = (await pre(
  { messages: [{ content: dockerText }] },
  async () => ({ kind: 'enter', messages: [{ content: dockerText }] }),
)).messages[0].content;
check('docker -p not mistaken for password', dockerOut === dockerText, dockerOut);

console.log('stream');
const stream = streamFn({}, () => (async function* () {
  yield { type: 'text-delta', text: SECRET };
  yield { type: 'tool-call-delta', argumentsDelta: `{"k":"${SECRET}"}` };
  yield { type: 'finish' };
})());
check('llm/stream is async iterable', typeof stream[Symbol.asyncIterator] === 'function');
const chunks = [];
for await (const c of stream) chunks.push(c);
check('text delta masked', chunks[0].text.includes('<SG_'));
check('tool call untouched', chunks[1].argumentsDelta.includes(SECRET));
check('finish passthrough', chunks[2].type === 'finish');

console.log('vault and tools');
const status = await tools.get('sensitive_guard_status').execute({});
check('status hides preview', !Object.hasOwn(status.entries[0] || {}, 'preview'));
check('status reports entries', status.entries.length >= 1);

const exported = await tools.get('sensitive_guard_export').execute({ placeholder: ph });
check('export writes plaintext file', fs.readFileSync(exported.path, 'utf8') === SECRET);
fs.unlinkSync(exported.path);

console.log('routes');
function fakeRes() {
  return { status: 0, body: '', writeHead(c) { this.status = c; }, end(b) { this.body = String(b || ''); } };
}
const reveal = routes.get('/guard/reveal');
const lan = fakeRes();
await reveal.handler({ method: 'POST', socket: { remoteAddress: '203.0.113.9' }, headers: { host: 'localhost:3080' } }, lan);
check('non-loopback rejected', lan.status === 403);

const local = fakeRes();
await reveal.handler(Object.assign(Readable.from([Buffer.from(JSON.stringify({ placeholder: ph }))]), {
  method: 'POST', socket: { remoteAddress: '127.0.0.1' }, headers: { host: 'localhost:3080' },
}), local);
const revealed = JSON.parse(local.body || '{}');
check('loopback reveal returns plaintext', revealed.plaintext === SECRET);
check('reveal splits body and prefix', revealed.prefix === 'sk-' && revealed.body === SECRET.slice(3));

console.log('pause switch');
const settings = routes.get('/guard/settings');
async function postSettings(payload) {
  const res = fakeRes();
  await settings.handler(Object.assign(Readable.from([Buffer.from(JSON.stringify(payload))]), {
    method: 'POST', socket: { remoteAddress: '127.0.0.1' }, headers: { host: 'localhost:3080' },
  }), res);
  return { status: res.status, body: JSON.parse(res.body || '{}') };
}

const idle = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '127.0.0.1' }, headers: { host: 'localhost:3080' } }, idle);
check('starts unpaused', JSON.parse(idle.body).paused === false);

const pausedState = (await postSettings({ action: 'pause', minutes: 30 })).body;
check('pause returns remaining time', pausedState.paused === true && pausedState.remainingMs > 1700000, JSON.stringify(pausedState));

const duringPause = (await pre(
  { messages: [{ content: `key ${SECRET}` }] },
  async () => ({ kind: 'enter', messages: [{ content: `key ${SECRET}` }] }),
)).messages[0].content;
check('masking suspended while paused', duringPause === `key ${SECRET}`, duringPause);

const resumed = (await postSettings({ action: 'resume' })).body;
check('resume clears pause', resumed.paused === false, JSON.stringify(resumed));

const afterResume = (await pre(
  { messages: [{ content: `key ${SECRET}` }] },
  async () => ({ kind: 'enter', messages: [] }),
)).messages[0].content;
check('masking back after resume', afterResume.includes('<SG_'), afterResume);

const lanToggle = fakeRes();
await settings.handler({ method: 'POST', socket: { remoteAddress: '203.0.113.9' }, headers: { host: 'localhost:3080' } }, lanToggle);
check('settings route is loopback-only', lanToggle.status === 403);

/* -------------------------------------------------------------- client -- */

console.log('client');
const React = {
  createElement: () => null,
  Fragment: 'Fragment',
  useState: () => [null, () => {}],
  useEffect: () => {},
  useRef: () => ({ current: 0 }),
  useCallback: (fn) => fn,
};
let api = null;
globalThis.window = { __ModuleLoader__: { load(def) { api = def.factory((n) => (n === 'react' ? React : {})); } } };
globalThis.fetch = async () => ({ ok: false, status: 404, json: async () => ({}) });

const clientSrc = fs.readFileSync(path.join(ROOT, 'client.js'), 'utf8');
new Function('window', 'globalThis', clientSrc).call(globalThis, globalThis.window, globalThis);
check('client module exposes apply', api && typeof api.apply === 'function');

const registered = [];
const slots = {
  inject(_name, factory) {
    const it = factory();
    if (it && typeof it.next === 'function') { let s = it.next(); while (!s.done) s = it.next(); }
  },
  register(options) { registered.push(options); return () => {}; },
};
const strictCtx = new Proxy({ slots, effect: () => () => {} }, {
  get(target, prop) { if (prop in target) return target[prop]; throw new Error(`no ${String(prop)}`); },
});
let threw = null;
try { api.apply(strictCtx); } catch (error) { threw = error; }
check('client apply never throws on missing services', threw === null, threw && threw.message);

const fullCtx = new Proxy({
  slots,
  effect: () => () => {},
  locale: { register: () => () => {}, bind: () => (k) => k },
  get: (name) => (name === 'uiConversation' ? { userText: { register: () => {} } } : undefined),
  inject: (_deps, cb) => cb({ uiConversation: { userText: { register: () => {} } } }),
}, {
  get(target, prop) { if (prop in target) return target[prop]; throw new Error(`no ${String(prop)}`); },
});
api.apply(fullCtx);
check('inline renderer uses keyed registration', registered.some((r) => r.key === 'sensitive-guard'));

/* ------------------------------------------------------------ behaviour -- */

console.log('performance');
const plain = `${'x'.repeat(300000)}`;
let started = performance.now();
await pre({ messages: [{ content: plain }] }, async () => ({ kind: 'enter', messages: [] }));
const scanMs = performance.now() - started;
check('300k chars scanned under 400ms', scanMs < 400, `${scanMs.toFixed(0)}ms`);

const many = Array.from({ length: 2000 }, () => SECRET).join(' ');
started = performance.now();
await pre({ messages: [{ content: many }] }, async () => ({ kind: 'enter', messages: [] }));
const maskMs = performance.now() - started;
check('2000 secrets masked under 800ms', maskMs < 800, `${maskMs.toFixed(0)}ms`);

console.log('entropy (opt-in)');
// Base64-ish blob: ~4.9 bits/char. A pure hex string caps at 4.0 bits and can
// therefore never reach the default 4.5 threshold — documented in README.
const blob = 'Zx9Kp2Qm7Rt4Wv1Yb6Nc3Ld8Fg5Hs0Jk';
const blobText = `value ${blob} end`;
const beforeEntropy = (await pre(
  { messages: [{ content: blobText }] },
  async () => ({ kind: 'enter', messages: [{ content: blobText }] }),
)).messages[0].content;
check('off by default', beforeEntropy.includes(blob), beforeEntropy);

fs.writeFileSync(
  path.join(TEMP_HOME, 'sensitive-guard', 'rules.json'),
  JSON.stringify({ entropy: true }),
);
await new Promise((r) => setTimeout(r, 2200));
const afterEntropy = (await pre(
  { messages: [{ content: blobText }] },
  async () => ({ kind: 'enter', messages: [{ content: blobText }] }),
)).messages[0].content;
check('enabled through rules.json', afterEntropy.includes('<SG_'), afterEntropy);

/* ------------------------------------------------------- lan allowlist -- */

console.log('lan allowlist');

// Loopback must stay allowed regardless of what the allowlist says.
const stillLocal = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '::ffff:127.0.0.1' }, headers: { host: '127.0.0.1:3080' } }, stillLocal);
check('v4-mapped loopback still allowed', stillLocal.status === 200, String(stillLocal.status));

// Still closed before the allowlist is configured for this read.
const closedFirst = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '198.51.100.10' }, headers: { host: '198.51.100.10:3080' } }, closedFirst);
check('lan closed by default', closedFirst.status === 403, String(closedFirst.status));

fs.writeFileSync(
  path.join(TEMP_HOME, 'sensitive-guard', 'rules.json'),
  JSON.stringify({ entropy: true, allowCidrs: ['198.51.100.0/24', '203.0.113.200/32', '::1/128'] }),
);
await new Promise((r) => setTimeout(r, 2200));

const allowed = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '198.51.100.10' }, headers: { host: '198.51.100.10:3080' } }, allowed);
check('allowCidrs opens /16', allowed.status === 200, String(allowed.status));

const mapped = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '::ffff:198.51.100.78' }, headers: { host: '198.51.100.10:3080' } }, mapped);
check('v4-mapped lan address matched', mapped.status === 200, String(mapped.status));

const exactHost = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '203.0.113.200' }, headers: { host: '203.0.113.200:3080' } }, exactHost);
check('/32 matches only its own address', exactHost.status === 200, String(exactHost.status));

const outside = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '203.0.113.250' }, headers: { host: '203.0.113.250:3080' } }, outside);
check('address outside allowCidrs rejected', outside.status === 403, String(outside.status));

const wrongSubnet = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '203.0.113.201' }, headers: { host: '203.0.113.201:3080' } }, wrongSubnet);
check('/32 does not leak into /24', wrongSubnet.status === 403, String(wrongSubnet.status));

// DNS rebinding: an allowed client, but Host is a domain name, not an IP.
const rebound = fakeRes();
await settings.handler({ method: 'GET', socket: { remoteAddress: '198.51.100.78' }, headers: { host: 'evil.example.com:3080' } }, rebound);
check('rebound host header rejected', rebound.status === 403 && JSON.parse(rebound.body).error === 'bad-host', rebound.body);

// Cross-site `text/plain` POST needs no preflight; JSON does.
const plainPost = fakeRes();
await settings.handler(Object.assign(Readable.from([Buffer.from('{"action":"pause","minutes":30}')]), {
  method: 'POST',
  socket: { remoteAddress: '198.51.100.10' },
  headers: { host: '198.51.100.10:3080', origin: 'http://198.51.100.10:3080', 'content-type': 'text/plain' },
}), plainPost);
check('lan POST must be json content-type', plainPost.status === 403 && JSON.parse(plainPost.body).error === 'content-type', plainPost.body);

const lanReveal = fakeRes();
await reveal.handler(Object.assign(Readable.from([Buffer.from(JSON.stringify({ placeholder: ph }))]), {
  method: 'POST',
  socket: { remoteAddress: '198.51.100.10' },
  headers: { host: '198.51.100.10:3080', origin: 'http://198.51.100.10:3080', 'content-type': 'application/json; charset=utf-8' },
}), lanReveal);
const lanPayload = JSON.parse(lanReveal.body || '{}');
check('lan reveal works with json', lanReveal.status === 200 && lanPayload.plaintext === SECRET, lanReveal.body.slice(0, 120));

const vaultRoute = routes.get('/guard/vault');
const exposure = fakeRes();
await vaultRoute.handler({ method: 'GET', socket: { remoteAddress: '198.51.100.10' }, headers: { host: '198.51.100.10:3080' } }, exposure);
const exposureBody = JSON.parse(exposure.body || '{}');
check('vault reports access level', exposureBody.access && exposureBody.access.level === 'lan', JSON.stringify(exposureBody.access));

// `/0` would expose the routes to the whole internet; it must be dropped and
// reported, not silently honoured.
fs.writeFileSync(
  path.join(TEMP_HOME, 'sensitive-guard', 'rules.json'),
  JSON.stringify({ allowCidrs: ['0.0.0.0/0', '198.51.100.0/24'] }),
);
await new Promise((r) => setTimeout(r, 2200));
const wild = fakeRes();
await vaultRoute.handler({ method: 'GET', socket: { remoteAddress: '203.0.113.99' }, headers: { host: '203.0.113.99:3080' } }, wild);
const wildBody = JSON.parse(wild.body || '{}');
check('/0 is refused (degraded to read-only)', wild.status === 200 && wildBody.restricted === true, `${wild.status} ${wildBody.restricted}`);
const wildReport = fakeRes();
await vaultRoute.handler({ method: 'GET', socket: { remoteAddress: '198.51.100.10' }, headers: { host: '198.51.100.10:3080' } }, wildReport);
const wildReportBody = JSON.parse(wildReport.body || '{}');
check('rejected cidr is reported', wildReport.status === 200 && String(wildReportBody.rules.error || '').includes('0.0.0.0/0'), String(wildReportBody.rules.error));

/* -------------------------------------------------------- read-only mode -- */

console.log('read-only degradation');

// 203.0.113.99 is outside the allowlist: metadata yes, preview no, reveal no.
const metaOnly = fakeRes();
await vaultRoute.handler({ method: 'GET', socket: { remoteAddress: '203.0.113.99' }, headers: { host: '203.0.113.99:3080' } }, metaOnly);
const metaBody = JSON.parse(metaOnly.body || '{}');
check('restricted keeps structure', metaOnly.status === 200 && metaBody.entries.length > 0, String(metaBody.entries.length));
check('restricted drops preview', metaBody.entries.every((e) => !('preview' in e)), JSON.stringify(metaBody.entries[0] || {}));
check('restricted drops audit', Array.isArray(metaBody.audit) && metaBody.audit.length === 0);
check('restricted suggests a cidr', metaBody.access.suggested === '203.0.113.0/24', String(metaBody.access.suggested));
check('restricted reports host', metaBody.access.host === '203.0.113.99:3080', String(metaBody.access.host));

const metaReveal = fakeRes();
await reveal.handler(Object.assign(Readable.from([Buffer.from(JSON.stringify({ placeholder: ph }))]), {
  method: 'POST',
  socket: { remoteAddress: '203.0.113.99' },
  headers: { host: '203.0.113.99:3080', 'content-type': 'application/json' },
}), metaReveal);
const metaRevealBody = JSON.parse(metaReveal.body || '{}');
check('restricted reveal still refused', metaReveal.status === 403 && metaRevealBody.error === 'not-allowed', metaReveal.body.slice(0, 80));
check('refusal carries the fix', String(metaRevealBody.suggested) === '203.0.113.0/24', String(metaRevealBody.suggested));

const metaToggle = fakeRes();
await settings.handler({ method: 'POST', socket: { remoteAddress: '203.0.113.99' }, headers: { host: '203.0.113.99:3080', 'content-type': 'application/json' } }, metaToggle);
check('restricted cannot toggle pause', metaToggle.status === 403, String(metaToggle.status));

const allowedPreview = fakeRes();
await vaultRoute.handler({ method: 'GET', socket: { remoteAddress: '198.51.100.10' }, headers: { host: '198.51.100.10:3080' } }, allowedPreview);
const allowedBody = JSON.parse(allowedPreview.body || '{}');
check('allowlisted peer still sees preview', allowedBody.restricted === false && allowedBody.entries.some((e) => 'preview' in e), JSON.stringify(allowedBody.entries[0] || {}));

/* --------------------------------------------------- wrapped / soft wrap -- */

console.log('wrapped key');

const runPre = async (text) => {
  const decision = await pre(
    { messages: [{ content: text }] },
    async () => ({ kind: 'enter', messages: [] }),
  );
  // Unchanged text comes back as the mock's empty array; treat that as "as-is".
  return decision.messages.length ? decision.messages[0].content : text;
};

const cleanOut = await runPre('我的 api key 是 sk-proj-abcdefghijklmnopqrstuvwx');
const cleanPh = (cleanOut.match(/<SG_[0-9a-f]{12}>/) || [])[0];
check('完整 key 正常遮挡', Boolean(cleanPh) && cleanOut.startsWith('我的 api key 是 sk-'), cleanOut);

const crlfOut = await runPre('我的 api key 是 sk-\r\nproj-abcdefghijklmnopqrstuvwx');
check('CRLF 打断的 key 能识别', /sk-<SG_[0-9a-f]{12}>$/.test(crlfOut) && !crlfOut.includes('proj-'), JSON.stringify(crlfOut));
check('换行版复用同一个占位符', crlfOut.includes(cleanPh), `${crlfOut} vs ${cleanPh}`);

const crOut = await runPre('我的 api key 是 sk-\rproj-abcdefghijklmnopqrstuvwx');
check('纯 CR 打断的 key 能识别', /sk-<SG_[0-9a-f]{12}>$/.test(crOut), JSON.stringify(crOut));

const proseOut = await runPre('第一行文字\n第二行文字继续');
check('普通换行不误伤', proseOut === '第一行文字\n第二行文字继续', JSON.stringify(proseOut));

/* ------------------------------------------------ short password floor -- */

console.log('password floor');

const six = await runPre('我的密码是 123456');
check('中文语境 6 位密码也拦', /我的密码是 <SG_[0-9a-f]{12}>$/.test(six), JSON.stringify(six));

const five = await runPre('我的密码是 12345');
check('5 位仍不拦', five === '我的密码是 12345', JSON.stringify(five));

const english = await runPre('the secret is hidden');
check('英文句子里 6 字单词不误伤', english === 'the secret is hidden', JSON.stringify(english));

// A trailing particle must stay outside the placeholder, and all spellings of
// the same secret must share one hash — otherwise export hands back "123456吗".
const withSpace = await runPre('我的密码是 123456 吗?');
const noSpace = await runPre('我的密码是123456吗');
const fullComma = await runPre('我的密码是123456，对吗');
const bare = await runPre('密码是 123456 吗');
check('语气词留在占位符外（有空格）', withSpace === '我的密码是 <SG_8d969eef6eca> 吗?', withSpace);
check('语气词留在占位符外（无空格）', noSpace === '我的密码是<SG_8d969eef6eca>吗', noSpace);
check('全角逗号切断取值', fullComma === '我的密码是<SG_8d969eef6eca>，对吗', fullComma);
check('四种写法共用同一占位符', new Set([withSpace, noSpace, fullComma, bare].map((s) => (s.match(/<SG_[0-9a-f]{12}>/) || [''])[0])).size === 1);
check('句尾问号不被吞进密码', (await runPre('我的密码是 abcdef?')).endsWith('<SG_') === false);

/* --------------------------------------------------------------------- */

fs.rmSync(TEMP_HOME, { recursive: true, force: true });
console.log(failed === 0 ? '\nall checks passed' : `\n${failed} check(s) failed`);
process.exit(failed === 0 ? 0 : 1);
