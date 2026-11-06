/**
 * Self-check for dsh-sensitive-guard. Runs entirely offline against a temporary
 * data directory, so it never touches a real vault.
 *
 *   node test.mjs
 */
import { execFileSync } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
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
check('five routes registered', routes.size === 5, [...routes.keys()].join(','));
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

console.log('persistent disable switch');
const pausePath = path.join(TEMP_HOME, 'sensitive-guard', 'pause.json');
const disabledState = (await postSettings({ action: 'disable' })).body;
check('关闭保护返回 off 且没有到期时间',
  disabledState.off === true && disabledState.paused === true && disabledState.remainingMs === null,
  JSON.stringify(disabledState));

const duringDisable = (await pre(
  { messages: [{ content: `key ${SECRET}` }] },
  async () => ({ kind: 'enter', messages: [{ content: `key ${SECRET}` }] }),
)).messages[0].content;
check('关闭期间明文原样进入上下文', duringDisable === `key ${SECRET}`, duringDisable);
check('关闭状态写进 pause.json', JSON.parse(fs.readFileSync(pausePath, 'utf8')).off === true);

const whileOff = (await postSettings({ action: 'resume' })).body;
check('resume 不会误解除持久关闭', whileOff.off === true && whileOff.paused === true, JSON.stringify(whileOff));
const pauseWhileOff = (await postSettings({ action: 'pause', minutes: 30 })).body;
check('限时暂停不会覆盖持久关闭', pauseWhileOff.off === true, JSON.stringify(pauseWhileOff));

// A fresh process re-reads pause.json from disk: this is the actual restart
// behaviour, not a simulation of the in-memory flag.
const restartProbe = [
  "import { Readable } from 'node:stream';",
  "const mod = await import(process.argv[1]);",
  "const listeners = new Map(); const routes = new Map();",
  "const ctx = { on(n,f){ if(!listeners.has(n)) listeners.set(n,[]); listeners.get(n).push(f); },",
  "  effect(fn){ try{fn()}catch{} return ()=>{}; }, tools:{register:()=>()=>{}},",
  "  webServer:{register(r){ routes.set(r.path,r); return ()=>{}; }}, inject(_d,cb){cb(ctx);} };",
  "mod.apply(ctx);",
  "const pre = listeners.get('agent/pre-step')[0];",
  "const raw = 'key ' + process.argv[2];",
  "const d = await pre({messages:[{content:raw}]}, async()=>({kind:'enter',messages:[{content:raw}]}));",
  "const text = d.messages.length ? d.messages[0].content : raw;",
  "const res={status:0,body:'',writeHead(c){this.status=c;},end(b){this.body=String(b||'');}};",
  "await routes.get('/guard/settings').handler({method:'GET',socket:{remoteAddress:'127.0.0.1'},headers:{host:'localhost:3080'}}, res);",
  "process.stdout.write(JSON.stringify({ masked: text.includes('<SG_'), state: JSON.parse(res.body||'{}') }));",
].join('\n');
const restarted = JSON.parse(execFileSync(process.execPath, [
  '--input-type=module', '-e', restartProbe,
  pathToFileURL(path.join(ROOT, 'index.js')).href, SECRET,
], { env: { ...process.env, DSH_HOME: TEMP_HOME }, encoding: 'utf8' }));
check('重启后 off 仍然生效', restarted.state.off === true && restarted.state.paused === true,
  JSON.stringify(restarted.state));
check('重启后仍然不遮挡', restarted.masked === false, JSON.stringify(restarted));

const enabled = (await postSettings({ action: 'enable' })).body;
check('开启保护清除 off', enabled.off === false && enabled.paused === false, JSON.stringify(enabled));
const afterEnable = (await pre(
  { messages: [{ content: `key ${SECRET}` }] },
  async () => ({ kind: 'enter', messages: [{ content: `key ${SECRET}` }] }),
)).messages[0].content;
check('重新开启后恢复遮挡', afterEnable.includes('<SG_'), afterEnable);
const savedOn = JSON.parse(fs.readFileSync(pausePath, 'utf8'));
check('恢复后写盘清除 off', savedOn.off === false && savedOn.until === 0, JSON.stringify(savedOn));

const lanDisable = fakeRes();
await settings.handler(Object.assign(Readable.from([Buffer.from(JSON.stringify({ action: 'disable' }))]), {
  method: 'POST', socket: { remoteAddress: '203.0.113.9' }, headers: { host: 'localhost:3080' },
}), lanDisable);
check('非本机来源不能关闭保护', lanDisable.status === 403, String(lanDisable.status));
check('未知 action 返回 400', (await postSettings({ action: 'status-probe' })).status === 400);
check('被拒绝后仍然是开启状态', JSON.parse(fs.readFileSync(pausePath, 'utf8')).off === false);

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

/**
 * Render both tabs through a React stub that actually calls function
 * components. Catches runtime errors in the new settings UI (undefined.map,
 * bad hook order, missing dictionary keys) that `api.apply` alone cannot.
 */
const fakeVault = {
  entries: [{
    ph: '<SG_aaaaaaaaaaaa>', name: '测试口令', preview: 'dsh-desk…',
    label: '公司内部凭据', rule: 'manual', createdAt: '2026-11-06T09:00:00.000Z',
    hits: 1, pinned: true,
  }],
  access: { level: 'loopback' }, stats: {}, rules: {},
};
function renderSettingsTab(forcedTab, opts = {}) {
  let stateIndex = 0;
  const ReactStub = {
    createElement: (type, props, ...children) => (
      typeof type === 'function' ? type({ ...(props || {}), children }) : { type, props, children }
    ),
    Fragment: 'Fragment',
    useState: (initial) => {
      stateIndex += 1;
      let value = forcedTab === 'rules' && stateIndex === 6 ? 'rules' : initial;
      if (opts.forceRows && stateIndex === 1) value = fakeVault;
      if (opts.forceForm && value === false) value = true;
      if (opts.forceCustom && value === '密码') value = '__custom__';
      return [value, () => {}];
    },
    useEffect: () => {},
    useRef: () => ({ current: 0 }),
    useCallback: (fn) => fn,
  };
  let localApi = null;
  const win = { __ModuleLoader__: { load(def) { localApi = def.factory((n) => (n === 'react' ? ReactStub : {})); } } };
  const captured = [];
  const localSlots = {
    inject(_name, factory) {
      const it = factory();
      if (it && typeof it.next === 'function') { let s = it.next(); while (!s.done) s = it.next(); }
    },
    register(options, renderer) { captured.push({ options, renderer }); return () => {}; },
  };
  const stubCtx = new Proxy({
    slots: localSlots,
    effect: () => () => {},
    locale: { register: () => () => {}, bind: () => (k) => k },
    get: (name) => (name === 'uiConversation' ? { userText: { register: () => {} } } : undefined),
    inject: (_deps, cb) => cb({ uiConversation: { userText: { register: () => {} } } }),
  }, { get(t, p) { return p in t ? t[p] : undefined; } });
  new Function('window', 'globalThis', clientSrc).call(globalThis, win, globalThis);
  localApi.apply(stubCtx);
  const section = captured.find((c) => c.options && c.options.name === 'settings.section');
  if (!section) throw new Error('settings renderer missing');
  return section.renderer();
}
const renderCases = [
  ['entries 标签', 'entries', {}],
  ['rules 标签', 'rules', {}],
  ['添加敏感数据弹窗', 'entries', { forceForm: true }],
  ['自定义分类弹窗', 'entries', { forceForm: true, forceCustom: true }],
  ['列表行与复制按钮', 'entries', { forceRows: true }],
];
for (const [name, tabName, opts] of renderCases) {
  let thrown = null;
  try { renderSettingsTab(tabName, opts); } catch (error) { thrown = error; }
  check(`设置页 ${name} 渲染不抛错`, thrown === null, thrown && thrown.message);
}
// forceForm also flips confirmDisable to true, so the modal is covered above.
check('设置页含关闭保护入口与确认弹窗',
  ["action: 'disable'", "action: 'enable'", 'statusDisabled', 'disableTitle', 'function DisableConfirm']
    .every((key) => clientSrc.includes(key)));

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
const particlePh = (withSpace.match(/<SG_[0-9a-f]{12}>/) || [])[0];
check('语气词留在占位符外（有空格）', withSpace === `我的密码是 ${particlePh} 吗?`, withSpace);
check('语气词留在占位符外（无空格）', noSpace === `我的密码是${particlePh}吗`, noSpace);
check('全角逗号切断取值', fullComma === `我的密码是${particlePh}，对吗`, fullComma);
check('四种写法共用同一占位符', new Set([withSpace, noSpace, fullComma, bare].map((s) => (s.match(/<SG_[0-9a-f]{12}>/) || [''])[0])).size === 1);
check('句尾问号不被吞进密码', (await runPre('我的密码是 abcdef?')).endsWith('<SG_') === false);

/* --------------------------------------------------- structured fields -- */

console.log('structured fields');

const jsonOne = await runPre('{"host":"db.internal","password":"Abc!23456","note":"hello"}');
check('JSON 文本：字段名说了算', /"password"\s*:\s*"<SG_[0-9a-f]{12}>"/.test(jsonOne), JSON.stringify(jsonOne));
check('JSON 文本：键名与别的值不变', jsonOne.includes('"host":"db.internal"') && jsonOne.includes('"note":"hello"'), JSON.stringify(jsonOne));

for (const [name, text] of [
  ['credential', '{"credential": "9f8e7d6c5b4a3210"}'],
  ['db_pass', '{"db_pass": "Abc!23456"}'],
  ['HTTP 头式字段名', '{"X-Auth-Credential": "9f8e7d6c5b4a3210"}'],
  ['带后缀的字段名', '{"password_hash": "9f8e7d6c5b4a3210"}'],
]) {
  const out = await runPre(text);
  check(`JSON 文本：${name}`, /<SG_[0-9a-f]{12}>/.test(out), JSON.stringify(out));
}

for (const [name, text] of [
  ['示例占位', '{"password": "your_password_here"}'],
  ['模板变量', '{"password": "${DB_PASS}"}'],
  ['尖括号占位', '{"token": "<your-token>"}'],
  ['字段名是描述', '{"password_policy": "must be 8 chars"}'],
]) {
  const out = await runPre(text);
  check(`JSON 文本不误伤：${name}`, out === text, JSON.stringify(out));
}

const obj = { password: 'Abc!23456', db_pass: 'Zx9Kp2', credential: '9f8e7d6c', note: 'hello' };
const objOut = await runPre(obj);
check('已解析对象：敏感字段的值被遮', ['password', 'db_pass', 'credential'].every((k) => /^<SG_[0-9a-f]{12}>$/.test(objOut[k])), JSON.stringify(objOut));
check('已解析对象：键名全保留', Object.keys(objOut).join(',') === Object.keys(obj).join(','), JSON.stringify(Object.keys(objOut)));
check('已解析对象：普通值不变', objOut.note === 'hello', JSON.stringify(objOut));

const exampleJson = '{"password": "Abc!23456"}';
const exampleStream = streamFn({}, () => (async function* () { yield { type: 'text-delta', text: exampleJson }; })());
const exampleChunks = [];
for await (const c of exampleStream) exampleChunks.push(c.text);
check('模型输出的示例 JSON 不被改写', exampleChunks[0] === exampleJson, JSON.stringify(exampleChunks));

console.log('placeholder hardening');
const shortOut = await runPre('我的密码是 123456');
const shortPh = (shortOut.match(/<SG_[0-9a-f]{12}>/) || [])[0];
check('占位符不是 sha256(明文) 前缀', Boolean(shortPh) && !shortPh.includes(createHash('sha256').update('123456').digest('hex').slice(0, 12)), shortPh);
const vaultKey = fs.readFileSync(path.join(TEMP_HOME, 'sensitive-guard', 'vault.key'));
const expectedPh = `<SG_${createHmac('sha256', vaultKey).update('123456').digest('hex').slice(0, 12)}>`;
check('占位符 = HMAC(vault.key, 明文)', shortPh === expectedPh, `${shortPh} vs ${expectedPh}`);
check('同一明文仍是同一占位符', (await runPre('我的密码是 123456')).includes(shortPh));

console.log('vault aliases');
const aliasRes = fakeRes();
await routes.get('/guard/vault').handler({ method: 'GET', socket: { remoteAddress: '127.0.0.1' }, headers: { host: 'localhost:3080' } }, aliasRes);
const aliasBody = JSON.parse(aliasRes.body || '{}');
check('保管库条目带 aliases 字段', Array.isArray((aliasBody.entries[0] || {}).aliases), JSON.stringify(aliasBody.entries[0] || {}));

/* ------------------------------------------------- upgrade from 0.3.x -- */

console.log('legacy placeholder upgrade');
const legacySecret = '123456';
const legacyPh = `<SG_${createHash('sha256').update(legacySecret).digest('hex').slice(0, 12)}>`;
const legacyHash = createHash('sha256').update(legacySecret).digest('hex').slice(0, 12);
// Vault writes are debounced by 250ms; let the capture above reach disk before
// rewriting the entry to its 0.3.x shape.
await new Promise((r) => setTimeout(r, 400));
const vaultPath = path.join(TEMP_HOME, 'sensitive-guard', 'vault.json');
const vaultRaw = JSON.parse(fs.readFileSync(vaultPath, 'utf8'));
const legacyEntry = vaultRaw.entries.find((e) => e.hash === legacyHash);
if (legacyEntry) {
  // Pretend this entry was written by 0.3.4: old sha256 code, no aliases.
  legacyEntry.ph = legacyPh;
  legacyEntry.aliases = [];
  fs.writeFileSync(vaultPath, JSON.stringify({ version: 1, entries: vaultRaw.entries }));
  const probe = [
    "import { Readable } from 'node:stream';",
    "const mod = await import(process.argv[1]);",
    "const listeners = new Map(); const routes = new Map();",
    "const ctx = { on(n,f){ if(!listeners.has(n)) listeners.set(n,[]); listeners.get(n).push(f); },",
    "  effect(fn){ try{fn()}catch{} return ()=>{}; }, tools:{register:()=>()=>{}},",
    "  webServer:{register(r){ routes.set(r.path,r); return ()=>{}; }}, inject(_d,cb){cb(ctx);} };",
    "mod.apply(ctx);",
    "const pre = listeners.get('agent/pre-step')[0];",
    "const d = await pre({messages:[{content:'我的密码是 123456'}]}, async()=>({kind:'enter',messages:[]}));",
    "const text = d.messages.length ? d.messages[0].content : '我的密码是 123456';",
    "const neu = (text.match(/<SG_[0-9a-f]{12}>/)||[])[0] || '';",
    "const reveal = routes.get('/guard/reveal');",
    "async function ask(ph){ const res={status:0,body:'',writeHead(c){this.status=c;},end(b){this.body=String(b||'');}};",
    "  await reveal.handler(Object.assign(Readable.from([Buffer.from(JSON.stringify({placeholder:ph}))]), {",
    "    method:'POST', socket:{remoteAddress:'127.0.0.1'}, headers:{host:'localhost:3080','content-type':'application/json'} }), res);",
    "  return {status:res.status, plaintext:(JSON.parse(res.body||'{}')).plaintext}; }",
    "const old = await ask(process.argv[2]);",
    "const fresh = await ask(neu);",
    "process.stdout.write(JSON.stringify({ neu, old, fresh }));",
  ].join('\n');
  const stdout = execFileSync(process.execPath, [
    '--input-type=module', '-e', probe,
    pathToFileURL(path.join(ROOT, 'index.js')).href, legacyPh,
  ], { env: { ...process.env, DSH_HOME: TEMP_HOME }, encoding: 'utf8' });
  const upgraded = JSON.parse(stdout);
  check('升级后新代号不再是旧哈希', upgraded.neu !== legacyPh && /^<SG_[0-9a-f]{12}>$/.test(upgraded.neu), upgraded.neu);
  check('旧会话里的代号仍能解锁', upgraded.old.status === 200 && upgraded.old.plaintext === legacySecret, JSON.stringify(upgraded.old));
  check('新代号也能解锁同一条', upgraded.fresh.status === 200 && upgraded.fresh.plaintext === legacySecret, JSON.stringify(upgraded.fresh));
} else {
  check('找到用于升级测试的 vault 条目', false, `missing ${legacySecret} in ${vaultRaw.entries.map((e) => e.hash).join(',')}`);
}

/* --------------------------------------------------- gitleaks catalog -- */

console.log('gitleaks catalog');
const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'rules', 'gitleaks.json'), 'utf8'));
check('目录统计 222 / 221 / 1 跳过',
  catalog.total === 222 && catalog.compiled === 221 && catalog.skipped.length === 1,
  JSON.stringify({ total: catalog.total, compiled: catalog.compiled, skipped: catalog.skipped.length }));
check('跳过的是 pkcs12-file', Boolean(catalog.skipped[0]) && catalog.skipped[0].id === 'pkcs12-file');
let compileFailures = 0;
for (const rule of catalog.rules) {
  try { new RegExp(rule.regex, rule.flags); } catch { compileFailures += 1; }
}
check('221 条正则全部能编译', compileFailures === 0, String(compileFailures));
const tiers = { core: 0, approx: 0, loose: 0 };
for (const rule of catalog.rules) tiers[rule.tier] += 1;
check('分级合计 221', tiers.core + tiers.approx + tiers.loose === 221, JSON.stringify(tiers));
check('approx 10 条、loose 至少 1 条', tiers.approx === 10 && tiers.loose >= 1, JSON.stringify(tiers));
check('只有 core 默认开', catalog.rules.every((r) => r.defaultOn === (r.tier === 'core')));
check('221 条都带 keywords 预筛', catalog.rules.every((r) => Array.isArray(r.keywords) && r.keywords.length > 0));
check('NOTICE 含 MIT 版权声明', fs.readFileSync(path.join(ROOT, 'NOTICE'), 'utf8').includes('Copyright (c) 2019 Zachary Rice'));

async function callRoute(routePath, method, payload, remote = '127.0.0.1') {
  const res = fakeRes();
  const req = payload === undefined
    ? { method, socket: { remoteAddress: remote }, headers: { host: 'localhost:3080' } }
    : Object.assign(Readable.from([Buffer.from(JSON.stringify(payload))]), {
      method, socket: { remoteAddress: remote },
      headers: { host: 'localhost:3080', 'content-type': 'application/json' },
    });
  await routes.get(routePath).handler(req, res);
  return { status: res.status, body: JSON.parse(res.body || '{}') };
}

const rulesGet = await callRoute('/guard/rules', 'GET');
check('规则页返回 221 条 + 1 条跳过',
  rulesGet.status === 200 && rulesGet.body.compiled === 221 && rulesGet.body.skipped.length === 1,
  JSON.stringify(rulesGet.body).slice(0, 130));
check('规则页含内置规则', rulesGet.body.rules.some((r) => r.source === 'builtin'));
check('规则页含 1Password Secret Key', rulesGet.body.rules.some((r) => r.name === '1Password Secret Key'));
const approxRule = rulesGet.body.rules.find((r) => r.tier === 'approx');
check('approx 规则默认关', Boolean(approxRule) && approxRule.enabled === false, approxRule && approxRule.id);
check('规则页分页大小 20', rulesGet.body.pageSize === 20);

const ageKey = 'AGE-SECRET-KEY-1' + 'Q'.repeat(58);
const ageBefore = await runPre(`key ${ageKey}`);
check('core 规则默认开且命中', ageBefore.includes('<SG_'), JSON.stringify(ageBefore.slice(0, 90)));
const lowEntropyKey = 'A3-AAAAAA-AAAAAAAAAAA-AAAAA-AAAAA-AAAAA';
const lowOut = await runPre(`key ${lowEntropyKey}`);
check('逐条 entropy 阈值挡住低熵命中', !lowOut.includes('<SG_'), JSON.stringify(lowOut.slice(0, 90)));

const id = 'gitleaks:age-secret-key';
const toggleOff = await callRoute('/guard/rules', 'POST', { id, enabled: false });
check('关闭 core 规则成功', toggleOff.status === 200 && toggleOff.body.rules.find((r) => r.id === id).enabled === false);
check('关闭后不再遮挡', !(await runPre(`key ${ageKey}`)).includes('<SG_'));
const toggleOn = await callRoute('/guard/rules', 'POST', { id, enabled: true });
check('重新打开成功', toggleOn.status === 200 && toggleOn.body.rules.find((r) => r.id === id).enabled === true);
const badToggle = await callRoute('/guard/rules', 'POST', { id: 'does-not-exist', enabled: true });
check('未知规则 id 被拒', badToggle.status === 400 && badToggle.body.error === 'unknown-rule');
const lanRuleToggle = await callRoute('/guard/rules', 'POST', { id, enabled: false }, '203.0.113.99');
check('非本机来源不能改规则', lanRuleToggle.status === 403, JSON.stringify(lanRuleToggle));
await callRoute('/guard/rules', 'POST', { id, enabled: true });

console.log('manual entries');
const manual = 'MANUAL-INTERNAL-778899';
const addedEntry = await callRoute('/guard/entries', 'POST', { action: 'add', name: '测试口令', plaintext: manual, kind: '密码' });
check('添加敏感数据返回占位符',
  addedEntry.status === 200 && /^<SG_[0-9a-f]{12}>$/.test(addedEntry.body.placeholder || ''),
  JSON.stringify(addedEntry));
const manualHit = await runPre(`value ${manual} end`);
check('手动录入的明文被遮', manualHit.includes('<SG_'), JSON.stringify(manualHit));
const rulesOnDisk = fs.readFileSync(path.join(TEMP_HOME, 'sensitive-guard', 'rules.json'), 'utf8');
check('明文不写进 rules.json', !rulesOnDisk.includes(manual));
const manualVault = await callRoute('/guard/vault', 'GET');
check('保管库条目带名称与 pinned',
  manualVault.body.entries.some((e) => e.name === '测试口令' && e.pinned === true),
  JSON.stringify(manualVault.body.entries.slice(0, 1)));
const manualReveal = await callRoute('/guard/reveal', 'POST', { placeholder: addedEntry.body.placeholder });
check('手动条目可解锁取回明文', manualReveal.status === 200 && manualReveal.body.plaintext === manual,
  JSON.stringify(manualReveal.body).slice(0, 100));
const tooShort = await callRoute('/guard/entries', 'POST', { action: 'add', name: 'x', plaintext: 'ab' });
check('过短的明文被拒', tooShort.status === 400 && tooShort.body.error === 'bad-plaintext');
const deleted = await callRoute('/guard/entries', 'POST', { action: 'delete', placeholder: addedEntry.body.placeholder });
check('删除手动条目成功', deleted.status === 200);
check('删除后不再遮挡', !(await runPre(`value ${manual} end`)).includes('<SG_'));

/* --------------------------------------------------------------------- */

fs.rmSync(TEMP_HOME, { recursive: true, force: true });
console.log(failed === 0 ? '\nall checks passed' : `\n${failed} check(s) failed`);
process.exit(failed === 0 ? 0 : 1);
