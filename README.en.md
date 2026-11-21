# dsh-sensitive-guard

**Keeps your keys out of the model context.** API keys you paste into chat, the `.env` your agent reads, passwords buried in a `config.json` tool result — all swapped for `<SG_1e62c5fe7944>` placeholders before they reach the model. Plaintext stays encrypted on your own machine (AES-256-GCM); clicking the lock reveals it. The model only ever sees the code.

[![npm version](https://img.shields.io/npm/v/dsh-sensitive-guard?color=3d8f66)](https://www.npmjs.com/package/dsh-sensitive-guard)
[![npm downloads](https://img.shields.io/npm/dm/dsh-sensitive-guard?color=3d8f66)](https://www.npmjs.com/package/dsh-sensitive-guard)
[![GitHub stars](https://img.shields.io/github/stars/wangxy496/dsh-sensitive-guard?color=3d8f66)](https://github.com/wangxy496/dsh-sensitive-guard/stargazers)
[![license](https://img.shields.io/npm/l/dsh-sensitive-guard?color=3d8f66)](./LICENSE)
[![dsh](https://img.shields.io/badge/dsh-%E2%89%A50.2.0-3d8f66)](https://github.com/deepseek-ai/deepseek-harness)

English · [中文](README.md)

<img src="https://cdn.jsdelivr.net/gh/wangxy496/dsh-sensitive-guard@main/docs/chat-masked.png" width="640" alt="A masked credential in the conversation: sk- followed by a lock pill">

*Paste `sk-proj-…` and you get this. Click the lock to reveal, it re-masks after 20 seconds.*

## Why

One pasted `.env`, one `cat config.json`, and the secret is permanently in **the session log, the model context, and every screenshot you share**.

| | Model context | Session log on disk | Your screen |
| --- | --- | --- | --- |
| Without it | `sk-proj-abcdef…` in full | in full | in full |
| With it | `<SG_1e62c5fe7944>` | `v1:iv:tag:ciphertext` (AES-256-GCM) | a lock, plaintext only on demand |

It does not rewrite outbound calls, does not sandbox anything, and is no substitute for rotating keys. It guarantees exactly one thing: **a secret never becomes readable text in the model context just because you copied it once.**

## Install

```bash
dsh plugin add dsh-sensitive-guard
```

Requires dsh 0.2.0+ and Node 18+. Tested on Windows 11 and Ubuntu 22.04; not tested on macOS.

A **Sensitive guard** section appears in Settings. To verify, send this in a session:

```
my api key is sk-proj-abcdefghijklmnopqrstuvwx
```

It should render as `my api key is sk-` plus a lock pill. Click it to reveal, it re-masks after 20 seconds. Then check **Settings → Sensitive guard**: the `inline reveal:` line at the bottom reads `ok` when healthy — any other value, see [Troubleshooting](#troubleshooting).

<details>
<summary>Without the CLI: edit package.json by hand</summary>

Edit `~/.dsh/profiles/<profile>/package.json`:

```json
{
  "dependencies": {
    "dsh-sensitive-guard": "0.5.0"
  },
  "dsh": {
    "profile": {
      "bundles": ["dsh-sensitive-guard"]
    }
  }
}
```

Keep the existing entries in `bundles` and append this one, then run `pnpm install` in the same directory and restart dsh.

</details>

<details>
<summary>Local development: link mode</summary>

Replace the version with `"link:/absolute/path/to/sensitive-guard"`. Client changes apply immediately; host-side changes still need a process restart.

</details>

## Screenshots

Click the lock to reveal in place — it re-masks after 20 seconds:

<img src="https://cdn.jsdelivr.net/gh/wangxy496/dsh-sensitive-guard@main/docs/chat-revealed.png" width="640" alt="Revealed in place">

The Settings page lists every vault entry with the same lock, plus a **Copy plaintext** button that writes the value straight to your clipboard (local API call, audited, plaintext never enters the model context):

<img src="https://cdn.jsdelivr.net/gh/wangxy496/dsh-sensitive-guard@main/docs/settings.png" width="720" alt="Settings page">

## What it catches

**Vendor rules.** 221 rules from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT, see `NOTICE`) — 1Password, Adobe, Adafruit, Age, AWS, GCP, Azure, Stripe, Slack and the rest. Each carries a keyword prefilter, a regex and an optional entropy threshold, so a 221-regex sweep never runs over your text. 207 high-confidence rules are on by default; 10 "approximate conversion" rules and 4 loose ones ship off and can be enabled per rule in the Rules tab. Upstream's `pkcs12-file` matches on file name (`.p12`/`.pfx`) and is marked "not applicable" for text redaction.

Vendor prefixes: `sk-`, `sk_`, `ghp_`, `glpat-`, `npm_`, `hf_`, `AKIA`, `ASIA`, `xox*-`, `AIza`, `whsec_`, `SG.`. PEM private key blocks, JWTs, `Bearer` tokens.

Assignments and env vars: `password=`, `secret:`, `api_key:`, `SECRET_KEY=`, `DB_PASSWORD=`.

**JSON and structured data.** A tool that runs `cat config.json` returns one blob of JSON, and `{"password": "Abc!23456"}` has no vendor prefix — the value alone is unrecognizable. Any field named `password`, `passwd`, `pwd`, `token`, `credential`, `api_key`, `db_pass`, `dsn`, `connection_string` (including snake_case, kebab-case and camelCase variants) gets its value replaced. Key names, nesting and sibling values are untouched. Already-parsed object results are handled the same way.

Examples and placeholders stay visible: `your_password_here`, `${DB_PASS}`, `<your-token>`, `changeme`, and field names that merely describe something (`password_policy`, `token_count`).

**Chinese phrasings** too: `数据库密码是…`, `我的 token 是…`. Chinese-language passwords are caught from 6 characters (6-digit numeric passwords are common there); English and `key=value` forms start at 8, so `the secret is hidden` does not eat `hidden`. Trailing particles (`吗`/`呢`/`吧`) and punctuation stay outside the placeholder.

**Connection strings:** `mysql://user:pass@host`, `postgresql://…`, `password=` inside JDBC params, `X-Api-Key:`.

**Command lines:** `mysql -uroot -pabc12345`, `redis-cli -a xxx`. Only these clients are recognized, so `docker run -p 8080:80` is not a false positive.

**Keys broken across lines** are re-joined: pasting from a webpage or screenshot often injects `\r`/`\n` into `sk-proj-…`. The two halves are stitched back into one vault entry, with the identical placeholder you would get unbroken.

## How the agent uses a credential

The model never gets plaintext. When it needs one — to connect to a database, to call an API — it exports:

```
sensitive_guard_export(<SG_xxx>)   # writes plaintext to a 0600 file, returns the path
$(cat /that/path)                  # in a command: plaintext never enters context
```

There are only two tools. `sensitive_guard_status` reports status and entry metadata with no plaintext — not even an 8-character preview. `sensitive_guard_export` writes the file, which expires after 15 minutes.

The most common false bug report: the model reads `application.yml`, sees placeholders, and fails to connect. Either have it export first, or pause protection temporarily.

## Data model

Three places, kept separate:

| | Content |
| --- | --- |
| Model context | `<SG_1e62c5fe7944>`, an HMAC prefix — not reversible offline |
| Disk | `v1:iv:tag:ciphertext`, AES-256-GCM, key in `vault.key` |
| Screen | The code plus a lock; plaintext only fetched from localhost on click |

The 12 hex digits are the first bytes of `HMAC-SHA256(vault.key, plaintext)`. The key never leaves the machine, so the code cannot be brute-forced back to a short password, while the same plaintext still yields the same code every time. Releases up to 0.3.4 used a `sha256(plaintext)` prefix, which is offline-guessable for low-entropy secrets; old codes are preserved in `vault.json` under `aliases` so old sessions still unlock, and every new capture uses the new algorithm.

Two interception points: user input through `agent/pre-step`, tool results through `tools/post-execute`. `llm/stream` additionally scrubs outbound streaming text as a fallback — only `text-delta` and `reasoning-delta`, never `tool-call-delta`, or tool arguments would turn into placeholders. Field-name matching only applies at the first two entry points, so example JSON the model writes itself is left alone.

## Config

`<data dir>/rules.json`, applied within two seconds of saving, no restart. `%USERPROFILE%\.dsh\sensitive-guard\` on Windows, `~/.dsh/sensitive-guard/` on Linux.

```json
{
  "extraRules": [
    { "id": "my-internal", "pattern": "X-WX-Token:\\s*([A-Za-z0-9]{20,})", "flags": "i", "group": 1 }
  ],
  "disabled": ["jwt"],
  "enabledRules": [],
  "outboundScrub": true,
  "entropy": false,
  "entropyThreshold": 4.5,
  "allowCidrs": ["192.168.0.0/16"]
}
```

`group` is the capture group to mask, 0 for the whole match. Your regex runs in a synchronous hook, so avoid `(a+)+` / `(.*)*` — a backtracking blowup stalls the host.

`disabled` turns off individual default-on rules by id; `enabledRules` turns on default-off ones. The Settings switches maintain both lists. `outboundScrub: false` disables the outbound fallback. `allowCidrs` is empty by default, meaning loopback only — see below.

### Reaching it from another machine

Desktop users can skip this. All HTTP routes accept loopback only, which a browser on the same machine always satisfies.

One case reaches this: dsh started with `--host 0.0.0.0` or `--host 192.168.x.x` and opened from another machine's browser. Two options — open `127.0.0.1:3080` on the host machine itself, or allow the subnet in `rules.json`:

```json
{ "allowCidrs": ["192.168.0.0/16"] }
```

The Settings page shows an orange banner when you arrive over the LAN. Unconfigured, the page degrades to read-only rather than blanking: entry counts, kinds, capture times and hit counts, no values and no 8-character preview, plus a card explaining the current address with a ready-to-copy config computed for your source address.

**Allowing a subnet means every device in it can read full plaintext, not just previews.** Use it on a trusted LAN only. There is no login because an auth layer would add two steps to every lock click; narrowing the subnet is the better trade.

## HTTP routes

Five routes, loopback only by default.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/guard/vault` | Panel data with 8-char previews and the current `access` level; unauthorized sources get a `restricted: true` read-only view without previews or audit |
| POST | `/guard/reveal` | `{placeholder}` → `{plaintext, body, prefix}`; 403 when unauthorized |
| GET | `/guard/settings` | `{off, paused, untilRestart, until, remainingMs}`; `remainingMs` is `null` when persistently off |
| POST | `/guard/settings` | `{action:"pause", minutes:30}`, `{action:"pause", untilRestart:true}`, `{action:"resume"}` clears a timed pause; `{action:"disable"}` persists off (survives restart), `{action:"enable"}` re-enables; 403 when unauthorized |
| GET | `/guard/rules` | Rule list (name, source, detector tag, tier, current state), totals, skipped items |
| POST | `/guard/rules` | `{id, enabled}` toggles one rule, writing `disabled` / `enabledRules` |
| POST | `/guard/entries` | `{action:"add", name, plaintext, kind}` or `{action:"delete", placeholder}`; plaintext goes only into the encrypted vault |

## Known limits

1. In-conversation pills cover user messages only (see above for why).
2. No outbound rewriting. The platform's `tools/pre-execute` only exposes allow, deny, cancel and ask — there is no hook to modify arguments, so credentials must go through an export file.
3. The vault defends against accidental reads and plaintext on disk, not against someone who already has your account. Encryption is AES-256-GCM and the key file is tightened with `icacls` on Windows.
4. Historical sessions are unprotected. `pre-step` runs after the host has written the user text to the log, and `session/event` is a read-only observer, so the plugin has no chance to rewrite before disk. Plaintext in old sessions is still on disk; rotate those keys.
5. `exports/` is the only place plaintext lands, cleaned on the next export after 15 minutes.
6. The vault holds at most 500 entries, evicting by last hit.
7. A corrupted vault fails open so the conversation continues, but counts the event — visible as `failOpen` in `sensitive_guard_status`.
8. Each text is scanned up to 200,000 characters. The hook is synchronous, so this bounds custom-regex backtracking; the tail of very long text is unmasked.
9. `allowCidrs` assumes the subnet is trustworthy. It blocks CSRF and DNS rebinding, not an active attacker inside the subnet. `0.0.0.0/0` is rejected and logged to `rules.error`.
10. Unauthorized sources still read metadata (which entries exist, which rules, when captured, hit counts) so the Settings page can explain itself — the cost is that a LAN peer can infer "12 credentials, keys and passwords". Values stay hidden.
11. The host is fail-fast: an exception at the top level of a client entry stops the whole app from booting. `apply` is fully guarded; that top-level risk cannot be removed.
12. Codes issued by 0.3.4 and earlier use a `sha256(plaintext)` prefix and are offline-guessable for short passwords. New captures use HMAC. Old codes remain in `vault.json` under `aliases` so old sessions still unlock, but **codes already written into historical session logs cannot be changed** — rotate those.
13. Rules come from gitleaks: 10 rules using Go's `(?-i:…)` scoping flag become slightly looser after conversion to JS and are marked "approximate conversion", off by default. `pkcs12-file` matches on file name and is not wired up. Rule data ships under the MIT license, declared in `NOTICE`.
14. Manually added entries are pinned in the vault and never count against the 500-entry cap. Plaintext lives only in the encrypted `vault.json`, decrypted into memory for literal matching, and is **never written to `rules.json`** — but it still cannot stop someone with your local account.

## Troubleshooting

Normal uninstall: edit `~/.dsh/profiles/<profile>/package.json`, remove `"dsh-sensitive-guard"` from `dependencies` and from the `dsh.profile.bundles` array, reopen the app.

If the app will not start, the log shows `web boot: N entry did not activate` with `dsh-sensitive-guard: failed`. Kill the leftover process first:

```
taskkill /F /IM "DeepSeek Harness.exe"
```

then remove the dependency as above. Crash logs live in `%APPDATA%\@deepseek-ai\dsh-desktop\logs\crash-*-web-boot.log`.

Values of `inline reveal:` — `ok` is healthy, `waiting` is still waiting for the `uiConversation` service, `no-service` cannot reach it, `matcher-failed` means the rule registration was rejected, `renderer-failed` means the renderer registration was rejected.

The data directory is `$DSH_PROFILE_DIR/sensitive-guard/`, holding `vault.json`, `vault.key`, `pause.json` (`until` for a timed pause plus `off` for persistent disable), `rules.json` and `exports/`. It falls back to `$DSH_HOME` when the variable is unset.

## Development

```bash
node test.mjs                        # offline self-test
node scripts/build-gitleaks.mjs      # regenerate rule data from upstream
node scripts/build-gitleaks.mjs ./gitleaks.toml
```

137 offline tests using a temporary directory, never touching the real vault: the 0.3.x code-upgrade drill, both Settings tabs and the add dialog (including custom categories), list rows and the copy button, render smoke tests for the disable-confirmation dialog, compilation and tiering of all 221 rules, per-rule entropy/switch/manual-entry regressions, and a fresh-process restart proving persistent disable really survives.

| File | Role |
| --- | --- |
| `index.js` | Host: three hooks, vault, two tools, five routes |
| `client.js` | Client: both Settings tabs, rules page (search/filter/paging/toggles), add dialog, in-conversation pills |
| `rules/gitleaks.json` | 221 rules converted from the gitleaks TOML (MIT, see `NOTICE`) |
| `scripts/build-gitleaks.mjs` | Rule converter, Go/RE2 → JS downgrades and tiering |
| `test.mjs` | Self-test |
| `CHANGELOG.md` | Change log |
| `locale/` | Market metadata for the plugin marketplace |

GitHub Actions runs Node 18, 20 and 22 on ubuntu and windows. MIT licensed.

---

If this ever kept a key out of a context it should not have entered, a star is the most direct way to help: [⭐ star](https://github.com/wangxy496/dsh-sensitive-guard/stargazers)

Found a credential format it misses? [Open an issue](https://github.com/wangxy496/dsh-sensitive-guard/issues) with a redacted sample — vendor rules can be added.
