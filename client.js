/**
 * Browser half of dsh-sensitive-guard: the Settings → 敏感保护 page
 * (WorkBuddy 敏感数据管理 equivalent). Lists vault metadata and reveals one
 * plaintext on demand through POST /guard/reveal (same-origin, audited,
 * auto re-masks after 20s). No DOM outside this component.
 */

window.__ModuleLoader__.load({
  id: 'dsh-sensitive-guard',
  factory: (require) => {
    const React = require('react');
    const h = React.createElement;
    const { useState, useEffect, useRef, useCallback } = React;

    /** Dictionary namespace owned by this plugin. */
    const NS = 'sensitiveGuard';
    const zh = {
      nav: '敏感保护',
      heading: '敏感数据管理',
      intro: '以下明文只保存在本机保管库。会话与模型上下文里只有 <SG_> 占位符；点右侧小锁可临时查看真实值。',
      loading: '载入中…',
      empty: '暂无被保护的敏感数据。输入或工具结果里出现密钥、令牌、密码时会自动入库。',
      error: '载入失败',
      reveal: '显示明文',
      hide: '隐藏明文',
      refresh: '刷新',
      autoHide: '20 秒后自动重新遮挡',
      colValue: '名称 / 值',
      colCategory: '分类',
      colKind: '规则',
      copyPlain: '复制明文',
      copyOk: '已复制',
      copyFail: '复制失败',
      stats: '共 {count} 条 · 揭示只记录在本机',
      placeholder: '上下文占位符格式：<SG_十六进制>',
      usage: '模型侧取用：sensitive_guard_export 工具把明文写入 0600 文件，命令里用 "$(cat <路径>)" 引用，明文不进上下文。',
      statusOn: '保护中',
      statusOff: '已暂停',
      statusDisabled: '保护已关闭',
      pause30: '暂停 30 分钟',
      pause120: '暂停 2 小时',
      pauseRestart: '暂停到重启',
      pauseRestartLeft: '重启前不再脱敏',
      resume: '恢复保护',
      disable: '关闭保护',
      enable: '开启保护',
      pausedHint: '暂停期间不做任何脱敏，明文会直接进入上下文与日志。到期自动恢复。',
      disabledHint: '保护已持久关闭：不做任何脱敏，明文直接进入上下文与日志；重启也不会自动恢复，需要时手动点「开启保护」。',
      disableTitle: '关闭保护？',
      disableBody: '关闭后所有脱敏立即停止，明文会直接进入模型上下文与日志，而且重启也不会自动恢复。只有再点「开启保护」才会恢复。建议优先用限时暂停。',
      disableConfirm: '确认关闭',
      disableCancel: '取消',
      lanExposed: '⚠ 本页经局域网访问（允许网段：{cidrs}）。这条链路上的明文与预览对该网段可见，用完建议把 allowCidrs 收回。',
      restrictedTitle: '只读：这台机器不是服务所在的本机',
      restrictedBody: '服务端默认只接受本机回环，所以这里能看到“有哪些凭据被保护”，看不到值。当前访问地址：{host}',
      restrictedFile: '要在这里查看或揭示明文，二选一。① 在服务所在机器上编辑下面这个文件，加一行：',
      restrictedAlt: '② 或者直接在服务所在机器的浏览器打开 http://127.0.0.1:<端口>。',
      restrictedUnlock: '需在服务所在的本机打开才能揭示',
      tabRules: '自动检测规则',
      tabEntries: '敏感数据管理',
      rulesSearch: '搜索规则名称或关键词',
      rulesAll: '全部状态',
      rulesOn: '已开启',
      rulesOff: '已关闭',
      rulesPrev: '上一页',
      rulesNext: '下一页',
      rulesPage: '第 {current} / {total} 页',
      rulesNoMatch: '没有匹配的规则',
      rulesLoading: '载入规则中…',
      ruleSystem: '系统规则',
      ruleBuiltin: '内置规则',
      ruleCustom: '自定义规则',
      ruleApprox: '近似转换',
      ruleLoose: '宽松规则',
      ruleSkipped: '{count} 条文件型规则不适用文本检测',
      addEntry: '添加敏感数据',
      addEntryTitle: '添加敏感数据',
      addEntryName: '例如：公司内网口令',
      addEntryNameLabel: '名称',
      addEntryPlain: '明文内容',
      addEntryPlainLabel: '明文',
      addEntryKind: '类型',
      addEntryKindLabel: '类型',
      addEntrySubmit: '保存',
      addEntryCancel: '取消',
      addEntryClose: '关闭',
      addEntryOk: '已加密保存，以后会自动遮挡',
      addEntryFail: '保存失败，确认是在本机打开的页面',
      addEntryNeedKind: '给自定义分类起个名字',
      addKindCustom: '自定义分类…',
      addKindCustomLabel: '分类名称',
      addKindCustomPlaceholder: '例如：公司内部凭据',
      entrySearch: '搜索名称、预览或代号',
      entryDelete: '删除',
      kindPassword: '密码',
      kindToken: '令牌',
      kindKey: '密钥',
    };
    const en = {
      nav: 'Sensitive guard',
      heading: 'Sensitive data',
      intro: 'These plaintexts live only in the local vault. Sessions and model context carry <SG_> placeholders; click the lock on the right to reveal a value temporarily.',
      loading: 'Loading…',
      empty: 'Nothing protected yet. Keys, tokens and passwords found in input or tool results are captured automatically.',
      error: 'Failed to load',
      reveal: 'Show secret',
      hide: 'Hide secret',
      refresh: 'Refresh',
      autoHide: 'Re-masks in 20 seconds',
      colValue: 'Name / value',
      colCategory: 'Type',
      colKind: 'Rule',
      copyPlain: 'Copy plaintext',
      copyOk: 'Copied',
      copyFail: 'Copy failed',
      stats: '{count} entries · reveals stay on this machine',
      placeholder: 'Context placeholder format: <SG_hex>',
      usage: 'For the agent: sensitive_guard_export writes the plaintext to a 0600 file; reference it as "$(cat <path>)" so plaintext never enters context.',
      statusOn: 'Protecting',
      statusOff: 'Paused',
      statusDisabled: 'Protection off',
      pause30: 'Pause 30 min',
      pause120: 'Pause 2 h',
      pauseRestart: 'Pause until restart',
      pauseRestartLeft: 'No masking until restart',
      resume: 'Resume',
      disable: 'Disable protection',
      enable: 'Enable protection',
      pausedHint: 'Nothing is masked while paused — plaintext reaches context and logs. Re-arms automatically.',
      disabledHint: 'Protection is persistently off: nothing is masked, plaintext reaches context and logs, and a restart will NOT re-arm it. Click "Enable protection" to restore it.',
      disableTitle: 'Disable protection?',
      disableBody: 'All masking stops immediately. Plaintext will reach the model context and logs, and a restart will not re-arm the guard — only "Enable protection" restores it. Prefer a timed pause when possible.',
      disableConfirm: 'Disable',
      disableCancel: 'Cancel',
      lanExposed: '⚠ This page is served over LAN (allowed: {cidrs}). Plaintext and previews on this route are visible to that network; narrow allowCidrs when you are done.',
      restrictedTitle: 'Read-only: this machine is not the one running the server',
      restrictedBody: 'The server only accepts loopback by default, so you can see which credentials are protected, but not their values. Current address: {host}',
      restrictedFile: 'To view or reveal values here, pick one. ① On the server machine, edit this file and add one line:',
      restrictedAlt: '② Or open http://127.0.0.1:<port> in a browser on that machine.',
      restrictedUnlock: 'Reveal requires the browser on the server machine',
      tabRules: 'Detection rules',
      tabEntries: 'Sensitive data',
      rulesSearch: 'Search rule names or keywords',
      rulesAll: 'All statuses',
      rulesOn: 'Enabled',
      rulesOff: 'Disabled',
      rulesPrev: 'Previous',
      rulesNext: 'Next',
      rulesPage: 'Page {current} / {total}',
      rulesNoMatch: 'No matching rules',
      rulesLoading: 'Loading rules…',
      ruleSystem: 'System',
      ruleBuiltin: 'Built-in',
      ruleCustom: 'Custom',
      ruleApprox: 'Approximate',
      ruleLoose: 'Loose',
      ruleSkipped: '{count} file-only rule(s) skipped',
      addEntry: 'Add sensitive data',
      addEntryTitle: 'Add sensitive data',
      addEntryName: 'e.g. intranet password',
      addEntryNameLabel: 'Name',
      addEntryPlain: 'Plaintext value',
      addEntryPlainLabel: 'Plaintext',
      addEntryKind: 'Type',
      addEntryKindLabel: 'Type',
      addEntrySubmit: 'Save',
      addEntryCancel: 'Cancel',
      addEntryClose: 'Close',
      addEntryOk: 'Saved encrypted; it will be masked from now on',
      addEntryFail: 'Could not save; open this page on the server machine',
      addEntryNeedKind: 'Give the custom type a name',
      addKindCustom: 'Custom type…',
      addKindCustomLabel: 'Type name',
      addKindCustomPlaceholder: 'e.g. internal credential',
      entrySearch: 'Search name, preview or placeholder',
      entryDelete: 'Delete',
      kindPassword: 'Password',
      kindToken: 'Token',
      kindKey: 'Key',
    };

    const REVEAL_MS = 20_000;
    const POLL_MS = 30_000;

    const boxStyle = {
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      padding: '8px 12px',
      borderRadius: 12,
      background: 'var(--dsw-alias-bg-layer-1)',
      border: '1px solid var(--dsw-alias-border-l2)',
      overflow: 'hidden',
    };
    const monoStyle = {
      fontFamily: 'var(--dsw-alias-font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)',
      fontSize: 13,
      fontVariantNumeric: 'tabular-nums',
    };
    const btnStyle = {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      width: 30,
      height: 30,
      flex: 'none',
      padding: 0,
      borderRadius: 8,
      background: 'transparent',
      border: '1px solid var(--dsw-alias-border-l2)',
      color: 'var(--dsw-alias-label-primary)',
      cursor: 'pointer',
    };
    const focusCss = '.dsguard-btn:focus-visible{outline:var(--dsw-focus-ring-width,2px) solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary));outline-offset:2px}';
    /** Some hosts only substitute a single {count}; fill placeholders locally too. */
    function fillTemplate(text, params) {
      let out = String(text || '');
      for (const [k, v] of Object.entries(params || {})) out = out.replace(`{${k}}`, String(v));
      return out;
    }
    const inputStyle = {
      flex: '1 1 200px', minWidth: 0, padding: '7px 10px', borderRadius: 8,
      border: '1px solid var(--dsw-alias-border-l2)',
      background: 'var(--dsw-alias-bg-layer-1)',
      color: 'var(--dsw-alias-label-primary)', fontSize: 12,
    };
    const selectStyle = { ...inputStyle, flex: '0 0 auto', cursor: 'pointer' };
    const primaryBtn = {
      ...btnStyle, width: 'auto', height: 32, padding: '0 14px', fontSize: 12,
      background: 'var(--dsw-alias-label-primary)', color: 'var(--dsw-alias-bg-layer-1)',
      border: '1px solid transparent',
    };
    const dangerBtn = {
      ...btnStyle, width: 'auto', height: 30, padding: '0 10px', fontSize: 12,
      color: 'var(--dsw-alias-state-error-primary, #e5534b)',
      borderColor: 'rgba(229,83,75,0.55)',
    };
    const dangerPrimary = {
      ...dangerBtn, padding: '0 14px', fontWeight: 500,
      background: 'rgba(229,83,75,0.14)',
    };
    const tagStyle = {
      padding: '2px 7px', borderRadius: 6, fontSize: 11,
      background: 'var(--dsw-alias-bg-layer-1)',
      color: 'var(--dsw-alias-label-secondary)',
      border: '1px solid var(--dsw-alias-border-l2)',
    };
    const warnTagStyle = { ...tagStyle, color: 'var(--dsw-alias-state-warn-label)', borderColor: 'rgba(239,159,39,0.55)' };
    const tabBarStyle = { display: 'flex', gap: 8, borderBottom: '1px solid var(--dsw-alias-border-l2)', paddingBottom: 8 };
    function tabStyle(active) {
      return {
        ...btnStyle, width: 'auto', height: 30, padding: '0 12px', fontSize: 12,
        border: '1px solid transparent',
        background: active ? 'var(--dsw-alias-bg-layer-1)' : 'transparent',
        color: active ? 'var(--dsw-alias-label-primary)' : 'var(--dsw-alias-label-secondary)',
      };
    }
    function switchStyle(on) {
      return {
        ...btnStyle, width: 38, height: 22, borderRadius: 11, padding: 0,
        background: on ? '#1D9E75' : 'var(--dsw-alias-border-l2)',
        border: '1px solid transparent',
        justifyContent: on ? 'flex-end' : 'flex-start',
      };
    }
    const knobStyle = { width: 16, height: 16, borderRadius: 8, background: '#fff', display: 'block' };

    function LockGlyph({ open }) {
      return h('svg', { width: 15, height: 15, viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', strokeWidth: 1.3, 'aria-hidden': 'true' },
        h('rect', { x: 3, y: 7.5, width: 10, height: 6.5, rx: 1.6 }),
        h('path', { d: open ? 'M5.5 7.5V5.5a2.5 2.5 0 0 1 4.9-.7' : 'M5.5 7.5V5.5a2.5 2.5 0 0 1 5 0v2' }));
    }

    function CopyGlyph() {
      return h('svg', { width: 15, height: 15, viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', strokeWidth: 1.3, 'aria-hidden': 'true' },
        h('rect', { x: 5.5, y: 5.5, width: 8, height: 8, rx: 1.4 }),
        h('path', { d: 'M10.5 3.5H4A1.5 1.5 0 0 0 2.5 5v6.5' }));
    }

    /** Never put plaintext into model context: this is a browser-side copy. */
    async function copyToClipboard(text) {
      try {
        if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch { /* fall through to the legacy path */ }
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
      } catch { return false; }
    }

    function formatLeft(ms) {
      const total = Math.max(0, Math.ceil((Number(ms) || 0) / 1000));
      const m = Math.floor(total / 60);
      const s = total % 60;
      return `${m}:${String(s).padStart(2, '0')}`;
    }

    /**
     * Shown when the page is opened from another machine and that peer is not
     * in `allowCidrs`. Read-only: structure yes, values no. The whole point is
     * that the fix (one JSON line, or open 127.0.0.1) is right here on screen.
     */
    function RestrictedNotice({ t, host, suggested, dataDir }) {
      const cidr = suggested || '192.168.0.0/16';
      const snippet = `{\n  "allowCidrs": ["${cidr}"]\n}`;
      const file = dataDir ? `${dataDir}${dataDir.endsWith('/') || dataDir.endsWith('\\') ? '' : '/'}rules.json` : 'rules.json';
      return h('div', {
        style: {
          display: 'grid',
          gap: 8,
          padding: '10px 12px',
          borderRadius: 10,
          border: '1px solid rgba(239,159,39,0.55)',
          background: 'rgba(239,159,39,0.10)',
        },
      },
        h('span', { style: { fontSize: 12, fontWeight: 500, color: 'var(--dsw-alias-state-warn-label)' } },
          `⚠ ${t('restrictedTitle')}`),
        h('p', { style: { fontSize: 11.5, lineHeight: 1.65, margin: 0, color: 'var(--dsw-alias-label-secondary)' } },
          t('restrictedBody', { host: host || '—' })),
        h('p', { style: { fontSize: 11.5, lineHeight: 1.65, margin: 0, color: 'var(--dsw-alias-label-secondary)' } },
          t('restrictedFile')),
        h('code', {
          style: {
            ...monoStyle,
            display: 'block',
            padding: '8px 10px',
            borderRadius: 8,
            background: 'var(--dsw-alias-bg-layer-1)',
            border: '1px solid var(--dsw-alias-border-l2)',
            fontSize: 11.5,
            lineHeight: 1.6,
            whiteSpace: 'pre',
            userSelect: 'text',
          },
        }, `${file}\n${snippet}`),
        h('p', { style: { fontSize: 11.5, lineHeight: 1.65, margin: 0, color: 'var(--dsw-alias-label-secondary)' } },
          t('restrictedAlt')));
    }

    /** Detection-rule catalogue: search, status filter, pagination, per-rule switch. */
    function RulesPane({ t }) {
      const [data, setData] = useState(null);
      const [query, setQuery] = useState('');
      const [filter, setFilter] = useState('all');
      const [page, setPage] = useState(1);
      const [busy, setBusy] = useState(null);
      const alive = useRef(true);

      const load = useCallback(async () => {
        try {
          const res = await fetch('/guard/rules', { cache: 'no-store' });
          const json = await res.json().catch(() => null);
          if (alive.current && res.ok && json) setData(json);
        } catch { /* leave the last known list */ }
      }, []);
      useEffect(() => {
        alive.current = true;
        load();
        return () => { alive.current = false; };
      }, [load]);

      const toggle = useCallback(async (id, enabled) => {
        setBusy(id);
        try {
          const res = await fetch('/guard/rules', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ id, enabled }),
          });
          const json = await res.json().catch(() => null);
          if (alive.current && res.ok && json) setData(json);
        } catch { /* keep the old state */ }
        if (alive.current) setBusy(null);
      }, []);

      const all = (data && data.rules) || [];
      const q = String(query || '').trim().toLowerCase();
      const filtered = all.filter((r) => {
        if (filter === 'on' && !r.enabled) return false;
        if (filter === 'off' && r.enabled) return false;
        if (!q) return true;
        return `${r.name} ${r.id} ${(r.keywords || []).join(' ')}`.toLowerCase().includes(q);
      });
      // Enabled rules first, so the 14 default-off ones collect on the last page
      // instead of being scattered through the list.
      const sorted = filtered.slice().sort((a, b) => (a.enabled === b.enabled ? 0 : a.enabled ? -1 : 1));
      const size = (data && data.pageSize) || 20;
      const pages = Math.max(1, Math.ceil(sorted.length / size));
      const current = Math.min(Math.max(1, page), pages);
      const rows = sorted.slice((current - 1) * size, current * size);
      const sourceLabel = (r) => (r.source === 'gitleaks' ? t('ruleSystem') : r.source === 'custom' ? t('ruleCustom') : t('ruleBuiltin'));

      let listNode;
      if (!data) {
        listNode = h('p', { style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)' } }, t('rulesLoading'));
      } else if (rows.length === 0) {
        listNode = h('p', { style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)' } }, t('rulesNoMatch'));
      } else {
        listNode = h('div', { style: { display: 'grid', gap: 8 } },
          rows.map((r) => h('div', { key: r.id, style: boxStyle },
            h('span', { style: { flex: '1 1 auto', minWidth: 0, display: 'grid', gap: 5 } },
              h('span', { style: { fontSize: 13, color: 'var(--dsw-alias-label-primary)' } }, r.name),
              h('span', { style: { display: 'flex', gap: 6, flexWrap: 'wrap' } },
                (r.detectors || []).map((d) => h('span', { key: d, style: tagStyle }, d)),
                h('span', { style: tagStyle }, sourceLabel(r)),
                r.approx ? h('span', { style: warnTagStyle }, t('ruleApprox')) : null,
                r.tier === 'loose' ? h('span', { style: warnTagStyle }, t('ruleLoose')) : null)),
            h('button', {
              type: 'button', className: 'dsguard-btn', style: switchStyle(r.enabled),
              'aria-pressed': Boolean(r.enabled), 'aria-label': r.name,
              disabled: busy === r.id,
              onClick: () => toggle(r.id, !r.enabled),
            }, h('span', { style: knobStyle })))));
      }

      return h('div', { style: { display: 'grid', gap: 12 } },
        h('div', { style: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
          h('select', {
            value: filter, style: selectStyle,
            onChange: (e) => { setFilter(e && e.target ? e.target.value : 'all'); setPage(1); },
          },
            h('option', { value: 'all' }, t('rulesAll')),
            h('option', { value: 'on' }, t('rulesOn')),
            h('option', { value: 'off' }, t('rulesOff'))),
          h('input', {
            type: 'text', value: query, placeholder: t('rulesSearch'), style: inputStyle,
            onChange: (e) => { setQuery(e && e.target ? e.target.value : ''); setPage(1); },
          }),
          h('span', { style: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)' } },
            `${filtered.length} / ${all.length}`)),
        listNode,
        h('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10 } },
          h('button', {
            type: 'button', className: 'dsguard-btn',
            style: { ...btnStyle, width: 'auto', padding: '0 10px', fontSize: 12, opacity: current <= 1 ? 0.45 : 1 },
            disabled: current <= 1, onClick: () => setPage(current - 1),
          }, t('rulesPrev')),
          h('span', { style: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)' } },
            fillTemplate(t('rulesPage', { current: String(current), total: String(pages) }),
              { current: String(current), total: String(pages) })),
          h('button', {
            type: 'button', className: 'dsguard-btn',
            style: { ...btnStyle, width: 'auto', padding: '0 10px', fontSize: 12, opacity: current >= pages ? 0.45 : 1 },
            disabled: current >= pages, onClick: () => setPage(current + 1),
          }, t('rulesNext'))),
        data && data.skipped && data.skipped.length
          ? h('p', { style: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)', margin: 0 } },
            fillTemplate(t('ruleSkipped', { count: String(data.skipped.length) }),
              { count: String(data.skipped.length) }))
          : null);
    }

    /** Add a secret by hand in a modal. Plaintext is sent once, never written to config. */
    const KIND_CUSTOM = '__custom__';
    function AddEntryForm({ t, onAdded, disabled }) {
      const [open, setOpen] = useState(false);
      const [name, setName] = useState('');
      const [plain, setPlain] = useState('');
      const [kind, setKind] = useState('密码');
      const [customKind, setCustomKind] = useState('');
      const [note, setNote] = useState('');

      const close = () => { setOpen(false); setPlain(''); setCustomKind(''); };
      useEffect(() => {
        if (!open) return undefined;
        const onKey = (e) => { if (e && e.key === 'Escape') close(); };
        try {
          window.addEventListener('keydown', onKey);
          return () => window.removeEventListener('keydown', onKey);
        } catch { return undefined; }
      }, [open]);

      const fieldStyle = { display: 'grid', gap: 5 };
      const labelStyle = { fontSize: 11, color: 'var(--dsw-alias-label-secondary)' };
      const fullInput = { ...inputStyle, flex: 'none', width: '100%', boxSizing: 'border-box' };

      const submit = async () => {
        const value = String(plain || '').trim();
        if (!value) return;
        const resolved = kind === KIND_CUSTOM ? String(customKind || '').trim() : kind;
        if (!resolved) { setNote(t('addEntryNeedKind')); return; }
        try {
          const res = await fetch('/guard/entries', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'add', name: String(name || '').trim(), plaintext: value, kind: resolved }),
          });
          if (!res.ok) throw new Error('failed');
          setName(''); close(); setNote(t('addEntryOk'));
          if (onAdded) onAdded();
        } catch { setNote(t('addEntryFail')); }
      };

      if (!open) {
        return h('div', { style: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
          h('button', {
            type: 'button', className: 'dsguard-btn', style: primaryBtn,
            disabled, onClick: () => { setNote(''); setOpen(true); },
          }, t('addEntry')),
          note ? h('span', { style: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)' } }, note) : null);
      }

      return h('div', {
        style: {
          position: 'fixed', inset: 0, zIndex: 9999, padding: 20,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'rgba(0,0,0,0.45)',
        },
        onClick: (e) => { if (e && e.target === e.currentTarget) close(); },
      },
        h('div', {
          style: {
            width: 'min(420px, 100%)', display: 'grid', gap: 14, padding: 20,
            borderRadius: 14, background: 'var(--dsw-alias-bg-layer-1)',
            border: '1px solid var(--dsw-alias-border-l2)',
            boxShadow: '0 12px 32px rgba(0,0,0,0.28)',
          },
        },
          h('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' } },
            h('h3', { style: { margin: 0, fontSize: 15, fontWeight: 500, color: 'var(--dsw-alias-label-primary)' } }, t('addEntryTitle')),
            h('button', {
              type: 'button', className: 'dsguard-btn',
              style: { ...btnStyle, width: 26, height: 26, fontSize: 14 },
              'aria-label': t('addEntryClose'), title: t('addEntryClose'),
              onClick: close,
            }, '×')),
          h('div', { style: fieldStyle },
            h('span', { style: labelStyle }, t('addEntryNameLabel')),
            h('input', {
              type: 'text', value: name, placeholder: t('addEntryName'), style: fullInput,
              onChange: (e) => setName(e && e.target ? e.target.value : ''),
            })),
          h('div', { style: fieldStyle },
            h('span', { style: labelStyle }, t('addEntryPlainLabel')),
            h('input', {
              type: 'text', value: plain, placeholder: t('addEntryPlain'), style: fullInput,
              onChange: (e) => setPlain(e && e.target ? e.target.value : ''),
            })),
          h('div', { style: fieldStyle },
            h('span', { style: labelStyle }, t('addEntryKindLabel')),
            h('select', {
              value: kind, style: { ...fullInput, cursor: 'pointer' },
              onChange: (e) => setKind(e && e.target ? e.target.value : '密码'),
            },
              h('option', { value: '密码' }, t('kindPassword')),
              h('option', { value: '令牌' }, t('kindToken')),
              h('option', { value: '密钥' }, t('kindKey')),
              h('option', { value: KIND_CUSTOM }, t('addKindCustom')))),
          kind === KIND_CUSTOM
            ? h('div', { style: fieldStyle },
              h('span', { style: labelStyle }, t('addKindCustomLabel')),
              h('input', {
                type: 'text', value: customKind, placeholder: t('addKindCustomPlaceholder'), style: fullInput,
                onChange: (e) => setCustomKind(e && e.target ? e.target.value : ''),
              }))
            : null,
          note ? h('p', { style: { margin: 0, fontSize: 11, color: 'var(--dsw-alias-state-warn-label)' } }, note) : null,
          h('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 2 } },
            h('button', {
              type: 'button', className: 'dsguard-btn',
              style: { ...btnStyle, width: 'auto', padding: '0 14px', fontSize: 12 },
              onClick: close,
            }, t('addEntryCancel')),
            h('button', {
              type: 'button', className: 'dsguard-btn', style: primaryBtn,
              disabled, onClick: submit,
            }, t('addEntrySubmit')))));
    }

    /** Destructive, persistent action — always confirm before disabling. */
    function DisableConfirm({ t, onConfirm, onCancel }) {
      useEffect(() => {
        const onKey = (e) => { if (e && e.key === 'Escape') onCancel(); };
        try {
          window.addEventListener('keydown', onKey);
          return () => window.removeEventListener('keydown', onKey);
        } catch { return undefined; }
      }, [onCancel]);
      return h('div', {
        style: {
          position: 'fixed', inset: 0, zIndex: 9999, padding: 20,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'rgba(0,0,0,0.45)',
        },
        onClick: (e) => { if (e && e.target === e.currentTarget) onCancel(); },
      },
        h('div', {
          style: {
            width: 'min(400px, 100%)', display: 'grid', gap: 14, padding: 20,
            borderRadius: 14, background: 'var(--dsw-alias-bg-layer-1)',
            border: '1px solid var(--dsw-alias-border-l2)',
            boxShadow: '0 12px 32px rgba(0,0,0,0.28)',
          },
        },
          h('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' } },
            h('h3', {
              style: { margin: 0, fontSize: 15, fontWeight: 500, color: 'var(--dsw-alias-state-error-primary, #e5534b)' },
            }, t('disableTitle')),
            h('button', {
              type: 'button', className: 'dsguard-btn',
              style: { ...btnStyle, width: 26, height: 26, fontSize: 14 },
              'aria-label': t('disableCancel'), title: t('disableCancel'),
              onClick: onCancel,
            }, '×')),
          h('p', {
            style: { margin: 0, fontSize: 12, lineHeight: 1.7, color: 'var(--dsw-alias-label-primary)' },
          }, t('disableBody')),
          h('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: 8 } },
            h('button', {
              type: 'button', className: 'dsguard-btn',
              style: { ...btnStyle, width: 'auto', padding: '0 14px', fontSize: 12 },
              onClick: onCancel,
            }, t('disableCancel')),
            h('button', {
              type: 'button', className: 'dsguard-btn', style: dangerPrimary,
              onClick: onConfirm,
            }, t('disableConfirm')))));
    }

    function GuardView({ t }) {
      const [data, setData] = useState(null);
      const [status, setStatus] = useState('loading');
      const [shown, setShown] = useState({});
      const [guard, setGuard] = useState(null);
      // Set when the server explains a rejection; keeps the page actionable
      // instead of showing a bare "failed to load".
      const [denied, setDenied] = useState(null);
      const [tab, setTab] = useState('entries');
      const [entryQuery, setEntryQuery] = useState('');
      const [copied, setCopied] = useState('');
      const [confirmDisable, setConfirmDisable] = useState(false);
      const timers = useRef({});
      const alive = useRef(true);

      const load = useCallback(async (signal) => {
        try {
          const res = await fetch('/guard/vault', { cache: 'no-store', signal });
          const json = await res.json().catch(() => null);
          if (!alive.current) return;
          if (!res.ok) {
            setDenied(json && (json.hint || json.suggested)
              ? { host: json.host || '', suggested: json.suggested || '', hint: json.hint || '' }
              : { host: '', suggested: '', hint: '' });
            setStatus('error');
            return;
          }
          setDenied(null);
          setData(json);
          setStatus('ready');
        } catch (error) {
          if (!alive.current || (error && error.name === 'AbortError')) return;
          setStatus('error');
        }
      }, []);

      useEffect(() => {
        alive.current = true;
        const controller = new AbortController();
        load(controller.signal);
        const poll = window.setInterval(() => load(controller.signal), POLL_MS);
        const timersRef = timers.current;
        return () => {
          alive.current = false;
          controller.abort();
          window.clearInterval(poll);
          Object.values(timersRef).forEach((id) => window.clearTimeout(id));
        };
      }, [load]);

      const reveal = useCallback(async (ph) => {
        try {
          const res = await fetch('/guard/reveal', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ placeholder: ph }),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const json = await res.json();
          if (!alive.current) return;
          setShown((prev) => ({ ...prev, [ph]: json.plaintext }));
          window.clearTimeout(timers.current[ph]);
          timers.current[ph] = window.setTimeout(() => {
            setShown((prev) => {
              const next = { ...prev };
              delete next[ph];
              return next;
            });
          }, REVEAL_MS);
        } catch {
          /* keep masked; the row simply stays closed */
        }
      }, []);

      const toggle = useCallback((ph) => {
        if (shown[ph]) {
          window.clearTimeout(timers.current[ph]);
          setShown((prev) => {
            const next = { ...prev };
            delete next[ph];
            return next;
          });
        } else {
          reveal(ph);
        }
      }, [shown, reveal]);

      const loadGuard = useCallback(async () => {
        try {
          const res = await fetch('/guard/settings', { cache: 'no-store' });
          if (res.ok) setGuard(await res.json());
        } catch { /* leave the last known state */ }
      }, []);

      const applyPause = useCallback(async (payload) => {
        try {
          const res = await fetch('/guard/settings', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
          });
          if (res.ok) { setGuard(await res.json()); setConfirmDisable(false); }
        } catch { /* ignore */ }
      }, []);

      const deleteEntry = useCallback(async (ph) => {
        try {
          const res = await fetch('/guard/entries', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'delete', placeholder: ph }),
          });
          if (res.ok) load();
        } catch { /* leave the row in place */ }
      }, [load]);

      const copyPlaintext = useCallback(async (ph) => {
        try {
          const res = await fetch('/guard/reveal', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ placeholder: ph }),
          });
          if (!res.ok) throw new Error('failed');
          const json = await res.json();
          const ok = await copyToClipboard(json.plaintext || '');
          if (!alive.current) return;
          setCopied(ok ? ph : `error:${ph}`);
          window.clearTimeout(timers.current.copy);
          timers.current.copy = window.setTimeout(() => { if (alive.current) setCopied(''); }, 1800);
        } catch {
          if (alive.current) setCopied(`error:${ph}`);
        }
      }, []);

      useEffect(() => { loadGuard(); }, [loadGuard]);

      const paused = Boolean(guard && guard.paused);
      const untilRestart = Boolean(guard && guard.untilRestart);
      const disabled = Boolean(guard && guard.off);

      useEffect(() => {
        if (!paused || untilRestart || disabled) return undefined;
        const id = window.setInterval(() => {
          setGuard((prev) => {
            if (!prev || !prev.paused) return prev;
            const left = (prev.remainingMs || 0) - 1000;
            if (left <= 0) { loadGuard(); return prev; }
            return { ...prev, remainingMs: left };
          });
        }, 1000);
        return () => window.clearInterval(id);
      }, [paused, untilRestart, disabled, loadGuard]);

      const entries = (data && data.entries) || [];
      const eq = String(entryQuery || '').trim().toLowerCase();
      const visibleEntries = eq
        ? entries.filter((e) => `${e.name || ''} ${e.preview || ''} ${e.ph} ${e.rule || ''}`.toLowerCase().includes(eq))
        : entries;
      const access = (data && data.access) || denied || {};
      // Either the server degraded us to metadata-only, or it refused outright.
      const restricted = Boolean(data && data.restricted) || Boolean(denied);

      // One row of state controls: a persistent disable is always reachable,
      // but it goes through a confirmation modal first.
      const stateButtons = disabled
        ? [h('button', {
          key: 'enable', type: 'button', className: 'dsguard-btn',
          style: { ...primaryBtn, width: 'auto', padding: '0 12px', fontSize: 12 },
          onClick: () => applyPause({ action: 'enable' }),
        }, t('enable'))]
        : [
          ...(paused
            ? [h('button', {
              key: 'resume', type: 'button', className: 'dsguard-btn',
              style: { ...btnStyle, width: 'auto', padding: '0 10px', fontSize: 12 },
              onClick: () => applyPause({ action: 'resume' }),
            }, t('resume'))]
            : [
              h('button', {
                key: 'p30', type: 'button', className: 'dsguard-btn',
                style: { ...btnStyle, width: 'auto', padding: '0 10px', fontSize: 12 },
                onClick: () => applyPause({ action: 'pause', minutes: 30 }),
              }, t('pause30')),
              h('button', {
                key: 'p120', type: 'button', className: 'dsguard-btn',
                style: { ...btnStyle, width: 'auto', padding: '0 10px', fontSize: 12 },
                onClick: () => applyPause({ action: 'pause', minutes: 120 }),
              }, t('pause120')),
              h('button', {
                key: 'pr', type: 'button', className: 'dsguard-btn',
                style: { ...btnStyle, width: 'auto', padding: '0 10px', fontSize: 12 },
                onClick: () => applyPause({ action: 'pause', untilRestart: true }),
              }, t('pauseRestart')),
            ]),
          h('button', {
            key: 'disable', type: 'button', className: 'dsguard-btn',
            style: dangerBtn, title: t('disableTitle'),
            onClick: () => setConfirmDisable(true),
          }, t('disable')),
        ];

      return h('div', { style: { display: 'grid', gap: 14 } },
        h('style', {}, focusCss),
        h('div', { style: tabBarStyle },
          h('button', {
            type: 'button', className: 'dsguard-btn', style: tabStyle(tab === 'rules'),
            onClick: () => setTab('rules'),
          }, t('tabRules')),
          h('button', {
            type: 'button', className: 'dsguard-btn', style: tabStyle(tab === 'entries'),
            onClick: () => setTab('entries'),
          }, t('tabEntries'))),
        tab === 'rules'
          ? h(RulesPane, { t })
          : h('div', { style: { display: 'grid', gap: 14 } },
        restricted
          ? h(RestrictedNotice, {
            t,
            host: access.host,
            suggested: access.suggested,
            dataDir: data && data.dataDir,
          })
          : h('div', {
          style: {
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
            padding: '8px 12px',
            borderRadius: 10,
            border: `1px solid ${disabled ? 'rgba(229,83,75,0.6)' : paused ? 'rgba(239,159,39,0.55)' : 'var(--dsw-alias-border-l2)'}`,
            background: disabled ? 'rgba(229,83,75,0.12)' : paused ? 'rgba(239,159,39,0.12)' : 'var(--dsw-alias-bg-layer-1)',
          },
        },
          h('span', {
            style: {
              fontSize: 12,
              fontWeight: 500,
              color: disabled
                ? 'var(--dsw-alias-state-error-primary, #e5534b)'
                : paused ? 'var(--dsw-alias-state-warn-label)' : 'var(--dsw-alias-label-primary)',
            },
          }, disabled ? `● ${t('statusDisabled')}` : paused ? `● ${t('statusOff')}` : `● ${t('statusOn')}`),
          paused && !disabled
            ? h('span', { style: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)' } },
              untilRestart ? t('pauseRestartLeft') : formatLeft(guard && guard.remainingMs))
            : null,
          h('span', { style: { flex: 1 } }),
          ...stateButtons),
        disabled
          ? h('p', { style: { fontSize: 11, lineHeight: 1.6, color: 'var(--dsw-alias-state-error-primary, #e5534b)', margin: 0 } }, t('disabledHint'))
          : paused
            ? h('p', { style: { fontSize: 11, color: 'var(--dsw-alias-state-warn-label)', margin: 0 } }, t('pausedHint'))
            : null,
        data && data.access && data.access.level === 'lan'
          ? h('p', { style: { fontSize: 11, lineHeight: 1.6, color: 'var(--dsw-alias-state-warn-label)', margin: 0 } },
            t('lanExposed', { cidrs: (data.access.allowCidrs || []).join(', ') || '-' }))
          : null,
        h('div', { style: { display: 'flex', alignItems: 'baseline', gap: 12, flexWrap: 'wrap' } },
          h('h3', { style: { fontSize: 13, fontWeight: 500, margin: 0, color: 'var(--dsw-alias-label-primary)' } }, t('heading')),
          data ? h('span', { style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)' } }, t('stats', { count: String(entries.length) })) : null,
          h('button', {
            type: 'button',
            className: 'dsguard-btn',
            style: { ...btnStyle, width: 'auto', padding: '0 10px', marginLeft: 'auto', fontSize: 12, gap: 6 },
            onClick: () => load(),
          }, t('refresh'))),
        h('p', { style: { fontSize: 12, lineHeight: 1.6, color: 'var(--dsw-alias-label-secondary)', margin: 0 } }, t('intro')),
        h('div', { style: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
          h(AddEntryForm, { t, onAdded: load, disabled: restricted }),
          h('input', {
            type: 'text', value: entryQuery, placeholder: t('entrySearch'), style: inputStyle,
            onChange: (e) => setEntryQuery(e && e.target ? e.target.value : ''),
          })),
        status === 'loading' && !data
          ? h('p', { style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)' } }, t('loading'))
          : status === 'error' && !data
            ? (denied ? null : h('p', { style: { fontSize: 12, color: 'var(--dsw-alias-state-error-primary)' } }, t('error')))
            : visibleEntries.length === 0
              ? h('p', { style: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)' } }, t('empty'))
              : h('div', { style: { display: 'grid', gap: 8 } },
                h('div', {
                  style: { display: 'flex', gap: 10, padding: '0 12px', fontSize: 11, color: 'var(--dsw-alias-label-secondary)', whiteSpace: 'nowrap' },
                },
                  h('span', { style: { flex: '1 1 auto', minWidth: 0 } }, t('colValue')),
                  h('span', { style: { flex: '0 0 100px' } }, t('colCategory')),
                  h('span', { style: { flex: '0 0 120px' } }, t('colKind')),
                  h('span', { style: { flex: '0 0 110px' } }, '')),
                ...visibleEntries.map((entry) => {
                  const revealed = Boolean(shown[entry.ph]);
                  const value = revealed ? shown[entry.ph] : (entry.name || entry.preview || entry.ph);
                  const copyState = copied === entry.ph
                    ? t('copyOk')
                    : copied === `error:${entry.ph}` ? t('copyFail') : null;
                  return h('div', { key: entry.ph, style: { ...boxStyle, alignItems: 'center' } },
                    h('span', { style: { flex: '1 1 auto', minWidth: 0, display: 'grid', gap: 2 } },
                      h('span', {
                        style: {
                          ...monoStyle,
                          color: revealed ? 'var(--dsw-alias-state-warn-label)' : 'var(--dsw-alias-label-primary)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        },
                        title: revealed ? shown[entry.ph] : (entry.name || entry.ph),
                      }, value),
                      h('span', { style: { ...monoStyle, fontSize: 11, color: 'var(--dsw-alias-label-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, entry.ph)),
                    h('span', { style: { flex: '0 0 100px', fontSize: 12, color: 'var(--dsw-alias-label-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, title: entry.label || '' }, entry.label || '—'),
                    h('span', { style: { flex: '0 0 120px', fontSize: 12, color: 'var(--dsw-alias-label-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, title: entry.rule || '' }, entry.rule),
                    h('div', { style: { flex: '0 0 110px', display: 'flex', gap: 6, justifyContent: 'flex-end' } },
                      h('button', {
                        type: 'button', className: 'dsguard-btn',
                        style: { ...btnStyle, opacity: restricted ? 0.45 : 1, cursor: restricted ? 'not-allowed' : 'pointer' },
                        'aria-pressed': revealed,
                        'aria-label': restricted ? t('restrictedUnlock') : t(revealed ? 'hide' : 'reveal'),
                        title: restricted ? t('restrictedUnlock') : t(revealed ? 'hide' : 'reveal'),
                        disabled: restricted,
                        onClick: () => { if (!restricted) toggle(entry.ph); },
                      }, h(LockGlyph, { open: revealed })),
                      h('button', {
                        type: 'button', className: 'dsguard-btn',
                        style: { ...btnStyle, width: copyState ? 'auto' : 30, padding: copyState ? '0 8px' : 0, fontSize: 11, opacity: restricted ? 0.45 : 1, cursor: restricted ? 'not-allowed' : 'pointer' },
                        'aria-label': t('copyPlain'), title: t('copyPlain'),
                        disabled: restricted,
                        onClick: () => { if (!restricted) copyPlaintext(entry.ph); },
                      }, copyState || h(CopyGlyph)),
                      entry.pinned
                        ? h('button', {
                          type: 'button', className: 'dsguard-btn',
                          style: { ...btnStyle, width: 'auto', padding: '0 8px', fontSize: 11, opacity: restricted ? 0.45 : 1 },
                          title: t('entryDelete'), disabled: restricted,
                          onClick: () => deleteEntry(entry.ph),
                        }, t('entryDelete'))
                        : null));
                }),
                revealedAny(shown)
                  ? h('p', { style: { fontSize: 11, color: 'var(--dsw-alias-state-warn-label)', margin: 0 } }, t('autoHide'))
                  : null),
        h('p', { style: { fontSize: 11, lineHeight: 1.6, color: 'var(--dsw-alias-label-secondary)', margin: 0 } }, `${t('placeholder')} · ${t('usage')}`),
        h('p', { style: { fontSize: 11, color: 'var(--dsw-alias-label-secondary)', margin: 0 } }, `inline reveal: ${inlineState}`),
        data && data.lastError
          ? h('p', { style: { fontSize: 11, color: 'var(--dsh-alias-state-error-primary, var(--dsw-alias-state-error-primary))', margin: 0 } }, `lastError: ${data.lastError}`)
          : null),
        confirmDisable
          ? h(DisableConfirm, {
            t,
            onCancel: () => setConfirmDisable(false),
            onConfirm: () => applyPause({ action: 'disable' }),
          })
          : null);
    }

    function revealedAny(shown) {
      return Object.keys(shown).length > 0;
    }

    const PH_RE = /<SG_[0-9a-f]{12}>/g;
    /** Visible in Settings so a broken registration is diagnosable without DevTools. */
    let inlineState = 'unknown';

    /** Colour by what leaked, not by which regex fired. */
    const TONES = {
      password: { bg: 'rgba(226,75,74,0.16)', border: 'rgba(226,75,74,0.55)' },
      token: { bg: 'rgba(127,119,221,0.18)', border: 'rgba(127,119,221,0.55)' },
      key: { bg: 'rgba(29,158,117,0.18)', border: 'rgba(29,158,117,0.55)' },
      other: { bg: 'rgba(85,135,200,0.16)', border: 'rgba(85,135,200,0.5)' },
    };

    const TONE_RULES = [
      [/password|passwd|pwd|密码|口令|凭证|私钥/i, 'password'],
      [/token|jwt|bearer|令牌/i, 'token'],
      [/key|密钥|secret/i, 'key'],
    ];

    function toneOf(label) {
      const name = String(label || '');
      for (const [re, tone] of TONE_RULES) if (re.test(name)) return TONES[tone];
      return TONES.other;
    }

    /** placeholder → vault metadata, so a chip can colour itself on first paint. */
    let metaByPh = new Map();
    let metaInflight = null;

    function loadMeta() {
      if (metaInflight) return metaInflight;
      metaInflight = fetch('/guard/vault', { cache: 'no-store' })
        .then((res) => (res.ok ? res.json() : null))
        .then((json) => {
          if (json && Array.isArray(json.entries)) {
            const map = new Map();
            for (const entry of json.entries) {
              map.set(entry.ph, entry);
              // Pre-0.4.0 codes are kept as aliases so chips in old sessions
              // still pick up the right colour.
              for (const alias of Array.isArray(entry.aliases) ? entry.aliases : []) map.set(alias, entry);
            }
            metaByPh = map;
          }
          return metaByPh;
        })
        .catch(() => metaByPh)
        .finally(() => { metaInflight = null; });
      return metaInflight;
    }

    /**
     * Inline chip for a `<SG_…>` placeholder inside a user message. Clicking it
     * asks the host for the plaintext (`/guard/reveal`, loopback-only) and
     * re-masks on its own. The plaintext never enters model context: this is a
     * browser fetch, not a tool result.
     */
    function RevealChip({ ph, interactive }) {
      const [value, setValue] = useState(null);
      const [busy, setBusy] = useState(false);
      const [tone, setTone] = useState(() => {
        const entry = metaByPh.get(ph);
        return toneOf(entry && (entry.label || entry.rule));
      });
      const timer = useRef(0);

      useEffect(() => () => window.clearTimeout(timer.current), []);

      useEffect(() => {
        if (metaByPh.has(ph)) return undefined;
        let alive = true;
        loadMeta().then((map) => {
          if (!alive) return;
          const entry = map.get(ph);
          if (entry) setTone(toneOf(entry.label || entry.rule));
        });
        return () => { alive = false; };
      }, [ph]);

      const toggle = useCallback(async () => {
        if (value !== null) {
          window.clearTimeout(timer.current);
          setValue(null);
          return;
        }
        if (busy) return;
        setBusy(true);
        try {
          const res = await fetch('/guard/reveal', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ placeholder: ph }),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const json = await res.json();
          // The chip sits immediately after the vendor prefix (`sk-`), so it must
          // show only the tail — otherwise revealing reads as `sk-sk-abc123`.
          setValue(typeof json.body === 'string' && json.body.length > 0 ? json.body : json.plaintext);
          window.clearTimeout(timer.current);
          timer.current = window.setTimeout(() => setValue(null), REVEAL_MS);
        } catch {
          /* remain masked */
        } finally {
          setBusy(false);
        }
      }, [value, busy, ph]);

      return h('span', {
        style: {
          display: 'inline-flex',
          alignItems: 'center',
          gap: 0,
          padding: '0 1px 0 7px',
          margin: '0 2px',
          borderRadius: 6,
          border: `1px solid ${tone.border}`,
          background: value !== null ? 'rgba(212,90,48,0.20)' : tone.bg,
          fontFamily: 'var(--dsw-alias-font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)',
          fontSize: '0.92em',
          lineHeight: 1.5,
          verticalAlign: 'baseline',
          whiteSpace: 'nowrap',
        },
      },
        h('span', {
          style: {
            color: value !== null ? 'var(--dsw-alias-state-warn-label)' : 'var(--dsw-alias-label-secondary)',
            userSelect: value !== null ? 'text' : 'none',
          },
          title: value !== null ? undefined : ph,
        }, value !== null ? value : ph),
        interactive === false
          ? null
          : h('button', {
            type: 'button',
            className: 'dsguard-btn',
            style: {
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 18,
              height: 18,
              flex: 'none',
              padding: 0,
              borderRadius: 5,
              border: 'none',
              background: 'transparent',
              color: 'var(--dsw-alias-label-secondary)',
              cursor: 'pointer',
            },
            'aria-pressed': value !== null,
            'aria-label': value !== null ? '隐藏明文' : '显示明文',
            title: value !== null ? '隐藏明文' : '显示明文',
            disabled: busy,
            onClick: toggle,
          }, h(LockGlyph, { open: value !== null })));
    }

    /**
     * Hosts contributed by the conversation package. Everything here is
     * best-effort: a missing service or a changed slot contract must degrade to
     * "placeholder shown as plain text", never break the message list.
     */
    function registerInlineReveal(ctx, slots) {
      const install = (conv) => {
        if (!conv || !conv.userText || typeof conv.userText.register !== 'function') {
          inlineState = 'no-service';
          return;
        }

        try {
          conv.userText.register({
            id: 'sensitive-guard',
            order: 20,
            match(text, from) {
              PH_RE.lastIndex = from;
              const m = PH_RE.exec(text);
              if (m === null) return undefined;
              return {
                id: 'sensitive-guard',
                start: m.index,
                end: m.index + m[0].length,
                data: { ph: m[0] },
              };
            },
          });
        } catch (error) {
          inlineState = 'matcher-failed';
          console.warn('[sensitive-guard] userText rule registration failed:', error && error.message);
          return;
        }

        try {
          // Keyed child slot: it matches on `key`, not `id`, and the injector is
          // a generator whose yielded disposers the slot owns. Registering with
          // `id` silently falls through to "missing renderer", which shows the
          // original fragment — the placeholder stays plain text.
          slots.inject('conversation.user.text.node', function* () {
            try {
              yield slots.register({
                name: 'conversation.user.text.node',
                key: 'sensitive-guard',
                priority: 100,
              }, (props) => h(RevealChip, {
                ph: props && props.node && props.node.data ? props.node.data.ph : '',
                interactive: props ? props.interactive : true,
              }));
              inlineState = 'ok';
            } catch (error) {
              inlineState = 'renderer-failed';
              console.warn('[sensitive-guard] inline renderer registration failed:', error && error.message);
            }
          });
        } catch (error) {
          inlineState = 'slot-inject-failed';
          console.warn('[sensitive-guard] conversation slot injection failed:', error && error.message);
        }
      };

      // `ctx.get` is a one-shot probe. On a cold boot the conversation package
      // may not have provided `uiConversation` yet: it returns undefined, and the
      // chip then stays off for the whole session. That is exactly why the lock
      // showed up on one launch and disappeared on the next. Declare the
      // dependency instead — cordis calls back when the service arrives, and
      // again if it is re-created.
      let ready = null;
      try {
        ready = typeof ctx.get === 'function' ? ctx.get('uiConversation') : null;
      } catch {
        /* not provided yet; fall through to the declared wait */
      }
      if (ready) {
        install(ready);
        return;
      }

      inlineState = 'waiting';
      try {
        ctx.inject(['uiConversation'], (sub) => install(sub.uiConversation));
      } catch (error) {
        inlineState = 'no-service';
        console.warn('[sensitive-guard] cannot wait for uiConversation:', error && error.message);
      }
    }

    function apply(ctx) {
      // The host is fail-fast: a throwing client entry stops the entire app from
      // booting ("web boot: 1 entry did not activate"). Never let one plugin do that.
      try {
        applyEntry(ctx);
      } catch (error) {
        console.warn('[sensitive-guard] plugin disabled after error:', error && error.message);
      }
    }

    function applyEntry(ctx) {
      const slots = ctx && ctx.slots;
      if (!slots || typeof slots.inject !== 'function' || typeof slots.register !== 'function') return;
      // Inline reveal only needs slots, so register it before the settings page —
      // a missing locale service must not cost users the in-conversation lock.
      registerInlineReveal(ctx, slots);
      const locale = ctx && ctx.locale;
      if (!locale) return;
      if (typeof locale.register !== 'function' || typeof locale.bind !== 'function') return;
      try {
        ctx.effect(() => locale.register(NS, { zh, en }), 'sensitive-guard: dictionaries');
      } catch (error) {
        console.warn('[sensitive-guard] dictionary registration failed:', error && error.message);
      }
      const t = locale.bind(NS);
      slots.inject('settings.section', () => {
        try {
          return slots.register({
            name: 'settings.section',
            id: 'sensitive-guard',
            order: 60,
            label: () => t('nav'),
            locale: NS,
            inject: () => ({ t }),
          }, () => h(GuardView, { t }));
        } catch (error) {
          console.warn('[sensitive-guard] settings section registration failed:', error && error.message);
          return undefined;
        }
      });
    }

    return { inject: ['slots', 'locale'], apply };
  },
});
