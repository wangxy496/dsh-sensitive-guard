# 变更记录

## 0.3.3

- 修复被换行打断的厂商 key 识别不到：从网页或截图里粘贴时，`sk-proj-…` 常被插进 `\r`、`\n` 或 `\r\n`，而所有单行规则都会在断点处失配。新增 `wrapped-key` 规则，跨行匹配后把值里的空白去掉再入库，因此与完整写法共用同一个占位符。
- 新增 `debug.pre`（只出现在 `/guard/vault`，未授权来源不返回）：记录 pre-step 每次调用的 payload 字段、消息数、`kind` 与退出阶段，用于确认宿主升级后钩子是否仍然生效。
- 自测 56 → 61 项，覆盖 CRLF、纯 CR、占位符复用与「普通换行不误伤」。

## 0.3.2

- `exports` 增加 `./package.json`，修掉 `require('dsh-sensitive-guard/package.json')` 报 `ERR_PACKAGE_PATH_NOT_EXPORTED`。
- README 安装章节按 npm 发版更新：给出从 npm 装的版本号写法，`link:` 降为本地开发用。

## 0.3.1

- 设置页不再只显示「载入失败」：被拒时展示说明卡，含当前访问地址、数据目录路径，以及**按来源算好的** `allowCidrs` 配置（IPv4 取 /24，IPv6 取 /64），可直接照抄。
- 未授权来源从"一律 403"改为**只读降级**：`/guard/vault` 返回条目结构（占位符、规则、时间、命中数）但**去掉 8 位预览与审计**；揭示与暂停仍然 403，并附带修复建议。
- 只读模式下小锁置灰，提示「需在服务所在的本机打开才能揭示」。
- `/guard/vault` 新增 `dataDir`，便于用户直接定位 `rules.json`。
- 自测 47 → 56 项，覆盖降级返回结构、预览被剔除、审计被清空、建议网段、拒绝仍带修复建议。

## 0.3.0

- 新增 `allowCidrs`：默认仍**只允许本机回环**，显式配置网段后才允许局域网/远程访问三个 HTTP 接口（用于 `dsh web --host 192.168.x.x` 这类部署）。
- 非回环访问额外三道检查：`Host` 必须是 IP 字面量（挡 DNS rebinding）、POST 必须 `application/json`（强制 CORS 预检，挡跨站表单）、`Origin` 与 `Host` 同源。
- CIDR 支持 IPv4 / IPv6，兼容 `::ffff:` v4-mapped 地址；`/0` 直接拒绝并写入 `rules.error`，避免手滑全网开放。
- `/guard/vault` 新增 `access: { level, allowCidrs }`，设置页在局域网访问时显示橙色提示。
- 自测 34 → 47 项，覆盖网段放行、`/32` 不越界、rebinding、content-type 与 `/0` 拒绝。

## 0.2.9

- 文档重构：原 README 把 9 个版本的 changelog 穿插在正文中间，识别范围与安装被切碎，安装章节掉到文件末尾。拆出本文件，README 按「快速开始 → 怎么用 → 原理 → 识别范围 → 配置 → 接口 → 边界 → 恢复 → 开发」重排。
- 补齐暂停开关、对话内小锁、模型取用凭据三段使用说明。

## 0.2.8

- 新增设置页「暂停保护」：30 分钟 / 2 小时 / 到重启，切换即时生效，暂停期间三个钩子全部透传（不脱敏、不入库、不补洗）。
- `untilRestart` **不持久化**——重启即恢复保护，避免“忘了开回来”。
- 限时暂停写到 `pause.json`，重启后若未到期仍然有效；时长上限夹到 24 小时，防止手滑关一周。
- 新增 `GET/POST /guard/settings`（仅回环），暂停/恢复都记审计。
- 自测 28 → 34 项，覆盖暂停生效、恢复、回环限制。

## 0.2.7

- 新增 `cli-password`：`mysql -uroot -pabc12345`、`redis-cli -a xxx` 这类命令行密码。规则限定在确实用 `-p`/`-a` 表示密码的客户端，`docker run -p 8080:80` 有专门用例保证不误伤。
- 新增可选熵值检测：`rules.json` 里 `"entropy": true` 开启，抓无前缀的随机串。默认关闭，限制见 README「识别范围」。
- 自测 21 → 24 项，新增命令行密码、`docker -p` 负向用例、性能基准（300k 字符扫描 / 2000 个密钥替换）、熵值开关。
- 补 `LICENSE`、`.gitignore`、GitHub Actions（ubuntu + windows × node 18/20/22）。
- host 端 `apply` 与正则预编译加兜底，避免半注册状态。

## 0.2.6

- 小锁按类型上色：密码/口令→红、token/JWT/Bearer→紫、api key/密钥→绿、其它→蓝，展开时统一转橙。颜色依据 vault 里新增的 `label` 字段（命中的关键词），而不是规则 id——因为 `keyword-prose` 一条规则同时覆盖密码和 token，只看 id 分不出类型。
- 视觉收紧：去掉文字与按钮间的空隙，按钮缩到 18px，整体更像一个胶囊。
- 新增 `/guard/vault` 元数据缓存，客户端首次渲染时按需拉取一次（并发去重），给胶囊取色。

## 0.2.5

- 修复对话内小锁「一次有、一次没有」的竞态：原来用 `ctx.get('uiConversation')` 只探测一次，冷启动时 conversation 包可能还没 provide 该服务，取到 `undefined` 后就直接放弃，整个会话都不会再出现锁。改为 `ctx.get` 快速路径 + `ctx.inject(['uiConversation'], …)` 声明式等待，服务就绪（或重建）时自动补注册。
- `inline reveal:` 新增 `waiting` 状态，表示正在等服务就绪。

## 0.2.4

- `keyword-prose` 支持关键词后接下划线后缀：`SECRET_KEY=`、`DB_PASSWORD_HASH=` 这类环境变量名此前整条漏掉（`secret` 被 `_KEY` 粘住，边界和分隔符都对不上）。
- 新增 `bearer-token`：`Authorization: Bearer <不透明令牌>` 此前不命中（既无厂商前缀，也没有 `key: value` 结构）。

## 0.2.3

- 保留厂商前缀：`sk-abc123` 遮成 `sk-<SG_…>`，`AKIA…` 遮成 `AKIA<SG_…>`。上下文里能看出是哪个服务的凭据，阅读不被打断；真正会认证的尾部仍然不出现。
- `/guard/reveal` 返回三个字段：`plaintext`（完整值，设置页与导出用）、`body`（去掉前缀的尾部，对话内胶囊用）、`prefix`。这样对话里点开不会变成 `sk-sk-abc123`。
- 修复对话内小锁不显示的真正原因：keyed slot 用 `key` 匹配，之前写成了 `id`，宿主按“无渲染器”静默退回原文。同时改为官方要求的 generator 注入（`function*` + `yield`）。
- 设置页底部新增 `inline reveal:` 状态行，不开 DevTools 也能定位。

## 0.2.2

- 修复致命问题：客户端 `apply` 里访问 `ctx.uiConversation`（未在 `inject` 声明）会抛 `cannot get property … without inject`，被宿主 fail-fast 判为 entry 未激活，导致**整个应用启动失败**。现在只用 `ctx.get('uiConversation')` 且逐层 try/catch，`apply` 整体兜底。
- 规则新增 `keyword-prose`：支持 `我的 api key 是 sk-…` / `密码是 …` 这类自然语言写法（中文关键词与「是/为/就是/is」分隔符），此前只认 `=` 和 `:`，整句都被漏掉。

## 0.2.1

- 新增：用户消息里的 `<SG_…>` 直接渲染为可点锁形胶囊，点击就地揭示明文（浏览器直连 `/guard/reveal`，不进模型上下文）。
- 修正 0.2.0 的错误结论：宿主确实提供 `ctx.uiConversation.userText` 注册 matcher、`conversation.user.text.node` 注册渲染器，且节点可自带 actions。

## 0.2.0

- 修复 `llm/stream` 用 `async function` 返回 `Promise`，导致整轮崩在 `yield* ... is not async iterable`；改为 async generator，且只洗文本增量。
- 修复 `tools/post-execute` 一直在洗 `decision.content`（默认决策 `{kind:"accept"}` 没有该字段）导致脱敏空转；改为洗 `result.content`。
- `sensitive_guard_status` 不再返回 8 位预览，避免明文片段进入模型上下文。
- `/guard/vault`、`/guard/reveal` 增加回环来源校验（`0.0.0.0` 绑定时不再对局域网暴露）。
- 导出文件 15 分钟 TTL；保管库 500 条上限；写盘改为 250ms 合并。
- `webServer` 改为可选依赖，无 Web 服务时脱敏与工具照常工作。
- `vault.key` 在 Windows 上用 `icacls` 收紧 ACL；`loadKey` 并发创建改为复用胜者而不是 fail-open。
- 占位符偏移改用 `d` 标志的 `match.indices`，修复 URL 中用户名/密码相同时遮错位置。

## 0.1.0

- 首个可用版本：三个钩子入口（`agent/pre-step`、`tools/post-execute`、`llm/stream`）、AES-256-GCM 保管库、设置页解锁、导出工具、两条回环路由。
