# dsh-sensitive-guard

DeepSeek Harness（DSH）的插件，只做一件事：把密钥、令牌、密码挡在模型上下文之外。用户消息和工具结果里的凭证，在进入上下文之前就被换成 `<SG_xxxxxxxxxxxx>` 占位符，明文加密留在本机。模型拿到的是代号，你点一下能看到真值。

代号里那 12 位十六进制是 `sha256(明文)` 的前缀，不可逆，只用来保证同一个密钥每次都是同一个代号。

## 它往宿主里注册了什么

DSH 插件分 host 端和客户端两半，这个插件两半都占：host 端抓数据、管保管库、开接口；客户端加设置页和对话里的胶囊。

| 注册点 | 端 | 作用 |
| --- | --- | --- |
| `agent/pre-step` | host 钩子 | 用户输入进上下文前脱敏 |
| `tools/post-execute` | host 钩子 | 工具结果进上下文前脱敏 |
| `llm/stream` | host 钩子 | 出网的流式文本兜底清洗 |
| `sensitive_guard_status`、`sensitive_guard_export` | host 工具 | 查状态；把明文导出成 0600 临时文件 |
| `/guard/vault`、`/guard/reveal`、`/guard/settings` | HTTP 路由 | 设置页取数、揭示明文、暂停开关 |
| `settings.section` | 客户端 slot | 设置页里的「敏感保护」 |
| `conversation.user.text.node` | 客户端 slot | 对话里的锁形胶囊 |

前提只要 `tools` 一个。`webServer` 不存在时脱敏照常工作，只是设置页和揭示用不了。

## 长什么样

遮住的时候，对话里是 `sk-` 后面跟一个锁：

![对话里被遮住的凭证](https://raw.githubusercontent.com/wangxy496/dsh-sensitive-guard/main/docs/chat-masked.png)

点一下锁，就地显示明文，20 秒后自动遮回：

![点开后显示明文](https://raw.githubusercontent.com/wangxy496/dsh-sensitive-guard/main/docs/chat-revealed.png)

设置页列出保管库里全部条目，行尾的锁同样能揭示：

![设置页](https://raw.githubusercontent.com/wangxy496/dsh-sensitive-guard/main/docs/settings.png)

## 安装

要求 dsh 0.2.0 以上、Node 18 以上。Windows 11 和 Ubuntu 22.04 都实测过，macOS 没测。

三种装法，按场景选。

**从 npm 装**（给使用者）。编辑 `~/.dsh/profiles/<profile>/package.json`：

```json
{
  "dependencies": {
    "dsh-sensitive-guard": "0.3.2"
  },
  "dsh": {
    "profile": {
      "bundles": ["dsh-sensitive-guard"]
    }
  }
}
```

`bundles` 里保留原有条目，只追加这一项。然后在同目录跑 `pnpm install`，重启 dsh。

**让 dsh 自己装**（不想手改文件的场合）。在会话里说「安装这个目录下的插件：/绝对/路径」，它走 `install_bundle`。

**本地改代码用 link**。把版本号换成 `"link:/absolute/path/to/sensitive-guard"`，源码改动立刻生效，但 host 端的改动还是要重启进程。

## 确认装好了

发一句：

```
我的 api key 是 sk-proj-abcdefghijklmnopqrstuvwx
```

应该显示成 `我的 api key 是 sk-` 加一个锁形胶囊。点开能看到明文，20 秒后自动遮回。

再看「设置 → 敏感保护」，最下面一行 `inline reveal:` 显示 `ok` 就正常，显示别的就翻到文末「卸载和故障」。

## 日常怎么用

**对话里看明文。** 用户消息里的占位符会渲染成可点的胶囊，颜色按类型分：密码红、token 紫、key 绿、其它蓝，点开后统一变橙。点击走本机接口，明文不经过模型。

只有用户消息能点。AI 回复和工具结果走另一套节点渲染，宿主没留「包一层」的口子，要接就得整体替换助手的消息渲染，宿主升级会白屏，所以没做。那些位置到设置页看。

**设置页。** 顶部是暂停开关，下面是保管库条目，每条都能点锁查看，揭示会记审计。暂停有三档：30 分钟、2 小时、到重启。连不上数据库、模型读不到密码的时候点一下就行，到期自动恢复。「到重启」不写盘，重启就恢复。

**模型怎么用凭据。** 它拿不到明文。要连库或者调接口时让它导出：

```
sensitive_guard_export(<SG_xxx>)   明文写到 0600 文件，返回路径
命令里用 $(cat /那个/路径)          明文不进上下文
```

工具只有两个。`sensitive_guard_status` 看状态和条目元数据，不含明文，连前 8 位预览都不返回。`sensitive_guard_export` 负责导出，文件 15 分钟后过期。

常被当成 bug 的一点：模型读 `application.yml` 时看到的是占位符，拿它去连库必然失败。要么让它先导出，要么临时点个暂停。

## 数据在哪

三处是分开的。

| | 内容 |
| --- | --- |
| 模型上下文 | `<SG_1e62c5fe7944>`，哈希前缀，不可逆 |
| 磁盘 | `v1:iv:tag:密文`，AES-256-GCM，密钥在 `vault.key` |
| 屏幕 | 代号加锁，点开才向本机要明文 |

拦截点有两个：用户输入走 `agent/pre-step`，工具结果走 `tools/post-execute`。另外 `llm/stream` 会洗一遍出网的流式文本做兜底，只处理 `text-delta` 和 `reasoning-delta`，`tool-call-delta` 放过，否则工具参数会变成占位符。

## 认得出什么

厂商前缀：`sk-`、`sk_`、`ghp_`、`glpat-`、`npm_`、`hf_`、`AKIA`、`ASIA`、`xox*-`、`AIza`、`whsec_`、`SG.`。PEM 私钥块、JWT、`Bearer` 令牌。

赋值和环境变量：`password=`、`secret:`、`api_key:`、`SECRET_KEY=`、`DB_PASSWORD=`。

中文说法：`数据库密码是…`、`我的 token 是…`。

连接串：`mysql://user:pass@host`、`postgresql://…`、JDBC 参数里的 `password=`、`X-Api-Key:`。

命令行：`mysql -uroot -pabc12345`、`redis-cli -a xxx`。只认这几个客户端，`docker run -p 8080:80` 不会被误伤。

被换行打断的 key 也认：从网页、截图或终端里粘贴时，`sk-proj-…` 常被插进 `\r`、`\n` 或 `\r\n`（`\r` 在界面上看着仍是同一行）。这类会按跨行匹配，把两段拼回完整值再入库，占位符与不换行时完全相同。

**可选的熵值检测，默认关闭。** `rules.json` 里加 `"entropy": true` 才会开。它抓的是没有前缀的随机串，但只对 base64 或混合字符集有用（熵约 4.8 到 5.0 bits/char）。纯 hex 串的上限就是 4.0，永远够不到 4.5 的默认阈值，所以 `8f3a9b2c…` 这种开了也抓不到；把阈值降到 3.9 又会误伤英文长句。另外 base64 图片、commit hash、UUID 都会被判成高熵。

抓不到的三类：自研格式的凭据，得自己往 `extraRules` 加正则；二进制和图片里的；被 base64 或 hex 二次编码搬运过的。

## 配置

`<数据目录>/rules.json`，存盘后两秒内生效，不用重启。Windows 下是 `%USERPROFILE%\.dsh\sensitive-guard\`，Linux 下是 `~/.dsh/sensitive-guard/`。

```json
{
  "extraRules": [
    { "id": "my-internal", "pattern": "X-WX-Token:\\s*([A-Za-z0-9]{20,})", "flags": "i", "group": 1 }
  ],
  "disabled": ["jwt"],
  "outboundScrub": true,
  "entropy": false,
  "entropyThreshold": 4.5,
  "allowCidrs": ["192.168.0.0/16"]
}
```

`group` 是要遮挡的捕获组序号，0 表示整个匹配。自定义正则的性能自己负责，别写 `(a+)+`、`(.*)*` 这类结构，它跑在同步钩子里，回溯爆炸会卡住宿主。

`disabled` 里写规则 id 可以关掉单条内置规则。`outboundScrub: false` 会关掉出网补洗。

`allowCidrs` 默认是空数组，意思是只认本机。它管的是 HTTP 接口，下一节细说。

## 从别的机器访问

桌面版不用管这节。三个 HTTP 接口默认只接受本机回环，浏览器和 dsh 在同一台机器上，天然满足。

只有一种情况会碰到：dsh 以 `--host 0.0.0.0` 或 `--host 192.168.x.x` 启动，你又从另一台机器的浏览器打开。这时来源不是回环，接口会拒。两个办法：

一是在服务所在那台机器的浏览器里打开 `127.0.0.1:3080`，不用改任何配置。

二是放行网段，在数据目录的 `rules.json` 里加一行：

```json
{ "allowCidrs": ["192.168.0.0/16"] }
```

存盘两秒生效。设置页顶栏会出现橙色提示，说明当前是从局域网进来的。

没配的时候页面不会白屏，会降级成只读：能看到有哪些条目、什么类型、什么时候入库、命中几次，看不到值，也看不到 8 位预览。顶部给一张说明卡，写着当前地址和可以直接抄的配置，网段按你的来源地址算好了。

放行之后除了网段匹配，还有三道检查，都不用配。Host 头必须是 IP 字面量，防 DNS rebinding，因为 rebinding 需要一个域名，而 Origin 和 Host 会一起被伪造，只靠同源校验分不出来。POST 必须是 `application/json`，这样跨站的 `text/plain` 表单发不进来，服务端也不应答 CORS 预检。最后 Origin 必须和 Host 同源。

开放网段意味着这个网段里任何设备都能读到完整明文，不只是预览。只在可信内网开，用完把这行删掉。没做登录是因为加一套认证会让点小锁多两步，不如把网段收窄。

## HTTP 接口

四个接口，默认只接受本机回环。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/guard/vault` | 面板数据，含 8 位预览和 `access` 当前级别；未授权来源返回 `restricted: true` 的只读版，不含预览和审计 |
| POST | `/guard/reveal` | `{placeholder}` 换 `{plaintext, body, prefix}`；未授权 403 |
| GET | `/guard/settings` | `{paused, untilRestart, until, remainingMs}`；未授权 403 |
| POST | `/guard/settings` | `{action:"pause", minutes:30}`、`{action:"pause", untilRestart:true}`、`{action:"resume"}`；未授权 403 |

## 已知限制

1. 对话里的胶囊只覆盖用户消息，原因见「日常怎么用」。
2. 不做出口改写。平台的 `tools/pre-execute` 只有 allow、deny、cancel、ask 四个动作，没有改参数的挂点，所以用凭据只能走导出文件。
3. 保管库防的是误读和落盘明文，不防已经拿到你账户权限的人。加密是 AES-256-GCM，密钥文件在 Windows 上用 `icacls` 收紧到当前账户。
4. 历史会话不受保护。`pre-step` 在宿主把用户原文写进日志之后才执行，`session/event` 又只是个观察者，插件没有机会在落盘前改。旧会话里的明文还在磁盘上，那批密钥该轮换。
5. `exports/` 下是唯一落盘的明文，15 分钟后在下次导出时清理。
6. 保管库最多留 500 条，超出按最后命中时间淘汰。
7. 保管库坏掉时会放行，保证对话不中断，但会计数，在 `sensitive_guard_status` 里能看到 `failOpen`。
8. 单条文本只扫前 200000 字符。钩子是同步跑的，防止自定义正则的回溯拖死宿主，代价是超长文本尾部不遮挡。
9. `allowCidrs` 建立在「网段可信」这个假设上。它挡 CSRF 和 DNS rebinding，不挡网段内的主动攻击者。别写 `0.0.0.0/0`，那个值会被拒绝并记进 `rules.error`。
10. 未授权来源仍然能读到元数据：有哪些条目、什么规则、什么时候入库、命中几次。这是为了让设置页能自我解释，代价是同网段的人能推断出「这里有 12 条凭据、分别是钥匙密码令牌」，但拿不到值。
11. 宿主是 fail-fast 的，客户端 entry 在模块顶层抛错会让整个应用起不来。`apply` 已经整体兜底，顶层风险消不掉。

## 卸载和故障

正常卸载：编辑 `~/.dsh/profiles/<profile>/package.json`，删掉 `dependencies` 里的 `"dsh-sensitive-guard": "link:…"`，以及 `dsh.profile.bundles` 数组里的 `"dsh-sensitive-guard"`，重开应用。

如果应用打不开了，日志里是 `web boot: N entry did not activate` 加 `dsh-sensitive-guard: failed`，先结束残留进程：

```
taskkill /F /IM "DeepSeek Harness.exe"
```

再按上面的步骤摘掉依赖。崩溃日志在 `%APPDATA%\@deepseek-ai\dsh-desktop\logs\crash-*-web-boot.log`。

`inline reveal:` 那行的取值：`ok` 正常，`waiting` 还在等 `uiConversation` 服务，`no-service` 拿不到服务，`matcher-failed` 规则注册被拒，`renderer-failed` 渲染器注册被拒。

数据目录在 `$DSH_PROFILE_DIR/sensitive-guard/`，包含 `vault.json`、`vault.key`、`pause.json`、`rules.json`、`exports/`。没设这个变量时回落到 `$DSH_HOME` 下。

## 开发

```bash
node test.mjs
```

56 项离线自测，用临时目录，不碰真实保管库。

| 文件 | 作用 |
| --- | --- |
| `index.js` | host 端：三条钩子、保管库、两个工具、三条路由 |
| `client.js` | 客户端：设置页、对话内胶囊、暂停开关 |
| `test.mjs` | 自测 |
| `CHANGELOG.md` | 变更记录 |
| `locale/` | 插件市场用的中英元数据 |

GitHub Actions 在 ubuntu 和 windows 上跑 node 18、20、22 三个版本。许可证 MIT。
