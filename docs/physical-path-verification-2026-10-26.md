# 物理路径判定与恢复：实现及现场验证

验证时间：2026-10-26T20:17:29+08:00（Asia/Shanghai）。工作目录：`~/PortalKit`。

## 实现结果

- A：`InternetCheckResult.layers` 分别记录 DNS UDP/TCP/DoH、TCP 建连与 HTTP 标记的结果；脱敏字符串 evidence 同时进入状态 JSON、日志和诊断窗口。TCP 可达但 HTTP 不匹配时使用 UNKNOWN，保留连接待验证语义。
- B：接口 DNS 按 UDP → TCP → DoH 回退；DoH 直接连接固定 bootstrap IP、校验 TLS 证书，并使用相同物理接口绑定。不会调用系统 resolver 获取域名地址。域名探针不足两个通过时，追加 Cloudflare/AliDNS 的 IP 直连诊断；直接 IP 的响应不计入联网票数。
- C：新增 CLI `portalkit refresh-session --json` 和菜单「强制刷新会话」。在线即跳过恢复；离线须通过信任检查；仅从门户实际 HTML 提取同源 GET 注销链接，HEAD 存活后才执行，再验证登录表单恢复并认证。没有经过验证的入口时，提示忽略 Wi-Fi 后重新加入，或联系管理员清除会话/检查出口策略。JS/POST API 未经证据验证，未作猜测性适配。

## 另外修复的两个实际缺陷

1. DNS 头由六个字段构成，旧代码却解包到七个变量；异常被吞掉，导致有效响应也返回 None。新增二进制报文测试验证正常解析、错误状态/截断标志及 fake-ip 拒绝。
2. 旧 HTTP 实现把域名 URL 改为 IP，响应 URL 的 IP 随后触发域名白名单校验失败，正常响应被误判为越界跳转。现在只在底层 socket 建连时使用物理 DNS 地址，保留逻辑 URL、Host、Cookie 域及 TLS SNI；物理 `IP_BOUND_IF` 常量和绑定语义保持原样。回环假门户覆盖域名解析、相对跳转和 Cookie 保留。

NeverSSL 原来的通用 DOCTYPE 标记也改为站点特征；Microsoft 使用完整正文匹配，Apple 要求标题和正文标记，减少普通登录页造成的假阳性。

## 现场实测

当前物理接口：`en0`（运行时动态发现）。Clash TUN 保持运行，未修改系统网络设置或代理配置。

`refresh-session --json` 返回：`ONLINE_NO_AUTH / REACHABLE`，错误码 `none`，4/4 域名探针通过。因前置物理验证通过，本次未注销会话、未提交凭据。

- `gstatic-204:dns.udp:pass`
- `gstatic-204:tcp:pass`
- `gstatic-204:http:pass(http204)`
- `msft-connecttest:dns.udp:pass`
- `msft-connecttest:tcp:pass`
- `msft-connecttest:http:pass(http200)`
- `apple-captive:dns.udp:pass`
- `apple-captive:tcp:pass`
- `apple-captive:http:pass(http200)`
- `neverssl:dns.udp:pass`
- `neverssl:tcp:pass`
- `neverssl:http:pass(http200)`

首次修正 DNS 解析后，现场已能收到 UDP DNS 响应，但暴露了 HTTP URL/白名单误判。进一步修复后，先得到 3/4 通过，随后得到以上 4/4 通过。交接中的历史阻断数据不能直接当作当前网络结果，现场存在波动；本记录只陈述本次观测。

菜单栏旧进程已重启加载工作区新代码；日志确认 `engine check: phase=ONLINE_NO_AUTH err=none` 及 `ui: 已联网 (none)`。

## 注销能力证据与限制

只读检查冻结仓库的 `zjlib_login_page_debug.html`，未发现 logout/logoff/注销/退出入口；初次现场验证仍得到该门户入口 404 的会话语义。未发现可据以验证的注销 API，未枚举或硬编码猜测路径。全站 404、真实链接存活/失效、跨源链接拒绝均由假门户回归覆盖。当前物理网络在线，所以现场恢复命令只验证了安全跳过分支；没有宣称真实注销或重新认证成功。

UDP 当前成功，TCP DNS/DoH 的回退成功分支通过模拟网络测试验证，本次未人为阻断 DNS 来重复历史实验。

## 自动化验证

- 初始基线：66 项通过。
- 最终命令：`.venv/bin/pytest -q -o addopts=''`，88 passed。
- `git diff --check` 通过。
- 覆盖：DNS 各级回退、TCP 分帧、DoH bootstrap/证书校验配置、fake-ip 拒绝、私网门户 DNS、半开路径/劫持页、无接口关闭在线判定、逻辑域名/Cookie/跳转、注销入口发现及失效处理、恢复的信任门槛、在线跳过和认证后物理验证红线。

未更改冻结仓库；未增加运行时依赖；未输出密码、Cookie、会话标识或账号。
