# 交接问题书：zjlib 网络「连接待验证」— 物理路径判定与恢复能力不足

> 交接对象：Codex · 日期：2026-10-26 · 仓库：`~/PortalKit`（GitHub: fejxc/PortalKit, master, 66/66 测试绿）
> 你接手的是一个**已完全定位但尚未解决**的网络判定/恢复问题。以下全部事实来自现场实测（浙江图书馆 Wi-Fi 现场），不是猜测。

## 1. 问题一句话

PortalKit 在 zjlib 网络显示「连接待验证」：门户协议层报告**会话有效**（入口 `https://2.2.1.1:8443` 及其全部路径均 HTTP 404——该门户"已认证"的语义），但**经物理网卡 en0 的互联网多探针 4/4 失败**。按产品红线（任何"已联网"必须以物理路径证据授予），当前状态是**正确且诚实**的；要解决的是**判定粒度与恢复手段**。

## 2. 环境

- macOS 15.1.1 (24B91)，MacBook Pro M3 Pro，Wi-Fi `en0`：10.18.147.89/24，网关 10.18.147.11，DHCP/手动 DNS 223.5.5.5
- **Clash.app TUN 模式常开且用户关不掉**（默认路由 `utun12`，fake-ip DNS 198.18.0.2）；浏览器经 Clash 代理可正常上网，不走代理则完全无法上网
- Python 3.14.3 (Homebrew)，项目 venv 在 `~/PortalKit/.venv`，零第三方运行时依赖（测试用 pytest）

## 3. 已验证事实（实测数据，勿重复臆测）

1. 绑定实现：`IP_BOUND_IF=25` 显式常量（该 CPython 构建不暴露 `socket.IP_BOUND_IF`），所有门户/探针流量强制从 en0 出。此实现**工作正常**。
2. 门户行为：绑 en0 访问 `https://2.2.1.1:8443` **始终可达**；`/cn/index.html`、`/cn/login.html`、`/cn/auth_success.html`、`/`、`/cn/logout.html` 等全站 **404**——已认证旁路模式，**无任何可见页面，无注销入口**。
3. 分层诊断（2026-10-26 11:00–11:55）：
   | 测试 | 结果 |
   |---|---|
   | UDP 53 出 en0（→223.5.5.5 和 →网关147.11） | 无响应 |
   | TCP 53 → 网关 147.11 | **Connection refused**（包达网关，策略拒绝）|
   | TCP 80 → 1.1.1.1 | 先 3/3 connect 成功，随后 HTTP 全超时（**状态波动**）|
   | HTTP 80 → 223.5.5.5 | 返回真实 404（**部分放行证据**）|
   | HTTP → 198.18.0.1（fake-ip 网段，绑 en0） | 超时（符合预期）|
4. **TUN 无罪的证据**：绑 en0 的包能到达网关并收到 RST、能拿到 223.5.5.5 的真实 HTTP 404——这些路径不经 TUN；若 TUN 劫持只会看到 fake-ip 或全部无响应。
5. 凭据已在 Keychain，认证提交链路完整可用；门户坚持"已认证"，无页面可提交、无自助注销。
6. PortalKit 自动化全部正常（勿动）：断网→离线→重连→自动检查+自动认证（network_generation 4→5 实测），菜单栏 UI/通知/日志均工作。

## 4. 要解决的三个子问题

### A. 判定粒度不足
`network/probes.py` 的 `check_internet` 只有 4 个域名探针 + `REACHABLE/UNKNOWN/BLOCKED` 三态，无法表达本场景的**半开状态**（TCP 出网部分可用但 DNS 全拦）。当前 evidence 只有 `fail(unreachable)`，用户和后续排查都无法区分：DNS 层断 / TCP 层断 / HTTP 标记层被劫持。
→ 期望：分层探针结果（DNS 层、TCP 层、HTTP 标记层各自的成功/失败证据）；必要时 `InternetState` 增加更细状态或结构化 evidence。

### B. DNS 无弹性
`network/dns.py` 的 `dns_query_a` 仅 UDP 单路径。UDP 53 被拦即全灭。
→ 期望：按序回退（接口 UDP DNS → TCP DNS → DoH 443 → IP 直连探针绕开 DNS），每层结果记入 evidence。注意：TCP DNS → 外网也被拦（实测超时），网关 53 拒绝——所以回退链的终点必须是 **IP 直连探针**（如对 `1.1.1.1`/`223.5.5.5` 的 80 端口发 Host 头正确的 GET，按响应特征判真外网 vs 劫持页）。

### C. 恢复手段缺失
门户全站 404 时产品没有任何"强制刷新会话"的动作。
→ 期望（按优先级）：探测该门户家族的注销 API 是否在 404 环境下仍存活（**先探测再结论，禁止臆造 URL**——可从原脚本仓库 `~/Documents/zjlib-wifi/zjlib_login_page_debug.html` 的 logout 按钮行为入手，只读参考）；探测失败则给出可操作文案（指引忽略网络重加/找管理员）。**注意：`~/Documents/zjlib-wifi` 是冻结的个人仓库，只读，任何改动禁止。**

## 5. 复现与验证命令

```bash
cd ~/PortalKit && .venv/bin/pytest -q                 # 66 passed 基线
.venv/bin/portalkit check --json                      # 当前: DEGRADED / verify_failed
.venv/bin/portalkit diagnostics --tail 20             # 事件链
# 分层诊断脚本模式（绑 en0 + IP 直连，绕开系统 fake-ip DNS）：
.venv/bin/python -c "from portalkit.network.http import BoundHTTPClient; \
  print(BoundHTTPClient(interface='en0').request('http://223.5.5.5/', timeout=6).status)"
```
真实环境 = 连接 zjlib Wi-Fi + Clash TUN 开启。若不在该网络，用 `tests/fakeserver.py` 的假门户 + 上表数据做回归即可。

## 6. 硬约束（违反即返工）

1. 任何「已联网」状态必须由**物理接口绑定路径**的探针证据授予；门户协议层结论（404=已认证）不得单独作为联网依据。
2. 不硬编码 en0；接口动态探测。
3. 不改 `IP_BOUND_IF` 绑定语义（已验证工作）；不引入 CLI argv/环境变量传密；日志脱敏红线（密码/Cookie/JSESSIONID/userIndex）。
4. 探测语义 per-adapter：zjlib 的 404=已认证，勿把他门户的魔法码共用（见 `adapters/zjlib.py` 注释与 `tests/test_zjlib.py`）。
5. 门户真实行为优先于任何文档；测试不放真实凭据。
