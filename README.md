<div align="center">

<img src="assets/appicon.png" width="96" alt="PortalKit 图标">

# PortalKit

**macOS 智能网络门户认证助手** —— 连上图书馆 / 校园网后自动识别门户、认证登录，并**通过物理网卡路径**验证真实联网。安静运行，异常时说清楚原因、给出下一步。

[![CI](https://github.com/fejxc/PortalKit/actions/workflows/ci.yml/badge.svg)](https://github.com/fejxc/PortalKit/actions/workflows/ci.yml)
[![Release](https://github.com/fejxc/PortalKit/actions/workflows/release.yml/badge.svg)](https://github.com/fejxc/PortalKit/releases)
[![GitHub Release](https://img.shields.io/github/v/release/fejxc/PortalKit)](https://github.com/fejxc/PortalKit/releases/latest)
![Platform](https://img.shields.io/badge/platform-macOS%2015%2B%20Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## 为什么需要它

公共 Wi-Fi 的 captive portal（认证门户）有两个恼人之处：每次连网都要手动打开登录页；而且当"连不上网"时，你分不清是**没认证**、**密码错了**、还是**网络本身的问题**——尤其当你同时跑着 Clash TUN 这类代理，代理能上网会制造"在线"的假象。

PortalKit 解决这两件事：

- **自动认证**：识别到已信任的门户后，用保存在 Keychain 的凭据自动登录，全程不需要打开浏览器；
- **诚实判定**：所有"已联网"结论必须来自**绑定物理网卡的探针证据**——代理隧道通不算数、门户返回个 200 也不算数。DNS、TCP、HTTP 逐层报告，卡在哪一层一目了然。

<div align="center">
<img src="assets/menubar-states.png" width="640" alt="菜单栏六种状态">
<br><sub>菜单栏状态一览：空闲 / 检测中 / 认证中 / 已联网 / 需处理 / 离线（template 图标，深浅色菜单栏自适应，形态互不相同——不依赖颜色也能分辨）</sub>
</div>

## 功能特性

- **三维状态模型**：物理链路（link）/ 门户（portal）/ 互联网（internet）独立判定，拒绝把复杂现实压成一个布尔值
- **物理路径强制**：socket 经 `IP_BOUND_IF` 钉在物理网卡，DNS 经该网卡的解析器解析——Clash TUN 接管默认路由与 fake-ip DNS 时依然走真实路径
- **分层探测**：DNS(UDP/TCP/DoH 回退) → TCP 建连 → HTTP 特征标记，逐层留证据；IP 直连诊断不计入联网票数（防劫持页假阳性）
- **凭据安全**：密码只存 macOS Keychain（SecKeychain API），不进 argv / 环境变量 / 日志；日志与诊断导出双重脱敏
- **信任门槛**：首次遇到门户必须显式确认目标（含证书指纹 pinning）；门户改版或证书更换 → 自动提交立即暂停
- **门户语义独立**：每个适配器声明自己的魔法码（zjlib 的 404=已认证），绝不共用
- **切网自动恢复**：SystemConfiguration 事件驱动（低频兜底），网络代际（generation）变化自动取消在途任务
- **菜单栏原生应用**：rumps/PyObjC 实现，独立打包后无需任何 Python 环境
- **门户语义化错误**：密码错误 / 需要验证码 / 门户改版 / 临时网络故障分开报告，只有临时故障做有界退避重试

## 安装

### 普通用户（推荐）

从 [Releases](https://github.com/fejxc/PortalKit/releases/latest) 下载 `PortalKit-x.x.x-macos-arm64.zip`，解压后把 **PortalKit.app** 拖入「应用程序」，双击打开（纯菜单栏应用，无 Dock 图标）。

> 当前为 ad-hoc 签名的个人构建：首次打开若提示无法验证，**右键 → 打开**即可。

### 从源码运行（开发 / CLI）

```bash
git clone https://github.com/fejxc/PortalKit.git
cd PortalKit
python3 -m venv .venv
.venv/bin/pip install -e '.[ui,dev]'

.venv/bin/pytest                    # 全部测试（无需真实网络与凭据）
.venv/bin/portalkit --help
.venv/bin/portalkit app install     # 构建独立 PortalKit.app 到 /Applications
```

运行时零第三方依赖（纯标准库）；`ui` extra（rumps/PyObjC）仅菜单栏需要，`dev` 是 pytest。

## 使用

### 菜单栏应用（主要方式）

首次使用流程：连接目标 Wi-Fi → 点菜单栏图标 → **「添加 / 确认可信网络…」**，查看门户证据（目标、证书指纹）并勾选确认 → **「录入 / 更新凭据…」**保存账号密码到 Keychain → 之后每次连网自动认证。

日常只需看图标：**实心圆=已联网**，圆弧=检查中，盾=认证中，叹号=需要你操作（点开菜单有说明），叉=未连网。异常时点 **「诊断与日志…」** 查看三层状态与脱敏事件，可导出诊断包。

### CLI（无头 / 调试）

```bash
portalkit status                  # 网络快照 + 上次状态（不探测）
portalkit check --json            # 物理探测 + 门户识别，不提交凭据
portalkit authenticate            # 对已信任门户认证 + 物理验证
portalkit refresh-session         # 强制刷新门户会话（在线时安全跳过）
portalkit diagnostics --tail 30   # 脱敏诊断摘要
portalkit trust list|add|revoke   # 信任目标管理
portalkit credentials set|list|delete
portalkit app install [--dev]     # 打包独立 .app
portalkit startup install|status  # 登录自启（LaunchAgent）
```

`--json` 输出带 `schema_version` 的结构化状态（`link/portal/internet/phase/error_code/evidence`），适合脚本与自动化。退出码：`0` 正常、`1` 需要用户操作、`2` 网络/系统错误。

## 当前支持的门户

| 门户 | 适配器 | 认证方式 | 状态 |
|---|---|---|---|
| 浙江图书馆 Wi-Fi（2.2.1.1:8443，大学路馆区 / 城市书房） | `zjlib` | 自签 HTTPS，iframe 登录页 + Mac 端 XHR 七字段；**404 = 已认证** | ✅ 真实网络回归通过 |
| 浙江理工大学校园网 ePortal | `zstu` | 302 动态发现 → pageInfo 动态 RSA 公钥 → getServices → 双重编码提交；**204 = 已在线** | ⚠️ 已按真实流程实现，待现场回归 |

新增门户 = 实现一个 Python 适配器（`src/portalkit/adapters/`，参照 `base.py` 契约与现有两例），协议私有逻辑留在适配器内，绑定 / 重试 / 信任 / 凭据全部由 core 提供。

## 安全设计

- **凭据边界**：密码仅经 `getpass` / GUI 安全输入框进入进程，存 Keychain（`PortalKit.<adapter>.<host>`），任何 repr / 日志 / 诊断导出路径不回显；CLI 禁止用参数传密码
- **信任模型**：仅凭 IP 可达或同名 SSID 不构成信任；信任记录绑定适配器身份 + 目标 host:port + 证书指纹 + 页面结构指纹，任一变化自动提交即暂停；携带凭据的请求阶段重定向越界立即终止，**绝不带凭据跟随未知目标**
- **完成判定红线**：认证"提交成功"≠"已联网"——只有物理接口路径上多探针（≥2 通过）验证后才显示已联网；验证不过则如实报告"连接待验证"
- **日志脱敏**：密码 / Cookie / JSESSIONID / userIndex / RSA 明文永不落日志；诊断导出前二次扫描
- **进程权限**：仅当前用户权限运行，不 root、不改系统代理、不做网络扩展；登录自启用用户级 LaunchAgent

## 架构

```text
菜单栏宿主 (rumps/PyObjC)          ← 只消费状态、只发命令，零第二状态机
    └── core/engine               ← 调度：单任务互斥、generation 取消、有界退避
        ├── network/              ← 物理接口发现、IP_BOUND_IF 绑定 HTTP、按接口 DNS、分层探针
        ├── adapters/             ← zjlib / zstu（协议私有逻辑；契约见 base.py）
        ├── core/trust            ← 可信目标注册表（证书 + 页面双指纹 pinning）
        ├── credentials/          ← Keychain（ctypes SecKeychain）
        └── diagnostics/          ← 脱敏结构化日志
```

状态对外的唯一形态是 `StateSnapshot`（序列化稳定，为将来 SwiftUI 宿主预留）；UI 与核心同进程起步，不为此过度设计 IPC。

## 开发

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[ui,dev]'
.venv/bin/pytest -q                 # 90+ 测试：假门户服务器、RSA 向量、调度/信任/脱敏回归
.venv/bin/portalkit app install     # 本地构建独立 .app（PyInstaller）
```

**发布**：改 `pyproject.toml` 版本 → `git tag vX.Y.Z && git push origin vX.Y.Z`，GitHub Actions 自动测试、构建、签名、发布（产物为自包含 `.app`，见 `.github/workflows/release.yml`）。

测试不含真实凭据；门户回归用 `tests/fakeserver.py` 的本地假门户覆盖 404 / 204 / 302 / RSA / 改版等分支。

## 已知限制

- 仅支持 **Apple Silicon + macOS 15+**；未签名分发，换机首次打开需右键 → 打开
- 不自动处理验证码 / 短信 / MFA——识别到即转人工（菜单提示），不会反复尝试
- `zstu` 适配器尚未在真实校园网回归；新门户需按适配器契约开发
- 不管理 Clash 配置 / 规则 / 订阅；不提供流量统计（没有可靠测量就不展示数字）
- 门户为 HTTP 明文时会明确警示（凭据传输不加密），是否信任由用户决定

## 致谢

- 门户认证流程的原始实现与协议逆向，来自作者的个人脚本库（zjlib v2.0 / zstu ePortal 路由器版）
- 菜单栏图标与 App 图标设计：ChatGPT 图像生成 + 人工调校

## License

[MIT](LICENSE) © 2026 fejxc
