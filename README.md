# PortalKit

面向 macOS 的智能网络门户认证助手：连接已信任的图书馆 / 校园网络后，自动识别门户、读取 Keychain 凭据、执行该门户适配器的登录流程，并**通过物理网络接口**验证互联网可达性。正常时安静运行，异常时给出明确原因与操作。

开发交接需求见 `PortalKit_Development_Handoff_v1.0`（文档、交互原型、验收矩阵）。本仓库为产品代码。

## 当前状态

- **Phase 0 完成**：真实脚本审计（zjlib / zstu）、实施决策。审计报告在交接包 `docs/repo-audit.md` 与 `docs/implementation-decisions.md`。
- **Phase 1 进行中**：P0 核心（`portalkit` CLI + 核心库，零第三方运行时依赖）。

## 安装（开发态）

```bash
cd ~/PortalKit
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest            # 单元 + 假门户回归（无真实凭据、无真实网络）
.venv/bin/portalkit --help
```

## CLI（P0）

```bash
portalkit status                  # 当前网络快照 + 上次状态（不探测、不提交凭据）
portalkit check [--json]          # 物理网络探测 + 门户识别（不提交凭据）
portalkit trust add --adapter zjlib   # 首次信任：展示门户证据与目标，交互确认
portalkit credentials set --adapter zjlib  # 账号录入（密码走 getpass，不入 argv/shell 历史）
portalkit authenticate [--json]   # 仅对已信任目标执行认证 + 物理出口验证
portalkit diagnostics             # 脱敏诊断摘要
portalkit trust list | trust revoke --adapter zjlib
portalkit credentials list | credentials delete --adapter zjlib
portalkit adapters                # 已注册适配器
```

### 安全设计要点

- 凭据存 macOS Keychain（Security.framework 经 ctypes 调用，密码不进 argv / 环境变量 / 日志）。
- 未获用户显式信任的门户目标 **0 次自动提交凭据**；门户指纹（自签证书 SHA-256 / 表单结构）变化时暂停自动认证。
- HTTP 401 / 404 / 204 等 **每个门户语义独立**（zjlib：入口 404 = 已认证；zstu：探测 204 = 已在线），不共用魔法码。
- 日志与诊断全程脱敏：不记录密码、Cookie/JSESSIONID、userIndex、RSA 明文。
- 认证"提交成功" ≠ "已联网"：只有物理接口绑定路径上的多探针验证通过才显示已联网。
- Clash TUN 共存：socket 经 `IP_BOUND_IF` 钉在物理网卡，DNS 经物理接口的 DHCP 解析器解析，绕开 fake-ip。

## 架构（Phase 1）

```text
src/portalkit/
├── models.py            # 三维状态（link/portal/internet）+ Phase/AuthCode/ErrorCode
├── core/                # 引擎、状态机、有界退避、可信目标注册表
├── network/             # 物理接口快照、IP_BOUND_IF 绑定 HTTP 客户端、按接口 DNS、分层探测、generation 监听
├── adapters/            # base 契约 + zjlib / zstu 迁移实现
├── credentials/         # Keychain（ctypes SecKeychain*）
├── diagnostics/         # 脱敏结构化日志 / 诊断导出
└── cli.py               # P0 命令行入口
```

- 运行时零第三方依赖（纯标准库）；pytest 仅用于开发。
- 网络变化监听 Phase 1 为快照对比（快照哈希 → `network_generation`）；SCDynamicStore 事件监听在 Phase 2（UI 宿主）接入。
- 适配器契约 Phase 1 为同步实现（单线程引擎 + generation 取消），与 ADAPTER_API 草案的 async 签名的差异已记录，后续如需再包装。
