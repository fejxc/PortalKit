"""PortalKit P0 命令行（PRD F10）。

    portalkit status | check | authenticate | diagnostics
    portalkit trust list|add|revoke
    portalkit credentials set|delete|list
    portalkit adapters

约定：
- 密码只经 getpass/stdin 输入，绝不放 argv / 环境变量；
- `--json` 输出 StateSnapshot.to_dict()（schema_version 随附）；
- 退出码：0 正常（含已联网/无需认证）；1 需要用户操作；2 网络/系统错误；3 内部错误。
"""

from __future__ import annotations

import argparse
import getpass
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from portalkit.adapters import default_registry
from portalkit.adapters.base import Credentials
from portalkit.core.engine import DEFAULT_STATE_DIR, Engine
from portalkit.core.trust import TrustRecord, TrustRegistry
from portalkit.credentials.service import KeychainCredentialService
from portalkit.diagnostics.logging import RedactedLogger
from portalkit.models import ErrorCode, Phase, StateSnapshot
from portalkit.network.monitor import NetworkMonitor

_EXIT_OK = 0
_EXIT_ACTION_REQUIRED = 1
_EXIT_ERROR = 2
_EXIT_INTERNAL = 3

_ACTION_PHASES = {
    Phase.TRUST_REQUIRED,
    Phase.WAITING_USER,
    Phase.DEGRADED,
}


def _build_engine(state_dir=None) -> Engine:
    logger = RedactedLogger(
        sink_path=(state_dir or DEFAULT_STATE_DIR) / "events.jsonl",
        echo_stderr=False,
    )
    return Engine(
        monitor=NetworkMonitor(),
        registry=default_registry(),
        trust=TrustRegistry(),
        credentials=KeychainCredentialService(),
        logger=logger,
        state_dir=state_dir,
    )


def _emit(state: StateSnapshot, as_json: bool) -> None:
    if as_json:
        print(json.dumps(state.to_dict(), ensure_ascii=False, indent=2))
        return
    print(f"状态: {state.message_key} ({state.phase.value})")
    print(f"  link={state.link.value} portal={state.portal.value} internet={state.internet.value}")
    if state.interface:
        print(f"  接口: {state.interface}  generation: {state.network_generation}")
    if state.adapter_id:
        print(f"  适配器: {state.adapter_id}")
    if state.error_code != ErrorCode.NONE:
        print(f"  错误: {state.error_code.value}")
    if state.detail:
        print(f"  说明: {state.detail}")
    for item in state.evidence:
        print(f"  · {item}")


def _exit_for(state: StateSnapshot) -> int:
    if state.phase in _ACTION_PHASES:
        return _EXIT_ACTION_REQUIRED
    if state.phase in (Phase.ERROR, Phase.CANCELLED) or state.error_code == ErrorCode.ENGINE_BUSY:
        return _EXIT_ERROR
    return _EXIT_OK


# ------------------------------------------------------------------ commands

def cmd_status(args) -> int:
    engine = _build_engine()
    snap = engine._monitor.current_snapshot()  # noqa: SLF001 — CLI 属 core 同包消费方
    if args.json:
        print(json.dumps(snap.to_dict(), ensure_ascii=False, indent=2))
    else:
        if snap.ready:
            print(f"物理网络: {snap.interface}  IP: {snap.ipv4}  网关: {snap.gateway}")
        else:
            print("物理网络: 未连接")
        print(f"指纹: {snap.fingerprint}  时间: {snap.timestamp}")
    state_path = (args.state_dir or DEFAULT_STATE_DIR) / "state.json"
    if state_path.exists():
        try:
            last = json.loads(state_path.read_text(encoding="utf-8"))
        except ValueError:
            last = None
        if last:
            if args.json:
                print(json.dumps({"last_state": last}, ensure_ascii=False, indent=2))
            else:
                print(
                    f"上次状态: {last.get('phase')} ({last.get('message_key')})"
                    f" @ {last.get('timestamp')}"
                )
    return _EXIT_OK


def cmd_check(args) -> int:
    state = _build_engine(args.state_dir).check()
    _emit(state, args.json)
    return _exit_for(state)


def cmd_authenticate(args) -> int:
    state = _build_engine(args.state_dir).authenticate()
    _emit(state, args.json)
    return _exit_for(state)


def cmd_refresh_session(args) -> int:
    state = _build_engine(args.state_dir).refresh_session()
    _emit(state, args.json)
    return _exit_for(state)


def cmd_diagnostics(args) -> int:
    state_dir = args.state_dir or DEFAULT_STATE_DIR
    print("== PortalKit 诊断（脱敏） ==")
    cmd_status(args)
    registry = TrustRegistry()
    records = registry.all()
    print(f"\n受信目标 {len(records)} 项:")
    for rec in records:
        tls = rec.scheme.upper()
        warning = "（HTTP 明文——凭据传输不加密）" if rec.scheme == "http" else ""
        print(f"  - [{rec.adapter_id}] {rec.portal_host}:{rec.portal_port} {tls}{warning}")
        print(f"    信任时间: {rec.created_at or '未知'}  证书指纹: {rec.cert_sha256 or '未固定'}")
    events_path = state_dir / "events.jsonl"
    if events_path.exists():
        lines = events_path.read_text(encoding="utf-8").splitlines()
        if args.tail > 0:
            lines = lines[-args.tail:]
        print(f"\n最近事件 {len(lines)} 条:")
        for line in lines:
            try:
                item = json.loads(line)
                print(
                    f"  {item.get('ts', '')} {item.get('event')}"
                    f" phase={item.get('phase', '')} err={item.get('error', '')}"
                )
            except ValueError:
                continue
    return _EXIT_OK


def cmd_adapters(args) -> int:
    from portalkit.adapters import default_registry as _dr

    reg = _dr()
    for adapter in reg.all():
        print(f"{adapter.id:8} {adapter.name}  api_version={adapter.api_version}")
    return _EXIT_OK


def cmd_ui(args) -> int:
    """启动菜单栏宿主（前台；登录自启见 portalkit startup install）。"""
    from portalkit.ui.menubar import main as ui_main

    return ui_main()


def cmd_startup(args) -> int:
    from portalkit.ui import launchagent

    if args.action == "install":
        ok = launchagent.install()
        print("登录启动已安装并拉起菜单栏。" if ok else
              "已写入 LaunchAgent，但 launchctl 拉起失败；查看 ~/Library/Logs/portalkit-ui.log")
        return _EXIT_OK if ok else _EXIT_ERROR
    if args.action == "uninstall":
        launchagent.uninstall()
        print("登录启动已移除。")
        return _EXIT_OK
    print(f"状态: {launchagent.status()}  ({launchagent.plist_path()})")
    return _EXIT_OK


def cmd_app(args) -> int:
    if args.action == "install":
        from portalkit.ui.appbundle import build_bundle, bundle_path

        path = build_bundle(sys.executable)
        print(f"已创建应用: {path}")
        print("双击启动，或：open -a PortalKit")
        return _EXIT_OK
    if args.action == "open":
        from portalkit.ui.appbundle import bundle_path

        path = bundle_path(Path(args.install_dir) if args.install_dir else None)
        if not path.exists():
            print(f"未找到 {path}；先运行 portalkit app install", file=sys.stderr)
            return _EXIT_ACTION_REQUIRED
        subprocess.run(["open", str(path)], check=False)
        return _EXIT_OK
    print("用法: portalkit app install | app open", file=sys.stderr)
    return _EXIT_INTERNAL


# -------------------------------------------------------------- trust 管理

def cmd_trust_list(args) -> int:
    records = TrustRegistry().all()
    if not records:
        print("（无受信目标）")
        return _EXIT_OK
    for rec in records:
        print(f"[{rec.adapter_id}] {rec.portal_host}:{rec.portal_port} ({rec.scheme})")
        print(f"  允许宿主: {', '.join(rec.allowed_hosts)}")
        print(f"  页面指纹: {rec.fingerprint or '未固定'}  证书指纹: {rec.cert_sha256 or '未固定'}")
        print(f"  信任时间: {rec.created_at or '未知'}")
    return _EXIT_OK


def cmd_trust_add(args) -> int:
    registry = default_registry()
    adapter = registry.get(args.adapter)
    if adapter is None:
        print(f"未知适配器: {args.adapter}（可用: {', '.join(registry.ids())}）", file=sys.stderr)
        return _EXIT_INTERNAL

    print(f"正在探测以识别 {adapter.name} 门户（不提交任何凭据）…")
    engine = _build_engine(args.state_dir)
    report = engine.detect()
    if not report.snapshot.ready:
        print("物理网络未连接，无法识别门户。", file=sys.stderr)
        return _EXIT_ERROR
    matched = next(
        (r for r in report.results if r.matched and r.adapter_id == adapter.id), None
    )
    if args.host:
        # 手动指定目标（门户入口与 discovery 不同宿主时的兜底）。
        parts = urlsplit(args.host if "://" in args.host else f"https://{args.host}")
        scheme = args.scheme or (parts.scheme or "https")
        matched = matched.__class__(
            matched=True, adapter_id=adapter.id,
            portal_scheme=scheme,
            portal_host=parts.hostname or args.host,
            portal_port=args.port or parts.port or (443 if scheme == "https" else 80),
            fingerprint=matched.fingerprint if matched else None,
            observed_cert_sha256=matched.observed_cert_sha256 if matched else None,
            evidence=("manually specified target",),
        )
    if matched is None or matched.portal_host is None:
        print("未能在当前网络识别该适配器的门户，无法添加信任。", file=sys.stderr)
        for result in report.results:
            for item in result.evidence:
                print(f"  · {item}", file=sys.stderr)
        return _EXIT_ERROR

    host, port, scheme = matched.portal_host, matched.portal_port, matched.portal_scheme or "https"
    print()
    print("== 待信任目标确认 ==")
    print(f"  适配器:   {adapter.name} ({adapter.id})")
    print(f"  认证目标: {scheme}://{host}:{port}")
    print(f"  凭据宿主: 仅以上目标（重定向跳出即终止）")
    if matched.fingerprint:
        print(f"  页面指纹: {matched.fingerprint}")
    if matched.observed_cert_sha256:
        print(f"  证书指纹: {matched.observed_cert_sha256}")
    if scheme == "http":
        print("  ⚠ 该门户为 HTTP 明文：凭据传输不加密，请确认你信任当前网络。")
    for item in matched.evidence:
        print(f"  · {item}")
    print()
    if not args.yes:
        answer = input("确认信任以上目标并允许此后自动认证？[y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("已取消，未保存信任。")
            return _EXIT_ACTION_REQUIRED
    record = TrustRecord(
        adapter_id=adapter.id, portal_host=host, portal_port=port,
        scheme=scheme, allowed_hosts=(host,),
        cert_sha256=matched.observed_cert_sha256,
        fingerprint=matched.fingerprint,
        network_hint=f"iface={report.snapshot.interface} gw={report.snapshot.gateway}",
        created_at=report.snapshot.timestamp,
        note="cli trust add",
    )
    TrustRegistry().add(record)
    print(f"已保存信任记录: [{adapter.id}] {host}:{port}")
    print("下一步: portalkit credentials set --adapter " + adapter.id)
    return _EXIT_OK


def cmd_trust_revoke(args) -> int:
    registry = TrustRegistry()
    records = [r for r in registry.all() if r.adapter_id == args.adapter]
    if args.host:
        records = [r for r in records if r.portal_host == args.host]
    if not records:
        print("没有匹配的信任记录。", file=sys.stderr)
        return _EXIT_ACTION_REQUIRED
    for rec in records:
        if args.yes or input(f"撤销 [{rec.adapter_id}] {rec.portal_host}:{rec.portal_port} 的信任？[y/N] ").strip().lower() in ("y", "yes"):
            registry.revoke(rec.adapter_id, rec.portal_host)
            print(f"已撤销: [{rec.adapter_id}] {rec.portal_host}")
    return _EXIT_OK


# --------------------------------------------------------- credentials 管理

def cmd_credentials_set(args) -> int:
    registry = default_registry()
    adapter = registry.get(args.adapter)
    if adapter is None:
        print(f"未知适配器: {args.adapter}", file=sys.stderr)
        return _EXIT_INTERNAL
    trust = TrustRegistry()
    records = [r for r in trust.all() if r.adapter_id == args.adapter]
    if not records:
        print("该适配器尚无受信目标；请先 portalkit trust add。", file=sys.stderr)
        return _EXIT_ACTION_REQUIRED
    target = records[0]
    username = args.username or input("账号: ").strip()
    if not username:
        print("账号不能为空。", file=sys.stderr)
        return _EXIT_ACTION_REQUIRED
    password = getpass.getpass("密码（不回显）: ")
    if not password:
        print("密码不能为空。", file=sys.stderr)
        return _EXIT_ACTION_REQUIRED
    service = KeychainCredentialService()
    service.save(adapter.id, target.portal_host, username, password)
    print(f"已保存 {adapter.id} @ {target.portal_host} 的凭据到 Keychain（账号 {username}）。")
    print("下一步: portalkit authenticate")
    return _EXIT_OK


def cmd_credentials_delete(args) -> int:
    service = KeychainCredentialService()
    trust = TrustRegistry()
    records = [r for r in trust.all() if r.adapter_id == args.adapter]
    if not records:
        print("没有匹配的凭据记录。", file=sys.stderr)
        return _EXIT_ACTION_REQUIRED
    target = records[0]
    usernames = service.usernames(args.adapter, target.portal_host)
    if not usernames:
        print("该目标没有已保存凭据。", file=sys.stderr)
        return _EXIT_ACTION_REQUIRED
    if service.delete(args.adapter, target.portal_host, usernames[0]):
        print(f"已删除 {args.adapter} @ {target.portal_host} 的凭据。")
        return _EXIT_OK
    print("删除失败。", file=sys.stderr)
    return _EXIT_ERROR


def cmd_credentials_list(args) -> int:
    service = KeychainCredentialService()
    trust = TrustRegistry()
    found = False
    for rec in trust.all():
        for username in service.usernames(rec.adapter_id, rec.portal_host):
            found = True
            print(f"[{rec.adapter_id}] {rec.portal_host}  账号: {username}  (密码已存 Keychain)")
    if not found:
        print("（无已保存凭据）")
    return _EXIT_OK


# ------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="以 JSON 输出结构化状态")
    common.add_argument("--state-dir", help=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="portalkit", description="PortalKit 门户认证助手（P0 CLI）",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, **kwargs):
        return sub.add_parser(name, parents=[common], **kwargs)

    add("status", help="当前网络快照与上次状态（不探测）").set_defaults(func=cmd_status)

    add("check", help="物理网络探测 + 门户识别（不提交凭据）").set_defaults(func=cmd_check)

    add("authenticate", help="对已信任目标执行认证与物理验证").set_defaults(func=cmd_authenticate)
    add("refresh-session", help="探测已信任门户的注销入口并尝试刷新会话").set_defaults(func=cmd_refresh_session)

    p = add("diagnostics", help="脱敏诊断摘要")
    p.add_argument("--tail", type=int, default=20, help="事件条数")
    p.set_defaults(func=cmd_diagnostics)

    add("adapters", help="列出已注册适配器").set_defaults(func=cmd_adapters)

    add("ui", help="启动菜单栏宿主").set_defaults(func=cmd_ui)

    startup = add("startup", help="登录启动管理")
    startup_sub = startup.add_subparsers(dest="action", required=True)
    startup_sub.add_parser("install", parents=[common]).set_defaults(func=cmd_startup)
    startup_sub.add_parser("uninstall", parents=[common]).set_defaults(func=cmd_startup)
    startup_sub.add_parser("status", parents=[common]).set_defaults(func=cmd_startup)

    app_p = add("app", help="本地 PortalKit.app（双击启动）管理")
    app_sub = app_p.add_subparsers(dest="action", required=True)
    app_sub.add_parser("install", parents=[common]).set_defaults(func=cmd_app)
    p = app_sub.add_parser("open", parents=[common], help="启动已安装的 PortalKit.app")
    p.add_argument("--install-dir", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_app)

    trust = sub.add_parser("trust", help="信任目标管理", parents=[common])
    trust_sub = trust.add_subparsers(dest="subcommand", required=True)
    trust_sub.add_parser("list", parents=[common]).set_defaults(func=cmd_trust_list)
    p = trust_sub.add_parser("add", help="识别当前网络门户并确认信任", parents=[common])
    p.add_argument("--adapter", required=True)
    p.add_argument("--host", help="手动指定认证目标（默认自动识别）")
    p.add_argument("--port", type=int)
    p.add_argument("--scheme", choices=("http", "https"))
    p.add_argument("--yes", action="store_true", help="跳过交互确认（仅自动化场景）")
    p.set_defaults(func=cmd_trust_add)
    p = trust_sub.add_parser("revoke", help="撤销信任", parents=[common])
    p.add_argument("--adapter", required=True)
    p.add_argument("--host")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_trust_revoke)

    creds = sub.add_parser("credentials", help="凭据管理", parents=[common])
    creds_sub = creds.add_subparsers(dest="subcommand", required=True)
    p = creds_sub.add_parser("set", help="录入账号密码（密码经 getpass，不入 argv）", parents=[common])
    p.add_argument("--adapter", required=True)
    p.add_argument("--username")
    p.set_defaults(func=cmd_credentials_set)
    p = creds_sub.add_parser("delete", parents=[common])
    p.add_argument("--adapter", required=True)
    p.set_defaults(func=cmd_credentials_delete)
    creds_sub.add_parser("list", parents=[common]).set_defaults(func=cmd_credentials_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断。", file=sys.stderr)
        return _EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 — CLI 顶层兜底，不打印含敏感值的栈
        print(f"内部错误: {type(exc).__name__}: {exc}", file=sys.stderr)
        return _EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
