# 现场证据回放 fixtures

这里存放**现场事故 → 永久回归用例**的转译产物。格式为声明式 JSON，
由 `tests/test_replay.py` 加载并在 `fakeserver.py` 上重放。

## 为什么

PortalKit 的坑几乎全部出在"现场"（白名单假在线、会话卡死、互踢），
而现场证据只有当事人见过。把一次事故变成一条 fixture 后：

- 回归防线永不丢失（CI 每次重放）；
- 新适配器/重构可以直接拿现场数据当验收标准。

## 从现场到 fixture 的工作流

1. 出事机器上：菜单栏 → 诊断与日志 → **导出脱敏诊断**（已过 redact_text）。
2. 对照 `events.jsonl` 里的 HTTP 证据（状态码、跳转链、门户响应结构），
   手工整理成本目录一个 `*.json`（**不含任何真实凭据/IP/账号**）。
3. `python -m pytest tests/test_replay.py -q` 通过后随代码提交。

## 格式

```json
{
  "name": "英文短名（kebab-case）",
  "scenario": "一句话：何时、何校、什么事故",
  "adapter": "zstu | zjlib",
  "entry_url": "可选；authenticate 阶段直连门户入口（含查询参数）",
  "routes": [
    {"method": "GET", "path": "/generate_204", "status": 302, "redirect": "/eportal/index.jsp?..."},
    {"method": "GET", "path": "/eportal/index.jsp", "status": 200, "body": "<html>…</html>"},
    {"method": "POST", "path": "/eportal/InterFace.do", "status": 200, "json": {"result": "success"}}
  ],
  "run": "detect | authenticate",
  "expect": {
    "code": "success",                       // authenticate 断言 AuthCode 值
    "matched": true,                          // detect 断言
    "already_authenticated": false,
    "no_request_to": ["/eportal/InterFace.do"],  // 断言这些路径零请求（如：禁止提交）
    "request_to": ["/cn/login"]               // 断言这些路径至少一次请求
  }
}
```

- `redirect` 展开为 `Location` 头（相对路径自动拼到假门户 origin）。
- `json` 与 `body` 二选一；`json` 会以 `application/json` 返回。
- zstu 的发现候选固定注入 `/generate_204`、`/connecttest.txt`、`/ns`、`/ex`
  四个假门户路径；zjlib 的 `entry_url` 即入口页路径。
