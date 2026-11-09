"""通用 ePortal 适配器：新校园 = 一份站点配置，不再必写代码。

ePortal 是国内高校最普遍的认证后台家族之一（InterFace.do / pageInfo /
无填充 RSA / success.jsp 语义，厂商实现高度一致）。zstu 即该协议的一个
已验收实例——本模块把 ZstuAdapter 参数化：

- `adapter_id` / `name`：信任与凭据按 (adapter_id, portal_host) 键控，
  各校独立，互不串号；
- `entry_url`：白名单放行探针域名的网络里 authenticate 的最后手段直连；
- `host_hint`：同网存在多个 ePortal 门户（如不同校区网段）时防止误配。

新站点配置见 `portalkit/adapters/eportal_sites.py`（用户可自定义 JSON，
无需发版）。协议私有逻辑（bootstrap/RSA/登录分类）仍归属 zstu 模块——
它是唯一经过真实门户交叉验证的实现，通用层不做任何协议假设。
"""

from __future__ import annotations

from portalkit.adapters.base import DetectionResult
from portalkit.adapters.zstu import DEFAULT_DISCOVERY_URL, DISCOVERY_CANDIDATES, ZstuAdapter

DEFAULT_API_VERSION = 1


class EPortalAdapter(ZstuAdapter):
    """参数化 ePortal 门户适配器（zstu 的泛化）。"""

    def __init__(
        self,
        *,
        adapter_id: str,
        name: str,
        entry_url: str | None = None,
        host_hint: str | None = None,
        discovery_url: str = DEFAULT_DISCOVERY_URL,
        discovery_candidates: tuple[str, ...] | None = None,
    ) -> None:
        super().__init__(
            discovery_url=discovery_url,
            entry_url=entry_url,
            discovery_candidates=discovery_candidates if discovery_candidates is not None else DISCOVERY_CANDIDATES,
        )
        self.id = adapter_id
        self.name = name
        self.api_version = DEFAULT_API_VERSION
        self._host_hint = host_hint

    def _match_redirect(self, host: str | None, url: str, *, cert: str | None,
                        extra: tuple[str, ...] = ()) -> DetectionResult:
        result = super()._match_redirect(host, url, cert=cert, extra=extra)
        if result.matched and self._host_hint and host != self._host_hint:
            # ePortal 的识别判据是路径含 "eportal"，同网多门户会互相误认——
            # 站点配置给出 host_hint 时严格过滤。
            return DetectionResult(
                matched=False, adapter_id=self.id,
                evidence=(f"eportal host {host} != site hint {self._host_hint}",) + extra,
            )
        return result
