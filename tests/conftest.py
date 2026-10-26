"""共享 fixtures：假门户 + 适配器上下文工厂。"""

from __future__ import annotations

import pytest

from fakeserver import FakePortalServer
from portalkit.adapters.base import AdapterContext
from portalkit.models import NetworkSnapshot
from portalkit.network.http import BoundHTTPClient


@pytest.fixture()
def portal():
    server = FakePortalServer()
    yield server
    server.stop()


def make_ctx(portal, *, snapshot=None, generation=1, allowed_default=None):
    def client_factory(allowed_hosts=None, *, tls_verify: bool = True):
        return BoundHTTPClient(
            interface=None,
            dns_resolver=None,
            allowed_hosts=allowed_hosts if allowed_hosts is not None else allowed_default,
            tls_verify=tls_verify,
        )

    return AdapterContext(
        snapshot=snapshot
        or NetworkSnapshot(interface=None, ipv4="127.0.0.1", gateway=None, dns=None),
        generation=generation,
        check_generation=lambda: None,
        client_factory=client_factory,
    )
