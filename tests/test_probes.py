from portalkit.models import InternetState
from portalkit.network import probes
from portalkit.network.http import HTTPResult, NetworkRequestError


def client_factory(monkeypatch, mode):
    class Client:
        def __init__(self, **kwargs):
            assert kwargs['interface'] == 'physical-test'
            self.evidence = []
            self.cert_sink = {}
        def request(self, url, **kwargs):
            self.cert_sink['tcp_connected'] = False
            if mode == 'online':
                p = next(p for p in probes.INTERNET_PROBES if p.url == url)
                self.cert_sink['tcp_connected'] = True
                body = '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>' if p.name == 'apple-captive' else p.marker or ''
                return HTTPResult(p.expect_status, url, body)
            if '223.5.5.5' in url:
                self.cert_sink['tcp_connected'] = True
                return HTTPResult(404, url, '<html>login</html>')
            if '1.1.1.1' not in url:
                self.evidence.extend(['dns.udp:fail(TimeoutError)', 'dns.tcp:fail(ConnectionRefusedError)', 'dns.doh:fail(TimeoutError)'])
            elif mode == 'tcp-only':
                self.cert_sink['tcp_connected'] = True
            raise NetworkRequestError('failed')
    monkeypatch.setattr(probes, 'BoundHTTPClient', Client)


def test_partial_path_not_online_and_layers_independent(monkeypatch):
    client_factory(monkeypatch, 'tcp-only')
    result = probes.check_internet('physical-test', '8.8.8.8')
    assert result.state == InternetState.UNKNOWN
    assert not result.reachable and result.passed == 0
    assert any(e.layer == 'dns.tcp' and e.outcome == 'fail' for e in result.layers)
    assert any(e.probe == 'ip-cloudflare' and e.layer == 'tcp' and e.outcome == 'pass' for e in result.layers)
    assert any(e.probe == 'ip-cloudflare' and e.layer == 'http' and e.outcome == 'fail' for e in result.layers)
    assert any('http404' in e for e in result.evidence)


def test_bound_markers_grant_online(monkeypatch):
    client_factory(monkeypatch, 'online')
    result = probes.check_internet('physical-test', '8.8.8.8')
    assert result.reachable and result.passed == 4


def test_no_interface_never_grants_online(monkeypatch):
    monkeypatch.setattr(probes, 'BoundHTTPClient', lambda **kwargs: None)
    assert not probes.check_internet(None, None).reachable


def test_login_page_with_generic_success_word_is_not_online():
    from portalkit.network.http import HTTPResult
    class Client:
        def request(self, url):
            return HTTPResult(200, url, '<!DOCTYPE html><html>Success! Login required</html>')
    for probe in probes.INTERNET_PROBES:
        assert not probes._probe_once(Client(), probe)[0]
