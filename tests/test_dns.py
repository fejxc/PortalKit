import socket
import struct

import pytest

from portalkit.network import dns


def answer(query, *, flags=0x8180, address=b'\x08\x08\x08\x08'):
    return (query[:2] + struct.pack('>5H', flags, 1, 1, 0, 0) + query[12:]
            + b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + address)


@pytest.mark.parametrize('winner', ['udp', 'tcp', 'doh', None])
def test_fallback_order_and_wire_answer(monkeypatch, winner):
    calls = []
    def exchange(query, resolver, interface, timeout, transport):
        assert interface == 'physical-test'
        assert 0 < timeout <= 3
        calls.append(transport)
        if transport != winner:
            raise socket.timeout()
        return answer(query)
    monkeypatch.setattr(dns, '_exchange', exchange)
    evidence = []
    result = dns.dns_query_a('example.com', '8.8.8.8', 'physical-test', timeout=3, evidence=evidence)
    assert result == ('8.8.8.8' if winner else None)
    assert calls == ['udp', 'tcp', 'doh'][:(['udp', 'tcp', 'doh'].index(winner) + 1) if winner else 3]
    assert len(evidence) == len(calls)


@pytest.mark.parametrize('flags,address', [(0x8380, b'\x08'*4), (0x8183, b'\x08'*4),
                                          (0x8180, b'\xc6\x12\x00\x01')])
def test_invalid_or_fake_ip_answer_fails_closed(monkeypatch, flags, address):
    monkeypatch.setattr(dns, '_exchange', lambda q, *args: answer(q, flags=flags, address=address))
    assert dns.dns_query_a('example.com', '8.8.8.8') is None


def test_tcp_framing_handles_fragmented_reads(monkeypatch):
    class Sock:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def connect(self, address): assert address == ('8.8.8.8', 53)
        def sendall(self, data): assert data == b'\x00\x03abc'
        chunks = iter([b'\x00', b'\x03', b'a', b'bc'])
        def recv(self, count): return next(self.chunks)
    monkeypatch.setattr(dns, '_socket', lambda *args: Sock())
    assert dns._exchange(b'abc', '8.8.8.8', 'physical', 1, 'tcp') == b'abc'


def test_doh_bootstrap_is_bound_and_certificate_verified(monkeypatch):
    calls = []
    class Sock:
        def connect(self, address): calls.append(address)
    monkeypatch.setattr(dns, '_socket', lambda interface, kind, timeout:
                        calls.append((interface, kind, timeout)) or Sock())
    class Response:
        status = 200
        def getheader(self, *args): return 'application/dns-message'
        def read(self, limit): return b'dns-wire-answer'
    class HTTPS:
        def __init__(self, host, timeout, context):
            assert host == '1.1.1.1'
            assert context.check_hostname and context.verify_mode == dns.ssl.CERT_REQUIRED
        def request(self, method, path, body, headers):
            assert (method, path, body) == ('POST', '/dns-query', b'query')
            self._create_connection(('1.1.1.1', 443), timeout=2)
        def getresponse(self): return Response()
        def close(self): calls.append('closed')
    monkeypatch.setattr(dns.http.client, 'HTTPSConnection', HTTPS)
    assert dns._exchange(b'query', None, 'physical-test', 2, 'doh') == b'dns-wire-answer'
    assert calls == [('physical-test', socket.SOCK_STREAM, 2), ('1.1.1.1', 443), 'closed']


def test_private_portal_dns_still_supported(monkeypatch):
    monkeypatch.setattr(dns, '_exchange', lambda q, *args: answer(q, address=b'\x0a\x01\x02\x03'))
    assert dns.dns_query_a('portal.example', '10.1.1.1') == '10.1.2.3'
