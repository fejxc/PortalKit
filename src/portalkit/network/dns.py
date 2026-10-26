"""物理接口 DNS：UDP → TCP → 经证书校验的 IP bootstrap DoH。

每次查询共享超时预算；禁止回退系统 resolver（可能是 TUN fake-ip）。
"""
from __future__ import annotations

import http.client
import ipaddress
import random
import socket
import ssl
import struct
import time

_IP_BOUND_IF = getattr(socket, "IP_BOUND_IF", 25)
DOH_IP = "1.1.1.1"


def is_ip_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 4
    except ValueError:
        return False


def _skip_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        b = data[offset]
        if b & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        if b & 0xC0 or offset + b + 1 > len(data):
            raise ValueError("invalid DNS label")
        offset += 1
        if b == 0:
            return offset
        offset += b
    raise ValueError("truncated DNS name")


def _parse_answer(data: bytes, query: bytes) -> str | None:
    if len(data) < 12:
        return None
    rid, flags, qd, an, _, _ = struct.unpack(">6H", data[:12])
    txid = struct.unpack(">H", query[:2])[0]
    if rid != txid or not flags & 0x8000 or flags & 0x020F or qd != 1:
        return None
    end = _skip_name(data, 12) + 4
    if data[12:end] != query[12:]:
        return None
    offset = end
    for _ in range(an):
        offset = _skip_name(data, offset)
        rtype, rclass, _, size = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + size > len(data):
            return None
        if rtype == 1 and rclass == 1 and size == 4:
            address = ipaddress.IPv4Address(data[offset:offset + 4])
            # 私网门户域名合法；fake-ip 绝不能与物理接口组合使用。
            if not address.is_unspecified and not address.is_multicast and address not in ipaddress.ip_network("198.18.0.0/15"):
                return str(address)
        offset += size
    return None


def _socket(interface: str | None, kind: int, timeout: float):
    sock = socket.socket(socket.AF_INET, kind)
    try:
        if interface:
            sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, socket.if_nametoindex(interface))
        sock.settimeout(timeout)
        return sock
    except BaseException:
        sock.close()
        raise


def _recv_exact(sock, count: int) -> bytes:
    result = b""
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise OSError("truncated DNS stream")
        result += chunk
    return result


def _exchange(query: bytes, resolver: str, interface: str | None,
              timeout: float, transport: str) -> bytes:
    if transport == "doh":
        # 用 IP 建连，标准 TLS 校验 IP SAN；不关闭校验，不需要额外 DNS。
        conn = http.client.HTTPSConnection(DOH_IP, timeout=timeout,
                                           context=ssl.create_default_context())
        def connect(address, timeout=None, source_address=None):
            sock = _socket(interface, socket.SOCK_STREAM, timeout)
            try:
                sock.connect((DOH_IP, 443))
                return sock
            except BaseException:
                sock.close()
                raise
        conn._create_connection = connect
        try:
            conn.request("POST", "/dns-query", body=query,
                         headers={"Content-Type": "application/dns-message",
                                  "Accept": "application/dns-message"})
            response = conn.getresponse()
            if response.status != 200 or response.getheader("Content-Type", "").split(";")[0] != "application/dns-message":
                return b""
            return response.read(65536)
        finally:
            conn.close()
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    with _socket(interface, kind, timeout) as sock:
        sock.connect((resolver, 53))  # UDP connect 也校验响应来源
        if transport == "udp":
            sock.send(query)
            return sock.recv(4096)
        sock.sendall(struct.pack(">H", len(query)) + query)
        size = struct.unpack(">H", _recv_exact(sock, 2))[0]
        return _recv_exact(sock, size)


def dns_query_a(name: str, resolver: str | None, interface: str | None = None,
                timeout: float = 4.0, *, evidence: list[str] | None = None) -> str | None:
    evidence = evidence if evidence is not None else []
    try:
        txid = random.SystemRandom().randint(0, 0xFFFF)
        labels = [label.encode("idna") for label in name.rstrip(".").split(".")]
        if not labels or any(not label or len(label) > 63 for label in labels):
            raise ValueError("invalid DNS name")
        query = (struct.pack(">6H", txid, 0x0100, 1, 0, 0, 0)
                 + b"".join(bytes([len(label)]) + label for label in labels)
                 + b"\0" + struct.pack(">HH", 1, 1))
        deadline = time.monotonic() + timeout
        for index, transport in enumerate(("udp", "tcp", "doh")):
            if transport != "doh" and not resolver:
                evidence.append(f"dns.{transport}:skip(no-resolver)")
                continue
            budget = (deadline - time.monotonic()) / (3 - index)
            if budget <= 0:
                evidence.append(f"dns.{transport}:fail(budget)")
                continue
            try:
                answer = _parse_answer(_exchange(query, resolver, interface, budget, transport), query)
                if answer:
                    evidence.append(f"dns.{transport}:pass")
                    return answer
                evidence.append(f"dns.{transport}:fail(invalid-or-no-answer)")
            except (OSError, ValueError, struct.error, http.client.HTTPException) as exc:
                evidence.append(f"dns.{transport}:fail({type(exc).__name__})")
    except (ValueError, UnicodeError, struct.error):
        evidence.append("dns:fail(invalid-name)")
    return None
