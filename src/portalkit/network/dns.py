"""按物理接口的 DNS A 查询（最小 UDP 实现，零依赖）。

动机（审计 F7 / 决策 D2）：Clash TUN fake-ip 模式下系统 resolver（如
198.18.0.2）会把域名解析成假 IP；普通 getaddrinfo 拿到的地址与绑定网卡
组合后会连到错误目标。这里直接把 UDP DNS 查询经 `IP_BOUND_IF` 钉在物理
接口上、发给该接口 DHCP 下发的真实解析器，绕开 fake-ip。
"""

from __future__ import annotations

import random
import re
import socket
import struct

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# 同 http.py：不能依赖 socket.IP_BOUND_IF 暴露（部分构建缺失），回退常量 25。
_IP_BOUND_IF = getattr(socket, "IP_BOUND_IF", 25)


def is_ip_literal(host: str) -> bool:
    return bool(_IPV4_RE.fullmatch(host))


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        if offset >= len(data):
            raise ValueError("DNS 报文越界")
        b = data[offset]
        if b & 0xC0:
            return offset + 2
        if b == 0:
            return offset + 1
        offset += 1 + b


def dns_query_a(
    name: str,
    resolver: str,
    interface: str | None = None,
    timeout: float = 4.0,
) -> str | None:
    """向 resolver 查询 name 的第一条 A 记录；失败返回 None（不抛网络异常）。"""
    if not name or not resolver:
        return None
    try:
        txid = random.SystemRandom().randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(
            bytes([len(label)]) + label.encode("idna") for label in name.split(".")
        ) + b"\x00"
        query = header + qname + struct.pack(">HH", 1, 1)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if interface:
                ifindex = socket.if_nametoindex(interface)
                sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, ifindex)
            sock.settimeout(timeout)
            sock.sendto(query, (resolver, 53))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()

        if len(data) < 12:
            return None
        rid, _flags, _qd, _an_count_q, an_count, _ns, _ar = struct.unpack(
            ">HHHHHH", data[:12]
        )
        if rid != txid:
            return None
        offset = 12
        # 跳过 Question Section（QNAME + QTYPE + QCLASS）
        offset = _skip_name(data, offset) + 4
        for _ in range(an_count):
            offset = _skip_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype, _rclass, _ttl, rdlength = struct.unpack(
                ">HHIH", data[offset : offset + 10]
            )
            offset += 10
            if rtype == 1 and rdlength == 4:
                return ".".join(str(b) for b in data[offset : offset + 4])
            offset += rdlength
        return None
    except (OSError, ValueError, struct.error):
        return None
