"""zstu 无填充 RSA 与双重编码的独立验证（不依赖真实门户）。"""

from __future__ import annotations

import random
from urllib.parse import quote, unquote

from portalkit.adapters.zstu import (
    build_login_payload,
    js_code_units,
    js_double_encode,
    js_encode_uri_component,
    rsa_encrypt_js,
)
from portalkit.adapters.zstu import PortalConfig


def _is_probable_prime(n: int, rng: random.Random, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate, rng):
            return candidate


def _test_key():
    rng = random.Random(42)  # 固定种子：确定性测试密钥
    p = _gen_prime(256, rng)
    q = _gen_prime(256, rng)
    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    return n, e, d


def test_js_code_units_utf16():
    assert js_code_units("A") == [65]
    # 代理对：U+1F600 → UTF-16 D83D DE00
    assert js_code_units("\U0001f600") == [0xD83D, 0xDE00]


def test_js_double_encode_matches_urllib_semantics():
    value = "a b&c=d/中文"
    once = js_encode_uri_component(value)
    assert " " not in once and "&" not in once
    assert unquote(unquote(js_double_encode(value))) == value


def test_rsa_encrypt_roundtrip_with_independent_decrypt():
    n, e, d = _test_key()
    plaintext = "s3cret-pw>AA-BB-CC-DD-EE-FF"
    ciphertext = rsa_encrypt_js(plaintext, format(e, "x"), n)
    # 512 位测试密钥 chunk=62 units，27 字符明文为单块；多块拼接由 zstu 集成用例覆盖

    # 独立解密：security.js 打包的逆过程。
    # 注：security.js 的 digit = charCodeAt(i) + (charCodeAt(i+1) << 8) 对
    # ASCII（unit<256）才是无损的——这是 security.js 的已知特性，门户服务端
    # 用同一套 JS 解包。回环测试使用 ASCII 密码，与真实约束一致。
    digit_count = (n.bit_length() + 15) // 16
    chunk_size = 2 * (digit_count - 1)
    units_reversed_padded: list[int] = []
    for block_hex in ciphertext.split(" "):
        block = int(block_hex, 16)
        raw = pow(block, d, n).to_bytes(chunk_size, "little")
        units_reversed_padded.extend(raw)  # ASCII 下每字节即一个 unit
    # 此刻列表 = 反转后的明文 unit + 末尾补零；先去零再反转
    while units_reversed_padded and units_reversed_padded[-1] == 0:
        units_reversed_padded.pop()
    original_units = units_reversed_padded[::-1]
    text = bytes(
        b for unit in original_units for b in (unit & 0xFF, (unit >> 8) & 0xFF)
    ).decode("utf-16-le")
    assert text == plaintext


def test_build_login_payload_encrypts_password_with_mac():
    n, e, _d = _test_key()
    config = PortalConfig(
        entry_url="http://192.0.2.1/eportal/index.jsp?x=1",
        query_string="x=1",
        login_endpoint="http://192.0.2.1/eportal/InterFace.do?method=login",
        password_encrypt=True,
        public_exponent=format(e, "x"),
        public_modulus=n,
        service="",
        service_required=False,
    )
    payload = build_login_payload(config, "user01", "pw12345", mac="AA-BB-CC")
    assert payload["passwordEncrypt"] == js_double_encode("true")
    assert "InterFace.do" in config.login_endpoint
    # password 字段是 double_encode 后的密文，不含明文
    assert "pw12345" not in payload["password"]
