"""macOS Keychain 凭据服务（SECURITY_AND_NETWORK §2）。

直接经 ctypes 调 Security.framework 的 SecKeychain* API：
- 密码不进 CLI argv / 环境变量 / 子进程参数（区别于 `security -w` 方案）；
- 服务名 = "PortalKit.<adapter_id>.<host>"，账号 = 用户输入的账号；
- 只在适配器执行认证时读取；UI/状态层永不展示明文。

首次访问系统会弹出 Keychain 授权提示（python/终端 作为访问方），属预期。
"""

from __future__ import annotations

import ctypes
from ctypes import c_char_p, c_int32, c_uint32, c_void_p, byref

_ERR_SUCCESS = 0
_ERR_ITEM_NOT_FOUND = -25300
_ERR_DUPLICATE_ITEM = -25299

_SERVICE_PREFIX = "PortalKit"

_sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
_cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")

_sec.SecKeychainAddGenericPassword.restype = c_int32
_sec.SecKeychainAddGenericPassword.argtypes = [
    c_void_p, c_uint32, c_char_p, c_uint32, c_char_p, c_uint32, c_char_p, c_void_p,
]
_sec.SecKeychainFindGenericPassword.restype = c_int32
_sec.SecKeychainFindGenericPassword.argtypes = [
    c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
    ctypes.POINTER(c_uint32), ctypes.POINTER(c_void_p), c_void_p,
]
_sec.SecKeychainItemDelete.restype = c_int32
_sec.SecKeychainItemDelete.argtypes = [c_void_p]
_sec.SecKeychainItemFreeContent.restype = c_int32
_sec.SecKeychainItemFreeContent.argtypes = [c_void_p, c_void_p]
_cf.CFRelease.restype = c_void_p
_cf.CFRelease.argtypes = [c_void_p]


class KeychainError(RuntimeError):
    def __init__(self, operation: str, status: int) -> None:
        super().__init__(f"Keychain {operation} 失败: OSStatus {status}")
        self.status = status


def service_name(adapter_id: str, host: str) -> str:
    return f"{_SERVICE_PREFIX}.{adapter_id}.{host}"


def save(adapter_id: str, host: str, username: str, password: str) -> None:
    """保存/覆盖凭据。已存在时先删后写（避免 -25299 分支的额外 API）。"""
    delete(adapter_id, host, username)
    svc = service_name(adapter_id, host).encode("utf-8")
    acct = username.encode("utf-8")
    pwd = password.encode("utf-8")
    status = _sec.SecKeychainAddGenericPassword(
        None, len(svc), svc, len(acct), acct, len(pwd), pwd, None
    )
    if status != _ERR_SUCCESS:
        raise KeychainError("add-generic-password", status)


def load(adapter_id: str, host: str, username: str) -> str | None:
    """读取密码；条目不存在返回 None（不抛异常）。"""
    svc = service_name(adapter_id, host).encode("utf-8")
    acct = username.encode("utf-8")
    length = c_uint32(0)
    data = c_void_p()
    status = _sec.SecKeychainFindGenericPassword(
        None, len(svc), svc, len(acct), acct, byref(length), byref(data), None
    )
    if status == _ERR_ITEM_NOT_FOUND:
        return None
    if status != _ERR_SUCCESS:
        raise KeychainError("find-generic-password", status)
    try:
        return ctypes.string_at(data, length.value).decode("utf-8")
    finally:
        _sec.SecKeychainItemFreeContent(None, data)


def delete(adapter_id: str, host: str, username: str) -> bool:
    """删除凭据条目；不存在返回 False。"""
    svc = service_name(adapter_id, host).encode("utf-8")
    acct = username.encode("utf-8")
    length = c_uint32(0)
    data = c_void_p()
    item = c_void_p()
    status = _sec.SecKeychainFindGenericPassword(
        None, len(svc), svc, len(acct), acct, byref(length), byref(data), byref(item)
    )
    if status == _ERR_ITEM_NOT_FOUND:
        return False
    if status != _ERR_SUCCESS:
        raise KeychainError("find-generic-password(for delete)", status)
    try:
        _sec.SecKeychainItemFreeContent(None, data)
        del_status = _sec.SecKeychainItemDelete(item)
        if del_status not in (_ERR_SUCCESS, _ERR_ITEM_NOT_FOUND):
            raise KeychainError("delete-item", del_status)
        return True
    finally:
        if item:
            _cf.CFRelease(item)
