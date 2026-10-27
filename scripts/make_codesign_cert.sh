#!/bin/bash
# 创建本地代码签名证书 "PortalKit Local Signing"（幂等，无需 Apple 开发者账号）。
#
# 为什么需要：PortalKit 的凭据存 Keychain，Keychain ACL 按"应用签名身份"
# 记忆授权。ad-hoc 签名每次构建身份都变 → 每次自动认证都弹授权框。
# 固定的自签证书给应用稳定身份 → "始终允许"点一次永久生效。
#
# 用法：bash scripts/make_codesign_cert.sh
# 之后构建自动选用该身份（见 portalkit.ui.appbundle.sign_identity）。

set -euo pipefail

CERT_CN="PortalKit Local Signing"
DAYS=3650
KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

if security find-identity -v -p codesigning 2>/dev/null | grep -q "$CERT_CN"; then
  echo "证书已存在：$CERT_CN（跳过创建）"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "生成自签代码签名证书（${CERT_CN}，有效期 ${DAYS} 天）…"
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
  -subj "/CN=$CERT_CN" \
  -addext "keyUsage=digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"

# 注意：OpenSSL 3 默认的 p12 加密参数（AES-256/PBKDF2 新变体）与 macOS
# security 导入器不兼容（MAC verification failed），显式使用 macOS 保证
# 支持的 SHA1+3DES 旧参数。p12 仅存在于临时目录，导入后即删除。
openssl pkcs12 -export \
  -out "$TMP/identity.p12" -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
  -passout pass:portalkit-import \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1

echo "导入登录钥匙串（预授权 codesign 使用私钥）…"
security import "$TMP/identity.p12" -k "$KEYCHAIN" -P "portalkit-import" \
  -T /usr/bin/codesign -T /usr/bin/security

echo "将证书标记为受信任的代码签名身份（用户域，无需管理员）…"
security add-trusted-cert -k "$KEYCHAIN" -p codeSign "$TMP/cert.pem"

# 导入后立即验证身份可用
if security find-identity -v -p codesigning 2>/dev/null | grep -q "$CERT_CN"; then
  echo "完成：$CERT_CN 已可用于签名。"
else
  echo "警告：身份未通过验证，构建将回退 ad-hoc（Keychain 仍会弹框）。" >&2
  exit 1
fi
