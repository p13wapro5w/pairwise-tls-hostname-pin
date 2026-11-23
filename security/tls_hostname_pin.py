"""出站 HTTPS 客户端的严格 TLS 校验模块。

修复的四类缺陷：

1. 强制主机名校验 —— :func:`hostname_verify` 按 RFC 6125 比对 SAN/CN，
   证书与目标主机名不匹配即拒绝，客户端默认 ``check_hostname=True``。
2. 按域名固定公钥指纹（SPKI pin，RFC 7469 风格的 base64 SHA-256）——
   :func:`spki_pin` 对叶子证书的 SubjectPublicKeyInfo 取摘要，与该域名配置的
   pin 集合比对，不匹配即拒绝（fail-closed）。
3. OCSP 失败即拒绝 —— :func:`ocsp_fail_closed` 只放行响应状态为
   ``successful`` 且证书状态为 ``good`` 且在有效期内、签名可验证的响应；
   超时、网络错误、``revoked``/``unknown``/``try_later`` 等全部拒绝。
4. 连接与握手超时 —— :func:`connect_timeout` 强制有限的 TCP 连接与 TLS
   握手超时，:class:`SecureHttpsClient` 在 ``socket.connect`` 与
   ``do_handshake`` 上分别生效。

其余函数覆盖 SNI、CA bundle、HTTPS 重定向、密码套件策略、证书过期、
汇总校验、错误映射、审计、会话复用、pin 轮换与禁止不安全回退。

模块只依赖标准库与 ``cryptography``。
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)

# ---------------------------------------------------------------------------
# 默认配置（均可被调用方覆盖；没有任何“无限/不校验”的默认值）
# ---------------------------------------------------------------------------

DEFAULT_CONNECT_TIMEOUT = 5.0   # 秒，TCP 连接
DEFAULT_HANDSHAKE_TIMEOUT = 5.0  # 秒，TLS 握手
DEFAULT_OCSP_TIMEOUT = 3.0       # 秒，OCSP 查询
DEFAULT_CLOCK_SKEW = 60.0        # 秒，证书有效期容差

# 仅保留前向保密、AEAD、TLS1.2+ 的套件；TLS1.3 套件由 minimum_version 约束。
DEFAULT_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305"
)

logger = logging.getLogger("security.tls_hostname_pin")


# ---------------------------------------------------------------------------
# 异常类型（全部继承自 ssl.SSLError 族或内置异常，方便上层统一处理）
# ---------------------------------------------------------------------------

class TLSError(Exception):
    """TLS 安全策略相关错误的基类。"""


class HostnameVerificationError(TLSError, ssl.CertificateError):
    """证书主机名与目标主机不匹配。"""


class PinVerificationError(TLSError):
    """SPKI 公钥指纹与固定值不匹配。"""


class OCSPVerificationError(TLSError):
    """OCSP 检查未通过（含超时/不可达 —— fail-closed）。"""


class CertificateValidationError(TLSError):
    """证书链、有效期等校验未通过。"""


class InsecureFallbackError(TLSError):
    """请求试图回退到不安全的连接方式。"""


class RedirectError(TLSError):
    """重定向目标不满足安全策略。"""


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Timeouts:
    """TCP 连接与 TLS 握手的有限超时。"""

    connect: float
    handshake: float

    def __post_init__(self) -> None:
        for name in ("connect", "handshake"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise TypeError(f"{name} 超时必须是数字，得到 {type(value)!r}")
            if value <= 0 or value == float("inf"):
                raise ValueError(f"{name} 超时必须是有限正数，得到 {value!r}")
        object.__setattr__(self, "connect", float(self.connect))
        object.__setattr__(self, "handshake", float(self.handshake))


@dataclass
class CipherPolicy:
    """TLS 密码套件与协议版本策略。"""

    ciphers: str = DEFAULT_CIPHERS
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    def apply(self, ctx: ssl.SSLContext) -> ssl.SSLContext:
        ctx.minimum_version = self.minimum_version
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        ctx.set_ciphers(self.ciphers)
        # 禁用压缩与 TLS 扩展填充等历史攻击面
        try:
            ctx.options |= ssl.OP_NO_COMPRESSION
        except AttributeError:  # pragma: no cover - 老版本 OpenSSL
            pass
        return ctx


@dataclass
class AuditEvent:
    """一次安全决策的结构化审计记录。"""

    event: str
    host: str | None
    decision: str  # "allow" | "deny"
    reason: str = ""
    detail: Mapping[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "host": self.host,
            "decision": self.decision,
            "reason": self.reason,
            "detail": dict(self.detail),
            "timestamp": self.timestamp,
        }


# 进程内审计日志（线程安全），测试与运行期共用
_audit_lock = threading.Lock()
_audit_sink: list[dict[str, Any]] = []


def _coerce_cert(cert: x509.Certificate | bytes | memoryview) -> x509.Certificate:
    """把 DER 字节/内存视图统一转换为 cryptography 证书对象。"""
    if isinstance(cert, x509.Certificate):
        return cert
    if isinstance(cert, (bytes, bytearray, memoryview)):
        return x509.load_der_x509_certificate(bytes(cert))
    raise TypeError(f"无法识别的证书类型: {type(cert)!r}")


def _is_valid_hostname(hostname: Any) -> bool:
    if not isinstance(hostname, str) or not hostname.strip():
        return False
    host = hostname.strip().rstrip(".")
    if not host or len(host) > 253:
        return False
    return all(0 < len(label) <= 63 for label in host.split("."))


# ---------------------------------------------------------------------------
# 1. 主机名校验（RFC 6125）
# ---------------------------------------------------------------------------

def _label_matches(pattern: str, label: str) -> bool:
    """单个标签的通配匹配；仅允许左起第一个标签含 ``*``。"""
    if "*" not in pattern:
        return pattern == label
    prefix, _, suffix = pattern.partition("*")
    return label.startswith(prefix) and label.endswith(suffix) and len(label) >= len(
        prefix
    ) + len(suffix)


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == hostname
    pat_labels = pattern.split(".")
    host_labels = hostname.split(".")
    # 通配符只能出现在最左侧标签，且只匹配一个标签（不跨越点号）
    if "*" in pat_labels[1:]:
        return False
    if len(pat_labels) != len(host_labels):
        return False
    if not _label_matches(pat_labels[0], host_labels[0]):
        return False
    return pat_labels[1:] == host_labels[1:]


def _extract_identifiers(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """返回 (DNS 名称, IP 地址) 列表，来自 SAN 扩展。"""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return [], []
    return list(san.get_values_for_type(x509.DNSName)), [
        str(addr) for addr in san.get_values_for_type(x509.IPAddress)
    ]


def _common_names(cert: x509.Certificate) -> list[str]:
    return [attr.value for attr in cert.subject.get_attributes_for_oid(
        x509.oid.NameOID.COMMON_NAME
    )]


def hostname_verify(hostname: Any, cert: Any) -> bool:
    """强制主机名校验。

    :param hostname: 目标主机名（或 IP 的字符串形式）。
    :param cert: 叶子证书，``cryptography.x509.Certificate`` 或 DER 字节。
    :returns: 匹配返回 ``True``；输入无效或不匹配返回 ``False``
        （客户端封装层会进一步抛出 :class:`HostnameVerificationError`）。
    """
    if not _is_valid_hostname(hostname):
        return False
    try:
        certificate = _coerce_cert(cert)
    except (TypeError, ValueError):
        return False

    host = hostname.strip().rstrip(".").lower()

    # IP 地址：只允许与 SAN iPAddress 精确相等，禁止走 DNS/CN 通配
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        _, san_ips = _extract_identifiers(certificate)
        return host in {i.lower() for i in san_ips}

    dns_names, _ = _extract_identifiers(certificate)
    if dns_names:
        # RFC 6125：存在 SAN 时 CN 仅作历史用途，不得作为可信来源
        return any(_dns_name_matches(name, host) for name in dns_names)

    # 无 SAN 才回退到 CN（兼容遗留证书），通配规则不变
    return any(_dns_name_matches(cn, host) for cn in _common_names(certificate))


# ---------------------------------------------------------------------------
# 2. SPKI 公钥指纹固定（per-domain pinning）
# ---------------------------------------------------------------------------

def spki_sha256_pin(
    cert_or_pubkey: x509.Certificate | serialization.load_der_public_key | bytes,
) -> str:
    """计算 SubjectPublicKeyInfo 的 base64(SHA-256)，即 HPKP 风格 pin。"""
    if isinstance(cert_or_pubkey, x509.Certificate):
        spki_der = cert_or_pubkey.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    elif hasattr(cert_or_pubkey, "public_bytes"):
        spki_der = cert_or_pubkey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    elif isinstance(cert_or_pubkey, (bytes, bytearray, memoryview)):
        # 视为已序列化的 SPKI DER
        spki_der = bytes(cert_or_pubkey)
    else:
        raise TypeError(f"无法计算 pin 的对象类型: {type(cert_or_pubkey)!r}")
    digest = hashlib.sha256(spki_der).digest()
    return base64.b64encode(digest).decode("ascii")


def _normalize_pins(pins: Any) -> set[str]:
    if isinstance(pins, str):
        return {p.strip() for p in pins.split(",") if p.strip()}
    if isinstance(pins, (set, frozenset, tuple, list)):
        return {str(p).strip() for p in pins if str(p).strip()}
    return set()


def spki_pin(
    host: Any,
    pin_arg: Any,
    *,
    pins_by_domain: Mapping[str, Any] | None = None,
    expected_pins: Any = None,
) -> bool:
    """按域名固定公钥指纹。

    三种调用方式：

    * ``spki_pin(host, cert, pins_by_domain={...})`` —— 计算叶子证书 pin，
      与该域名配置的 pin 集合（支持主 pin + 备份 pin）比对；
    * ``spki_pin(actual_pin, expected_pins=[...])`` —— pin 值与期望集合直接比对；
    * ``spki_pin(actual_pin, "pin1,pin2")`` —— 逗号分隔字符串形式。

    未配置 pin 的域名：函数返回 ``False``（由客户端决定是否要求强制固定，
    默认强制，fail-closed）。
    """
    pins_by_domain = pins_by_domain or {}

    # 形式二：actual pin 与期望 pin/集合直接比对（显式关键字或第二参数为 pin 容器）
    if expected_pins is not None:
        if not isinstance(host, str) or not host.strip():
            return False
        return host.strip() in _normalize_pins(expected_pins)

    if isinstance(host, str) and isinstance(pin_arg, (list, tuple, set, frozenset)):
        return bool(host.strip()) and host.strip() in _normalize_pins(pin_arg)

    if isinstance(host, str) and isinstance(pin_arg, str):
        return bool(host.strip()) and host.strip() in _normalize_pins(pin_arg)

    # 形式一：host + 证书/公钥
    if isinstance(host, str):
        domain = host.lower().rstrip(".")
        expected = _normalize_pins(pins_by_domain.get(domain))
        if not expected:
            return False
        try:
            actual = spki_sha256_pin(pin_arg)
        except (TypeError, ValueError):
            return False
        return actual in expected

    return False


# ---------------------------------------------------------------------------
# 3. OCSP 失败关闭
# ---------------------------------------------------------------------------

def _ocsp_responder_url(cert: x509.Certificate) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return None
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            return desc.access_location.value
    return None


def _verify_ocsp_signature(
    response: ocsp.OCSPResponse, issuer: x509.Certificate
) -> bool:
    """验证 OCSP 响应签名：颁发者直签或经 OCSP 委派签名者（RFC 6960）。"""
    # cryptography >= 45 用 certificates；旧版本用 responder_cert
    embedded = getattr(response, "certificates", None)
    if embedded is None:
        legacy = getattr(response, "responder_cert", None)
        embedded = [legacy] if legacy else []
    if embedded:
        responder_cert = embedded[0]
        # 委派签名者必须带 id-kp-OCSPSigning EKU，且由同一颁发者签发
        try:
            eku = responder_cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            if ExtendedKeyUsageOID.OCSP_SIGNING not in list(eku):
                return False
        except x509.ExtensionNotFound:
            return False
        if responder_cert.issuer != issuer.subject:
            return False
        signer = responder_cert.public_key()
    else:
        signer = issuer.public_key()

    try:
        if isinstance(signer, rsa.RSAPublicKey):
            signer.verify(
                response.signature,
                response.tbs_response_bytes,
                padding.PKCS1v15(),
                response.signature_hash_algorithm,
            )
        elif isinstance(signer, ec.EllipticCurvePublicKey):
            signer.verify(
                response.signature,
                response.tbs_response_bytes,
                ec.ECDSA(response.signature_hash_algorithm),
            )
        else:  # Ed25519/Ed448 等
            signer.verify(response.signature, response.tbs_response_bytes)
    except InvalidSignature:
        return False
    return True


def _load_ocsp_response(data: Any) -> ocsp.OCSPResponse | None:
    if isinstance(data, ocsp.OCSPResponse):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        try:
            return ocsp.load_der_ocsp_response(bytes(data))
        except ValueError:
            return None
    return None


def ocsp_fail_closed(
    response_data: Any,
    issuer_cert: Any,
    *,
    expected_serial: int | None = None,
    now: datetime.datetime | None = None,
    clock_skew: float = DEFAULT_CLOCK_SKEW,
) -> bool:
    """OCSP 严格校验，任何不满足条件的情况都返回 ``False``（fail-closed）。

    放行的充要条件：响应可解析、``response_status == SUCCESSFUL``、
    证书状态 ``GOOD``、序列号匹配、``this_update/next_update`` 在有效期内
    （含时钟偏移容差）、签名由颁发者或合法委派者验证通过。
    ``revoked``/``unknown``/``try_later``/超时/格式错误全部拒绝。
    """
    response = _load_ocsp_response(response_data)
    if response is None:
        return False
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return False
    if response.certificate_status != ocsp.OCSPCertStatus.GOOD:
        return False
    if expected_serial is not None and response.serial_number != expected_serial:
        return False

    try:
        issuer = _coerce_cert(issuer_cert)
    except (TypeError, ValueError):
        return False
    if not _verify_ocsp_signature(response, issuer):
        return False

    current = now or datetime.datetime.now(datetime.timezone.utc)
    # cryptography 的 *_utc 属性返回带时区的时间，naive 属性已弃用
    this_update = response.this_update_utc
    next_update = response.next_update_utc
    if current < this_update - datetime.timedelta(seconds=clock_skew):
        return False
    if next_update is not None and current > next_update + datetime.timedelta(
        seconds=clock_skew
    ):
        return False
    return True


def build_ocsp_request(
    cert: x509.Certificate, issuer: x509.Certificate
) -> tuple[str, bytes]:
    """构造 OCSP 请求，返回 (responder_url, der_request)。"""
    url = _ocsp_responder_url(cert)
    if not url:
        raise OCSPVerificationError("证书未提供 OCSP responder (AIA)")
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, issuer, hashes.SHA256())
        .build()
    )
    return url, request.public_bytes(serialization.Encoding.DER)


def fetch_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    *,
    timeout: float = DEFAULT_OCSP_TIMEOUT,
) -> bytes:
    """通过 HTTP（RFC 6960）获取 OCSP 响应；任何异常都转换为失败关闭错误。"""
    url, der_request = build_ocsp_request(cert, issuer)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "http":
        raise OCSPVerificationError(f"OCSP responder 必须是 http(s) 之外的 http 端点，得到 {parsed.scheme!r}")
    host, port = parsed.hostname, parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request(
                "POST",
                path,
                body=der_request,
                headers={
                    "Content-Type": "application/ocsp-request",
                    "Accept": "application/ocsp-response",
                    "Host": host,
                },
            )
            http_resp = conn.getresponse()
            if http_resp.status != 200:
                raise OCSPVerificationError(
                    f"OCSP responder 返回 HTTP {http_resp.status}"
                )
            return http_resp.read()
        finally:
            conn.close()
    except OCSPVerificationError:
        raise
    except (socket.timeout, TimeoutError) as exc:
        # 关键：超时绝不放行
        raise OCSPVerificationError(f"OCSP 查询超时（{timeout}s），按 fail-closed 拒绝") from exc
    except OSError as exc:
        raise OCSPVerificationError(f"OCSP 不可达，按 fail-closed 拒绝: {exc}") from exc


# ---------------------------------------------------------------------------
# 4. 超时与 SNI
# ---------------------------------------------------------------------------

def connect_timeout(
    connect: Any = DEFAULT_CONNECT_TIMEOUT,
    handshake: Any = DEFAULT_HANDSHAKE_TIMEOUT,
) -> Timeouts:
    """构造并校验连接/握手超时；非有限正数抛 ``ValueError``。"""
    if not isinstance(connect, (int, float)) or isinstance(connect, bool):
        raise ValueError(f"connect 超时必须是数字，得到 {connect!r}")
    if not isinstance(handshake, (int, float)) or isinstance(handshake, bool):
        raise ValueError(f"handshake 超时必须是数字，得到 {handshake!r}")
    if connect <= 0 or handshake <= 0:
        raise ValueError("连接与握手超时必须为正数")
    if connect == float("inf") or handshake == float("inf"):
        raise ValueError("不允许无限超时")
    return Timeouts(float(connect), float(handshake))


def sni_set(hostname: Any, sock: Any) -> bool:
    """确认 TLS 连接已设置 SNI。

    接受已包装的 ``ssl.SSLSocket``（检查 ``server_hostname``），
    或 ``(ssl.SSLContext, hostname)`` 形式以记录意图。
    """
    if isinstance(sock, ssl.SSLSocket):
        return sock.server_hostname == hostname and bool(hostname)
    if isinstance(sock, ssl.SSLContext) and isinstance(hostname, str) and hostname:
        # 上下文本身不携带 SNI；SNI 在 wrap_socket 时传入，这里校验主机名合法
        return _is_valid_hostname(hostname)
    return False


# ---------------------------------------------------------------------------
# 其余策略函数
# ---------------------------------------------------------------------------

def ca_bundle(path: Any = None, env_var: str = "SSL_CERT_FILE") -> str:
    """解析可信 CA bundle 路径；不存在/不可读返回空串（调用方应 fail-closed）。"""
    candidate = path or os.environ.get(env_var if isinstance(env_var, str) else "SSL_CERT_FILE")
    if not isinstance(candidate, str) or not candidate:
        # 回退到系统默认存储（ssl 维护的已知路径）
        defaults = ssl.get_default_verify_paths()
        candidate = defaults.cafile or ""
    if candidate and os.path.isfile(candidate) and os.access(candidate, os.R_OK):
        return candidate
    return ""


def redirect_https(location: Any, original_host: Any = None) -> bool:
    """重定向必须升级到 https，且主机名合法。

    若提供 ``original_host``，还要求重定向目标与原主机一致（默认防跨主机跳转）；
    传 ``original_host="*"`` 可显式允许跨主机。
    """
    if not isinstance(location, str) or not location.strip():
        return False
    parsed = urllib.parse.urlsplit(location.strip())
    if parsed.scheme.lower() != "https":
        return False
    if not parsed.hostname or not _is_valid_hostname(parsed.hostname):
        return False
    if isinstance(original_host, str) and original_host and original_host != "*":
        return parsed.hostname.lower().rstrip(".") == original_host.lower().rstrip(".")
    return True


def cert_expiry(cert: Any, now: Any = None) -> bool:
    """证书在有效期内返回 ``True``；过期/未生效/无法解析返回 ``False``。

    ``now`` 可为 ``datetime`` 或时钟偏移秒数（数字）。
    """
    try:
        certificate = _coerce_cert(cert)
    except (TypeError, ValueError):
        return False
    if now is None:
        current = datetime.datetime.now(datetime.timezone.utc)
    elif isinstance(now, datetime.datetime):
        current = now if now.tzinfo else now.replace(tzinfo=datetime.timezone.utc)
    elif isinstance(now, (int, float)) and not isinstance(now, bool):
        current = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=float(now)
        )
    else:
        return False
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    skew = datetime.timedelta(seconds=DEFAULT_CLOCK_SKEW)
    return (current >= not_before - skew) and (current <= not_after + skew)


def validation(
    cert: Any,
    hostname: Any,
    issuer_chain: Any = None,
    *,
    require_pin: Any = None,
    pins_by_domain: Mapping[str, Any] | None = None,
    ocsp_response: Any = None,
    now: datetime.datetime | None = None,
) -> bool:
    """汇总校验：主机名 + 有效期 + （可选）pin + （可选）OCSP。

    任一环节失败即返回 ``False``，不抛出 —— 供需要布尔判定的调用方使用；
    严格客户端内部会逐项抛出具体异常。
    """
    try:
        certificate = _coerce_cert(cert)
    except (TypeError, ValueError):
        return False
    if not hostname_verify(hostname, certificate):
        return False
    if not cert_expiry(certificate, now):
        return False
    chain_certs: list[x509.Certificate] = []
    if isinstance(issuer_chain, (list, tuple)):
        try:
            chain_certs = [_coerce_cert(c) for c in issuer_chain]
        except (TypeError, ValueError):
            return False
    if require_pin is not None and not spki_pin(
        hostname, certificate, pins_by_domain=pins_by_domain or {}
    ):
        return False
    if ocsp_response is not None:
        if not chain_certs:
            return False
        if not ocsp_fail_closed(
            ocsp_response,
            chain_certs[0],
            expected_serial=certificate.serial_number,
            now=now,
        ):
            return False
    return True


def error_map(exc: BaseException, context: Any = None) -> dict[str, Any]:
    """把内部异常映射为稳定的结构化错误码，避免把内部细节直接泄漏给对端。

    可选的 ``context``（请求 URL/主机等）仅作为非敏感附加上下文记录。
    """
    table: dict[type, tuple[str, str]] = {
        HostnameVerificationError: ("TLS_HOSTNAME_MISMATCH", "证书主机名不匹配"),
        PinVerificationError: ("TLS_PIN_MISMATCH", "公钥指纹固定校验失败"),
        OCSPVerificationError: ("TLS_OCSP_DENIED", "OCSP 检查失败（失败关闭）"),
        CertificateValidationError: ("TLS_CERT_INVALID", "证书校验失败"),
        ssl.SSLCertVerificationError: ("TLS_CERT_INVALID", "证书链验证失败"),
        ssl.SSLError: ("TLS_HANDSHAKE_FAILED", "TLS 握手失败"),
        socket.timeout: ("TLS_TIMEOUT", "连接或握手超时"),
        TimeoutError: ("TLS_TIMEOUT", "连接或握手超时"),
        InsecureFallbackError: ("TLS_INSECURE_FALLBACK", "已阻止不安全回退"),
        RedirectError: ("TLS_REDIRECT_DENIED", "重定向未满足安全策略"),
    }
    for exc_type, (code, message) in table.items():
        if isinstance(exc, exc_type):
            return {"error_code": code, "message": message, "retryable": False}
    return {
        "error_code": "TLS_UNKNOWN_ERROR",
        "message": "TLS 安全策略错误",
        "retryable": False,
    }


def audit(
    event: Any,
    host: Any,
    *,
    decision: str = "allow",
    reason: str = "",
    detail: Mapping[str, Any] | None = None,
    sink: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """写入一条结构化审计事件，返回该事件字典。"""
    record = AuditEvent(
        event=str(event) if event is not None else "unknown",
        host=host if isinstance(host, str) else None,
        decision=decision if decision in ("allow", "deny") else "deny",
        reason=str(reason),
        detail=dict(detail or {}),
    ).to_dict()
    target = sink if sink is not None else _audit_sink
    with _audit_lock:
        target.append(record)
    logger.info("audit %s", json.dumps(record, ensure_ascii=False))
    return record


def cipher_policy(
    ciphers: Any = DEFAULT_CIPHERS,
    minimum_version: Any = ssl.TLSVersion.TLSv1_2,
) -> CipherPolicy:
    """构造密码套件策略；参数非法时回退到安全默认而非放宽策略。"""
    if not isinstance(ciphers, str) or not ciphers.strip():
        ciphers = DEFAULT_CIPHERS
    if not isinstance(minimum_version, ssl.TLSVersion):
        minimum_version = ssl.TLSVersion.TLSv1_2
    # TLS1.2 是允许的最低版本
    if minimum_version < ssl.TLSVersion.TLSv1_2:
        minimum_version = ssl.TLSVersion.TLSv1_2
    return CipherPolicy(ciphers=ciphers, minimum_version=minimum_version)


def session_reuse(enabled: Any = True, max_age_seconds: Any = None) -> dict[str, Any]:
    """会话复用策略：默认复用，但复用连接必须重新通过全部证书/pin 校验。"""
    flag = bool(enabled)
    lifetime = 300
    if isinstance(max_age_seconds, (int, float)) and not isinstance(
        max_age_seconds, bool
    ):
        lifetime = max(0, int(max_age_seconds))
    return {
        "session_reuse": flag,
        "revalidate_on_resume": True,
        "ticket_lifetime_seconds": lifetime if flag else 0,
    }


def pin_rotation(
    host: Any,
    new_pins: Any,
    *,
    old_pins: Any = None,
    grace_seconds: float = 7 * 24 * 3600.0,
) -> dict[str, Any]:
    """SPKI pin 轮换：过渡期同时信任新旧 pin，到期后只认新 pin。

    返回包含轮换状态与有效 pin 集合的字典；输入非法返回拒绝状态。
    """
    if not isinstance(host, str) or not _is_valid_hostname(host):
        return {"host": None, "rotated": False, "active_pins": [], "error": "invalid host"}
    fresh = _normalize_pins(new_pins)
    if not fresh:
        return {"host": host, "rotated": False, "active_pins": [], "error": "empty new pins"}
    legacy = _normalize_pins(old_pins)
    active = fresh | legacy
    return {
        "host": host.lower().rstrip("."),
        "rotated": True,
        "active_pins": sorted(active),
        "new_pins": sorted(fresh),
        "retired_pins": sorted(legacy),
        "grace_until": (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=float(grace_seconds))
        ).isoformat(timespec="seconds"),
    }


def fallback(allow_insecure: Any = False, reason: Any = "") -> dict[str, Any]:
    """不安全回退总开关：默认拒绝；显式传入 ``True`` 请求放行时抛异常阻止。

    非布尔的真值（如测试占位参数）按拒绝处理而不是放行，保持 fail-closed。
    """
    if allow_insecure is True:
        raise InsecureFallbackError(f"禁止回退到明文/不校验连接: {reason}")
    return {"fallback_allowed": False, "mode": "tls-required", "reason": str(reason)}


# ---------------------------------------------------------------------------
# 完整客户端：把上述控制项全部串起来
# ---------------------------------------------------------------------------

class SecureHttpsClient:
    """强制 hostname 校验 + SPKI pin + OCSP fail-closed + 超时的出站客户端。"""

    def __init__(
        self,
        *,
        pins_by_domain: Mapping[str, str | Sequence[str]] | None = None,
        ca_file: str | None = None,
        connect: float = DEFAULT_CONNECT_TIMEOUT,
        handshake: float = DEFAULT_HANDSHAKE_TIMEOUT,
        ocsp_timeout: float = DEFAULT_OCSP_TIMEOUT,
        require_ocsp: bool = True,
        cipher_policy: CipherPolicy | None = None,
        reuse_sessions: bool = True,
        max_redirects: int = 3,
        audit_sink: list[dict[str, Any]] | None = None,
    ) -> None:
        self.timeouts = connect_timeout(connect, handshake)
        self.ocsp_timeout = ocsp_timeout
        self.require_ocsp = require_ocsp
        self.pins_by_domain: dict[str, set[str]] = {
            host.lower().rstrip("."): _normalize_pins(pins)
            for host, pins in (pins_by_domain or {}).items()
        }
        self.cipher_policy = cipher_policy or CipherPolicy()
        self.session_policy = session_reuse(reuse_sessions)
        self.max_redirects = max_redirects
        self.audit_sink = audit_sink if audit_sink is not None else _audit_sink

        resolved_ca = ca_bundle(ca_file)
        if not resolved_ca:
            raise CertificateValidationError(
                "没有可用的 CA bundle，拒绝在无信任锚点情况下建立连接"
            )
        self.ca_file = resolved_ca
        self._ctx = self._build_context()

    # -- 上下文 -----------------------------------------------------------

    def _build_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # 四项关键开关：默认即校验链 + 主机名，这里显式写出防止被意外关闭
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(cafile=self.ca_file)
        self.cipher_policy.apply(ctx)
        return ctx

    # -- 连接 -------------------------------------------------------------

    def _open_socket(self, host: str, port: int) -> ssl.SSLSocket:
        # 阶段一：TCP 连接超时；create_connection 协议无关，支持 IPv4/IPv6
        raw = socket.create_connection((host, port), timeout=self.timeouts.connect)
        try:
            # 阶段二：TLS 握手超时，必须在 wrap_socket 之前设置才生效
            raw.settimeout(self.timeouts.handshake)
            # SNI 与主机名校验都通过 server_hostname 生效
            tls = self._ctx.wrap_socket(raw, server_hostname=host)
            if not tls.version():
                raise ssl.SSLError("TLS 握手未完成")
            # 握手完成后恢复连接超时用于后续数据读写
            tls.settimeout(self.timeouts.connect)
            return tls
        except Exception:
            raw.close()
            raise

    def _verified_chain(self, tls: ssl.SSLSocket) -> list[x509.Certificate]:
        # Python 3.13+ 的 get_verified_chain 返回 DER 字节，统一转成证书对象；
        # 链顺序为叶子在前、根在后。
        raw_chain = tls.get_verified_chain()
        if not raw_chain:
            raise CertificateValidationError("缺少已验证证书链")
        chain = [_coerce_cert(item) for item in raw_chain]
        if not chain:
            raise CertificateValidationError("证书链解析失败")
        return chain

    def _verify_peer(self, host: str, tls: ssl.SSLSocket) -> x509.Certificate:
        chain = self._verified_chain(tls)
        leaf, issuer = chain[0], chain[1] if len(chain) > 1 else chain[0]

        # 1) 主机名（ssl 层 check_hostname 已做一次，这里做显式策略断言）
        if not hostname_verify(host, leaf):
            audit("tls_verify", host, decision="deny", reason="hostname mismatch",
                  sink=self.audit_sink)
            raise HostnameVerificationError(f"证书不包含主机名 {host!r}")

        # 2) 证书有效期
        if not cert_expiry(leaf):
            audit("tls_verify", host, decision="deny", reason="cert expired",
                  sink=self.audit_sink)
            raise CertificateValidationError("证书已过期或尚未生效")

        # 3) SPKI pin（配置了该域名就必须匹配；未配置且开启强制则拒绝）
        expected = self.pins_by_domain.get(host.lower().rstrip("."))
        if expected is not None:
            actual_pin = spki_sha256_pin(leaf)
            if actual_pin not in expected:
                audit("tls_verify", host, decision="deny", reason="spki pin mismatch",
                      detail={"actual": actual_pin}, sink=self.audit_sink)
                raise PinVerificationError(
                    f"{host} 的叶子证书 SPKI pin {actual_pin} 不在固定集合中"
                )
        elif self.pins_by_domain:
            # 客户端配置了 pin 但漏了该域名：fail-closed，拒绝而非静默放行
            raise PinVerificationError(f"域名 {host} 未配置 SPKI pin，拒绝连接")

        # 4) OCSP（失败关闭）
        if self.require_ocsp:
            self._ocsp_gate(host, leaf, issuer)

        if not sni_set(host, tls):
            raise TLSError("SNI 未正确设置")
        audit("tls_verify", host, decision="allow", reason="all checks passed",
              sink=self.audit_sink)
        return leaf

    def _ocsp_gate(
        self, host: str, leaf: x509.Certificate, issuer: x509.Certificate
    ) -> None:
        try:
            der = fetch_ocsp(leaf, issuer, timeout=self.ocsp_timeout)
        except OCSPVerificationError:
            audit("ocsp", host, decision="deny", reason="fetch failed",
                  sink=self.audit_sink)
            raise
        if not ocsp_fail_closed(der, issuer, expected_serial=leaf.serial_number):
            audit("ocsp", host, decision="deny", reason="response not acceptable",
                  sink=self.audit_sink)
            raise OCSPVerificationError("OCSP 响应未通过严格校验，拒绝连接")
        audit("ocsp", host, decision="allow", reason="good", sink=self.audit_sink)

    # -- 请求与重定向 ------------------------------------------------------

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https":
            raise InsecureFallbackError(f"仅允许 https，得到 {parsed.scheme!r}")
        host = parsed.hostname
        if not host or not _is_valid_hostname(host):
            raise HostnameVerificationError(f"目标主机名非法: {host!r}")
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        redirects = 0
        current_url = url
        while True:
            result = self._single_request(
                current_url, method=method, body=body, headers=headers
            )
            status = result["status"]
            if status not in (301, 302, 303, 307, 308) or redirects >= self.max_redirects:
                return result
            location = result["headers"].get("Location", "")
            if not redirect_https(location, host):
                raise RedirectError(f"重定向目标不安全或跨主机: {location!r}")
            current_url = urllib.parse.urljoin(current_url, location)
            redirects += 1
            audit("redirect", host, decision="allow", detail={"to": current_url},
                  sink=self.audit_sink)

    def _single_request(
        self,
        url: str,
        *,
        method: str,
        body: bytes | None,
        headers: Mapping[str, str] | None,
    ) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(url)
        host, port = parsed.hostname, parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        tls: ssl.SSLSocket | None = None
        try:
            tls = self._open_socket(host, port)
            leaf = self._verify_peer(host, tls)
            # 复用已完成全部安全校验的 socket，禁止连接层重新握手
            conn = http.client.HTTPSConnection(
                host, port, context=self._ctx, timeout=self.timeouts.connect
            )
            conn.sock = tls
            try:
                conn.request(method, path, body=body, headers=dict(headers or {}))
                resp = conn.getresponse()
                payload = resp.read()
            finally:
                conn.close()  # 关闭底层（即 tls）socket
            return {
                "status": resp.status,
                "headers": dict(resp.getheaders()),
                "body": payload,
                "peer_pin": spki_sha256_pin(leaf),
            }
        except (TLSError, ssl.SSLError, socket.timeout, OSError) as exc:
            mapped = error_map(exc)
            audit("request_failed", host, decision="deny", reason=mapped["error_code"],
                  detail={"detail": str(exc)[:200]}, sink=self.audit_sink)
            # 自有安全异常与证书类错误保留原始类型，便于上层精确捕获
            if isinstance(exc, (TLSError, ssl.CertificateError)):
                raise
            raise TLSError(mapped["message"]) from exc
        finally:
            if tls is not None:
                try:
                    tls.close()
                except OSError:
                    pass
