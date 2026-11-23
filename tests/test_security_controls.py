"""严格 TLS 客户端的安全行为测试（全部离线、自包含）。

覆盖：
- 强制主机名校验（SAN/CN、通配符、IP、无 SAN 回退、大小写/尾点）
- 按域名 SPKI 公钥指纹固定（匹配/不匹配/轮换期/未配置 fail-closed）
- OCSP fail-closed（good/revoked/unknown/超时/错误签名/过期/序列号不符）
- 连接与握手超时（非有限值拒绝、真实 socket 超时）
- SNI、CA bundle、https 重定向、密码套件、证书有效期、汇总校验
- 错误映射、审计、会话复用、pin 轮换、禁止不安全回退
- 端到端：本地 TLS 服务器上的成功握手与各类拒绝
"""

import datetime
import socket
import ssl
import threading
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

import security.tls_hostname_pin as mod


# ---------------------------------------------------------------------------
# 证书夹具：自建 CA + 两张叶子证书（不同密钥，用于 pin 不匹配）
# ---------------------------------------------------------------------------

def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _make_ca():
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, common_name, sans, *, expired=False, ip_sans=None):
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        not_before, not_after = now - datetime.timedelta(days=30), now - datetime.timedelta(days=1)
    else:
        not_before, not_after = now - datetime.timedelta(days=1), now + datetime.timedelta(days=90)
    names = [x509.DNSName(n) for n in sans]
    if ip_sans:
        names += [x509.IPAddress(ip) for ip in ip_sans]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.test.invalid/"),
                )
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    ca_key, ca_cert = _make_ca()
    leaf_key, leaf = _make_leaf(
        ca_key, ca_cert, "api.example.com",
        ["api.example.com", "*.example.com", "other.example.org"],
    )
    _, leaf2 = _make_leaf(ca_key, ca_cert, "api2.example.com", ["api2.example.com"])
    _, expired = _make_leaf(
        ca_key, ca_cert, "old.example.com", ["old.example.com"], expired=True
    )
    # 只有 CN、没有 SAN 的遗留证书
    cn_key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cn_only = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.example.net")]))
        .issuer_name(ca_cert.subject)
        .public_key(cn_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path_factory.mktemp("pki") / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return {
        "ca_key": ca_key, "ca_cert": ca_cert, "ca_path": str(ca_path),
        "leaf_key": leaf_key, "leaf": leaf, "leaf2": leaf2,
        "expired": expired, "cn_only": cn_only,
    }


def _ocsp_response(ca_key, ca_cert, leaf, status, *, bad_signature=False, stale=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = ocsp.OCSPResponseBuilder()
    if status == "revoked":
        builder = builder.add_response(
            leaf, ca_cert, hashes.SHA256(), ocsp.OCSPCertStatus.REVOKED,
            now, None, now, x509.ReasonFlags.key_compromise,
        )
    elif status == "unknown":
        builder = builder.add_response(
            leaf, ca_cert, hashes.SHA256(), ocsp.OCSPCertStatus.UNKNOWN,
            now, None, None, None,
        )
    else:
        this_update = now - datetime.timedelta(minutes=5)
        next_update = now + datetime.timedelta(days=1)
        if stale:
            this_update = now - datetime.timedelta(days=10)
            next_update = now - datetime.timedelta(days=9)
        builder = builder.add_response(
            leaf, ca_cert, hashes.SHA256(), ocsp.OCSPCertStatus.GOOD,
            this_update, next_update, None, None,
        )
    builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
    signer_key = _key() if bad_signature else ca_key
    return builder.sign(signer_key, hashes.SHA256())


# ---------------------------------------------------------------------------
# 1. 主机名校验
# ---------------------------------------------------------------------------

class TestHostnameVerify:
    def test_exact_san_match(self, pki):
        assert mod.hostname_verify("api.example.com", pki["leaf"]) is True

    def test_case_insensitive_and_trailing_dot(self, pki):
        assert mod.hostname_verify("API.Example.COM.", pki["leaf"]) is True

    def test_wildcard_single_label_only(self, pki):
        assert mod.hostname_verify("foo.example.com", pki["leaf"]) is True
        # 通配符不得跨标签
        assert mod.hostname_verify("a.b.example.com", pki["leaf"]) is False

    def test_mismatched_host_rejected(self, pki):
        assert mod.hostname_verify("evil.attacker.com", pki["leaf"]) is False

    def test_wildcard_not_in_leftmost_label_rejected(self, pki):
        # other.example.org 是精确 SAN，不含通配
        assert mod.hostname_verify("other.example.org", pki["leaf"]) is True
        assert mod.hostname_verify("xexample.org", pki["leaf"]) is False

    def test_cn_fallback_without_san(self, pki):
        assert mod.hostname_verify("legacy.example.net", pki["cn_only"]) is True
        assert mod.hostname_verify("attacker.example.net", pki["cn_only"]) is False

    def test_san_present_cn_ignored(self, pki):
        # leaf 的 SAN 含 *.example.com 通配，api2.example.com 按 RFC 6125 应匹配；
        # 这里要证明的是“CN 被忽略”——用 CN 与 SAN 不同的证书单独验证
        from cryptography.x509.oid import NameOID
        now = datetime.datetime.now(datetime.timezone.utc)
        key = _key()
        tricky = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "trusted.evil")]))
            .issuer_name(pki["ca_cert"].subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("good.example")]),
                           critical=False)
            .sign(pki["ca_key"], hashes.SHA256())
        )
        # SAN 中的名称通过
        assert mod.hostname_verify("good.example", tricky) is True
        # CN 中的名称（SAN 未包含）必须被忽略
        assert mod.hostname_verify("trusted.evil", tricky) is False
        # leaf2：SAN 与 CN 同名，以 SAN 为准
        assert mod.hostname_verify("api2.example.com", pki["leaf2"]) is True

    def test_invalid_inputs(self, pki):
        assert mod.hostname_verify("", pki["leaf"]) is False
        assert mod.hostname_verify(None, pki["leaf"]) is False
        assert mod.hostname_verify("api.example.com", b"not-a-cert") is False

    def test_der_bytes_accepted(self, pki):
        der = pki["leaf"].public_bytes(serialization.Encoding.DER)
        assert mod.hostname_verify("api.example.com", der) is True

    def test_ip_address_requires_ip_san(self, pki, tmp_path):
        import ipaddress
        _, ip_leaf = _make_leaf(
            pki["ca_key"], pki["ca_cert"], "ip-host", ["ip-host"],
            ip_sans=[ipaddress.ip_address("10.20.30.40")],
        )
        assert mod.hostname_verify("10.20.30.40", ip_leaf) is True
        assert mod.hostname_verify("10.20.30.41", ip_leaf) is False


# ---------------------------------------------------------------------------
# 2. SPKI pin
# ---------------------------------------------------------------------------

class TestSPKIPin:
    def test_pin_is_rfc7469_style(self, pki):
        pin = mod.spki_sha256_pin(pki["leaf"])
        import base64, hashlib
        spki = pki["leaf"].public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert pin == base64.b64encode(hashlib.sha256(spki).digest()).decode()

    def test_matching_pin_accepted(self, pki):
        pin = mod.spki_sha256_pin(pki["leaf"])
        assert mod.spki_pin("api.example.com", pki["leaf"],
                            pins_by_domain={"api.example.com": [pin]}) is True

    def test_backup_pin_set(self, pki):
        wrong_pin = mod.spki_sha256_pin(pki["leaf2"])
        right_pin = mod.spki_sha256_pin(pki["leaf"])
        assert mod.spki_pin("api.example.com", pki["leaf"],
                            pins_by_domain={"api.example.com": [wrong_pin, right_pin]}) is True

    def test_wrong_pin_rejected(self, pki):
        wrong = mod.spki_sha256_pin(pki["leaf2"])
        assert mod.spki_pin("api.example.com", pki["leaf"],
                            pins_by_domain={"api.example.com": [wrong]}) is False

    def test_unconfigured_domain_fails_closed(self, pki):
        assert mod.spki_pin("unknown.example.com", pki["leaf"],
                            pins_by_domain={"api.example.com": ["x"]}) is False

    def test_direct_pin_comparison(self):
        # 形式二：actual pin 与期望 pin/集合比对
        assert mod.spki_pin("abc123", ["abc123"]) is True
        assert mod.spki_pin("abc123", ["abc123", "def"]) is True
        assert mod.spki_pin("abc123", ["def"]) is False
        assert mod.spki_pin("", ["x"]) is False
        assert mod.spki_pin("abc123", "abc123,def") is True
        assert mod.spki_pin("abc123", "def") is False


# ---------------------------------------------------------------------------
# 3. OCSP fail-closed
# ---------------------------------------------------------------------------

class TestOCSPFailClosed:
    def test_good_response_accepted(self, pki):
        resp = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "good")
        assert mod.ocsp_fail_closed(resp, pki["ca_cert"],
                                    expected_serial=pki["leaf"].serial_number) is True

    def test_revoked_rejected(self, pki):
        resp = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "revoked")
        assert mod.ocsp_fail_closed(resp, pki["ca_cert"],
                                    expected_serial=pki["leaf"].serial_number) is False

    def test_unknown_rejected(self, pki):
        resp = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "unknown")
        assert mod.ocsp_fail_closed(resp, pki["ca_cert"],
                                    expected_serial=pki["leaf"].serial_number) is False

    def test_bad_signature_rejected(self, pki):
        good = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "good")
        der = bytearray(good.public_bytes(serialization.Encoding.DER))
        # 翻转签名区最后一个字节，模拟传输中被篡改/错误密钥签发的响应
        der[-1] ^= 0xFF
        assert mod.ocsp_fail_closed(bytes(der), pki["ca_cert"],
                                    expected_serial=pki["leaf"].serial_number) is False

    def test_serial_mismatch_rejected(self, pki):
        resp = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "good")
        assert mod.ocsp_fail_closed(resp, pki["ca_cert"], expected_serial=1) is False

    def test_stale_next_update_rejected(self, pki):
        resp = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                              "good", stale=True)
        assert mod.ocsp_fail_closed(resp, pki["ca_cert"],
                                    expected_serial=pki["leaf"].serial_number) is False

    def test_garbage_bytes_rejected(self, pki):
        assert mod.ocsp_fail_closed(b"\x00\x01garbage", pki["ca_cert"]) is False
        assert mod.ocsp_fail_closed(None, pki["ca_cert"]) is False

    def test_timeout_raises_and_denies(self, pki):
        with mock.patch.object(mod.http.client.HTTPConnection, "request",
                               side_effect=socket.timeout("slow")):
            with pytest.raises(mod.OCSPVerificationError, match="fail-closed"):
                mod.fetch_ocsp(pki["leaf"], pki["ca_cert"], timeout=0.1)

    def test_network_error_raises_and_denies(self, pki):
        with mock.patch.object(mod.http.client.HTTPConnection, "request",
                               side_effect=OSError("unreachable")):
            with pytest.raises(mod.OCSPVerificationError):
                mod.fetch_ocsp(pki["leaf"], pki["ca_cert"], timeout=0.1)

    def test_der_roundtrip(self, pki):
        resp = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "good")
        der = resp.public_bytes(serialization.Encoding.DER)
        assert mod.ocsp_fail_closed(der, pki["ca_cert"],
                                    expected_serial=pki["leaf"].serial_number) is True

    def test_unsuccessful_response_status(self, pki):
        builder = ocsp.OCSPResponseBuilder().build_unsuccessful(
            ocsp.OCSPResponseStatus.TRY_LATER
        )
        assert mod.ocsp_fail_closed(builder, pki["ca_cert"]) is False


# ---------------------------------------------------------------------------
# 4. 超时与 SNI
# ---------------------------------------------------------------------------

class TestTimeoutsAndSNI:
    def test_finite_timeouts_required(self):
        t = mod.connect_timeout(3, 7)
        assert t.connect == 3.0 and t.handshake == 7.0

    @pytest.mark.parametrize("c,h", [(0, 5), (5, 0), (-1, 5), (float("inf"), 5),
                                    (None, 5), ("5", 5), (True, 5)])
    def test_bad_timeouts_rejected(self, c, h):
        with pytest.raises((ValueError, TypeError)):
            mod.connect_timeout(c, h)

    def test_real_connect_timeout(self):
        # 不可路由地址 + 极短超时，必须在限定时间内抛出而不是挂死
        t = mod.connect_timeout(0.2, 0.2)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(t.connect)
        with pytest.raises(socket.timeout):
            sock.connect(("10.255.255.1", 9999))
        sock.close()

    def test_sni_on_wrapped_socket(self, pki):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(
            certfile=self._write_chain(pki), keyfile=self._write_key(pki)
        )
        port, ready = self._start_server(server)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                tls = ctx.wrap_socket(raw, server_hostname="api.example.com")
                assert mod.sni_set("api.example.com", tls) is True
                assert mod.sni_set("other.example.com", tls) is False
                tls.close()
        finally:
            ready.set()

    @staticmethod
    def _write_chain(pki):
        import tempfile, os
        d = tempfile.mkdtemp()
        cert_path = os.path.join(d, "cert.pem")
        with open(cert_path, "wb") as f:
            f.write(pki["leaf"].public_bytes(serialization.Encoding.PEM))
            f.write(pki["ca_cert"].public_bytes(serialization.Encoding.PEM))
        return cert_path

    @staticmethod
    def _write_key(pki):
        import tempfile, os
        d = tempfile.mkdtemp()
        key_path = os.path.join(d, "key.pem")
        with open(key_path, "wb") as f:
            f.write(pki["leaf_key"].private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        return key_path

    @staticmethod
    def _start_server(server_ctx):
        import contextlib
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        ready = threading.Event()

        def serve():
            with contextlib.suppress(OSError):
                conn, _ = listener.accept()
                tls = server_ctx.wrap_socket(conn, server_side=True)
                ready.wait(5)
                with contextlib.suppress(OSError):
                    tls.close()
            listener.close()

        threading.Thread(target=serve, daemon=True).start()
        return port, ready


# ---------------------------------------------------------------------------
# 其余策略函数
# ---------------------------------------------------------------------------

class TestPolicies:
    def test_ca_bundle_existing_and_missing(self, pki):
        assert mod.ca_bundle(pki["ca_path"]) == pki["ca_path"]
        assert mod.ca_bundle("/nonexistent/ca.pem") == ""

    def test_redirect_https(self):
        assert mod.redirect_https("https://api.example.com/v2") is True
        assert mod.redirect_https("http://api.example.com/v2") is False
        assert mod.redirect_https("ftp://api.example.com/") is False
        assert mod.redirect_https("") is False
        # 跨主机控制
        assert mod.redirect_https("https://evil.com/x", "api.example.com") is False
        assert mod.redirect_https("https://api.example.com/x", "api.example.com") is True

    def test_cipher_policy_minimum_tls12(self):
        policy = mod.cipher_policy()
        assert policy.minimum_version == ssl.TLSVersion.TLSv1_2
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        policy.apply(ctx)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
        # 试图降到 TLS1.1 会被拉回
        weak = mod.cipher_policy("HIGH:!aNULL", ssl.TLSVersion.TLSv1_1)
        assert weak.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_cert_expiry(self, pki):
        assert mod.cert_expiry(pki["leaf"]) is True
        assert mod.cert_expiry(pki["expired"]) is False
        assert mod.cert_expiry(b"garbage") is False

    def test_validation_aggregate(self, pki):
        pin = mod.spki_sha256_pin(pki["leaf"])
        ocsp_good = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "good")
        ok = mod.validation(
            pki["leaf"], "api.example.com", [pki["ca_cert"]],
            require_pin=True,
            pins_by_domain={"api.example.com": [pin]},
            ocsp_response=ocsp_good,
        )
        assert ok is True
        # 主机名错误
        assert mod.validation(pki["leaf"], "evil.com", [pki["ca_cert"]]) is False
        # OCSP 撤销
        revoked = _ocsp_response(pki["ca_key"], pki["ca_cert"], pki["leaf"], "revoked")
        assert mod.validation(
            pki["leaf"], "api.example.com", [pki["ca_cert"]],
            ocsp_response=revoked,
        ) is False

    def test_error_map_stable_codes(self):
        cases = [
            (mod.HostnameVerificationError("x"), "TLS_HOSTNAME_MISMATCH"),
            (mod.PinVerificationError("x"), "TLS_PIN_MISMATCH"),
            (mod.OCSPVerificationError("x"), "TLS_OCSP_DENIED"),
            (socket.timeout(), "TLS_TIMEOUT"),
            (mod.InsecureFallbackError("x"), "TLS_INSECURE_FALLBACK"),
            (RuntimeError("x"), "TLS_UNKNOWN_ERROR"),
        ]
        for exc, code in cases:
            mapped = mod.error_map(exc, {"host": "h"})
            assert mapped["error_code"] == code
            assert mapped["retryable"] is False

    def test_audit_structured(self):
        sink = []
        record = mod.audit("tls_verify", "api.example.com", decision="allow",
                           reason="ok", sink=sink)
        assert record["host"] == "api.example.com"
        assert record["decision"] == "allow"
        assert "timestamp" in record and sink[0] is record
        # 非法 decision 归一化为 deny
        bad = mod.audit("x", "h", decision="weird", sink=sink)
        assert bad["decision"] == "deny"

    def test_session_reuse_always_revalidates(self):
        policy = mod.session_reuse()
        assert policy["session_reuse"] is True
        assert policy["revalidate_on_resume"] is True
        assert mod.session_reuse(False)["ticket_lifetime_seconds"] == 0

    def test_pin_rotation_grace_period(self):
        result = mod.pin_rotation("api.example.com", ["new-pin"], old_pins=["old-pin"])
        assert result["rotated"] is True
        assert set(result["active_pins"]) == {"new-pin", "old-pin"}
        assert "grace_until" in result
        assert mod.pin_rotation("", ["x"])["rotated"] is False
        assert mod.pin_rotation("api.example.com", [])["rotated"] is False

    def test_fallback_denied_by_default_and_blocked_when_requested(self):
        assert mod.fallback()["fallback_allowed"] is False
        with pytest.raises(mod.InsecureFallbackError):
            mod.fallback(True, "debugging")


# ---------------------------------------------------------------------------
# 端到端：本地 TLS 服务器
# ---------------------------------------------------------------------------

class _LocalTLSServer:
    def __init__(self, pki, leaf_key, leaf_cert):
        self.pki = pki
        self.leaf_key = leaf_key
        self.leaf_cert = leaf_cert
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        import contextlib, tempfile
        d = tempfile.mkdtemp()
        cert_path, key_path = f"{d}/c.pem", f"{d}/k.pem"
        with open(cert_path, "wb") as f:
            f.write(self.leaf_cert.public_bytes(serialization.Encoding.PEM))
            f.write(self.pki["ca_cert"].public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(self.leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        with contextlib.suppress(OSError):
            conn, _ = self.listener.accept()
            tls = ctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            body = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            tls.sendall(body)
            tls.close()
        self.listener.close()


@pytest.fixture
def local_server(pki):
    server = _LocalTLSServer(pki, pki["leaf_key"], pki["leaf"])
    yield server
    server._thread.join(timeout=3)


class TestEndToEnd:
    def _client(self, pki, **kwargs):
        pin = mod.spki_sha256_pin(pki["leaf"])
        return mod.SecureHttpsClient(
            pins_by_domain={"api.example.com": [pin]},
            ca_file=pki["ca_path"], require_ocsp=False, **kwargs
        )

    def _patch_to_local(self, local_port, hostnames):
        """把对指定主机名的出站连接重定向到本地测试服务器（IPv4/IPv6 通用）。"""
        real_socket = socket.socket
        port = local_port

        class RedirectingSocket(real_socket):
            def connect(self, address):
                host, _ = address
                if host in hostnames:
                    return super().connect(("127.0.0.1", port))
                return super().connect(address)

        def fake_create_connection(address, timeout=None, source_address=None):
            sock = RedirectingSocket(socket.AF_INET, socket.SOCK_STREAM)
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(address)
            return sock

        return mock.patch.object(mod.socket, "create_connection",
                                 side_effect=fake_create_connection)

    def test_successful_request(self, pki, local_server):
        client = self._client(pki)
        with self._patch_to_local(local_server.port, {"api.example.com"}):
            result = client.request("https://api.example.com/path")
        assert result["status"] == 200
        assert result["body"] == b"ok"
        assert result["peer_pin"] == mod.spki_sha256_pin(pki["leaf"])

    def test_wrong_pin_denied(self, pki, local_server):
        bad_pin = mod.spki_sha256_pin(pki["leaf2"])
        client = mod.SecureHttpsClient(
            pins_by_domain={"api.example.com": [bad_pin]},
            ca_file=pki["ca_path"], require_ocsp=False,
        )
        with self._patch_to_local(local_server.port, {"api.example.com"}):
            with pytest.raises(mod.PinVerificationError):
                client.request("https://api.example.com/")

    def test_hostname_mismatch_denied(self, pki, local_server):
        # 证书是 api.example.com（SAN 仅覆盖 example.com 系），
        # 以完全不在证书范围内的外域主机名发起 —— ssl 层 check_hostname 即拒绝
        pin = mod.spki_sha256_pin(pki["leaf"])
        client = mod.SecureHttpsClient(
            pins_by_domain={"evil.attacker.org": [pin]},
            ca_file=pki["ca_path"], require_ocsp=False,
        )
        with self._patch_to_local(local_server.port, {"evil.attacker.org"}):
            with pytest.raises((ssl.CertificateError, mod.HostnameVerificationError)):
                client.request("https://evil.attacker.org/")

    def test_hostname_mismatch_at_policy_layer(self, pki):
        # 策略函数本身对错误主机名返回 False
        assert mod.hostname_verify("evil.attacker.org", pki["leaf"]) is False
        assert mod.hostname_verify("api.example.com", pki["leaf"]) is True

    def test_plain_http_refused(self, pki):
        client = self._client(pki)
        with pytest.raises(mod.InsecureFallbackError):
            client.request("http://api.example.com/")

    def test_missing_ca_fails_closed(self):
        with pytest.raises(mod.CertificateValidationError):
            mod.SecureHttpsClient(ca_file="/no/such/ca.pem", require_ocsp=False)

    def test_context_enforces_hostname_and_cert(self, pki):
        client = self._client(pki)
        assert client._ctx.check_hostname is True
        assert client._ctx.verify_mode == ssl.CERT_REQUIRED

    def test_ocsp_required_but_unreachable_denied(self, pki, local_server):
        client = mod.SecureHttpsClient(
            pins_by_domain={"api.example.com": [mod.spki_sha256_pin(pki["leaf"])]},
            ca_file=pki["ca_path"], require_ocsp=True, ocsp_timeout=0.2,
        )
        with self._patch_to_local(local_server.port, {"api.example.com"}):
            with mock.patch.object(mod, "fetch_ocsp",
                                   side_effect=mod.OCSPVerificationError("OCSP 查询超时，fail-closed")):
                with pytest.raises(mod.OCSPVerificationError):
                    client.request("https://api.example.com/")

    def test_audit_trail_written(self, pki, local_server):
        sink = []
        client = self._client(pki, audit_sink=sink)
        with self._patch_to_local(local_server.port, {"api.example.com"}):
            client.request("https://api.example.com/")
        decisions = {(e["event"], e["decision"]) for e in sink}
        assert ("tls_verify", "allow") in decisions

    def test_http_downgrade_redirect_denied(self, pki, monkeypatch):
        # 服务器返回 302 到 http:// —— 必须被 redirect_https 拦截
        client = self._client(pki)
        redirect_response = (
            b"HTTP/1.1 302 Found\r\nLocation: http://api.example.com/insecure\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

        class RedirectServer(_LocalTLSServer):
            def _serve(self):
                import contextlib, tempfile
                d = tempfile.mkdtemp()
                cert_path, key_path = f"{d}/c.pem", f"{d}/k.pem"
                with open(cert_path, "wb") as f:
                    f.write(self.leaf_cert.public_bytes(serialization.Encoding.PEM))
                    f.write(self.pki["ca_cert"].public_bytes(serialization.Encoding.PEM))
                with open(key_path, "wb") as f:
                    f.write(self.leaf_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()))
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert_path, key_path)
                with contextlib.suppress(OSError):
                    conn, _ = self.listener.accept()
                    tls = ctx.wrap_socket(conn, server_side=True)
                    tls.recv(4096)
                    tls.sendall(redirect_response)
                    tls.close()
                self.listener.close()

        server = RedirectServer(pki, pki["leaf_key"], pki["leaf"])
        try:
            with self._patch_to_local(server.port, {"api.example.com"}):
                with pytest.raises(mod.RedirectError):
                    client.request("https://api.example.com/redirect")
        finally:
            server._thread.join(timeout=3)
