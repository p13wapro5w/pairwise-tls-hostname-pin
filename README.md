# pairwise-tls-hostname-pin

## 领域

安全

## 主题

出站 TLS 校验

## 说明

主机名校验、证书固定与 OCSP 失败关闭。

`security/tls_hostname_pin.py` 实现了一个严格的出站 HTTPS 客户端，修复以下四类缺陷：

### 1. 强制主机名校验（`hostname_verify`）

- 按 RFC 6125 比对证书 SAN 中的 DNSName / IPAddress；存在 SAN 时 CN 不再作为可信来源。
- 通配符只允许出现在最左侧标签，且只匹配单个标签（`*.example.com` 匹配 `a.example.com`，不匹配 `a.b.example.com`）。
- IP 地址只与 SAN `iPAddress` 精确比较，不走 DNS 通配。
- `SecureHttpsClient` 的 SSLContext 显式 `check_hostname=True` + `CERT_REQUIRED`，策略层再断言一次。

### 2. 按域名固定公钥指纹（`spki_pin` / `spki_sha256_pin`）

- 对叶子证书的 SubjectPublicKeyInfo 计算 `base64(SHA-256)`（RFC 7469 / HPKP 风格 pin）。
- 每个域名维护独立 pin 集合，支持主 pin + 备份 pin；不匹配即拒绝。
- 客户端配置了 pin 但目标域名未配置时 fail-closed（拒绝，而非静默放行）。
- `pin_rotation` 支持轮换宽限期：过渡期同时信任新旧 pin，到期只认新 pin。

### 3. OCSP 失败即拒绝（`ocsp_fail_closed` / `fetch_ocsp`）

只在以下条件全部满足时放行，其余一律拒绝：

- 响应可解析且 `response_status == SUCCESSFUL`；
- 证书状态为 `GOOD`（`REVOKED` / `UNKNOWN` / `TRY_LATER` 全部拒绝）；
- 序列号与目标证书一致，`this_update` / `next_update` 在有效期内（含时钟偏移容差）；
- 签名由颁发者直签，或由带 `id-kp-OCSPSigning` EKU、同一颁发者签发的委派者签名。

OCSP 查询超时、responder 不可达、HTTP 非 200 都转换为 `OCSPVerificationError` 并拒绝连接，
**绝不把超时当成通过**。

### 4. 连接与握手超时（`connect_timeout`）

- `Timeouts` 数据类强制 TCP 连接超时与 TLS 握手超时都是有限正数，拒绝 0、负数、`inf`、非数字。
- 客户端在 `socket.create_connection` 上施加连接超时，在 `wrap_socket`（握手）之前设置握手超时，
  握手完成后恢复连接超时用于数据读写。

### 其余控制项

| 函数 | 作用 |
| --- | --- |
| `sni_set` | 确认连接通过 `server_hostname` 设置了 SNI |
| `ca_bundle` | 解析并校验可信 CA bundle，无信任锚点时客户端拒绝启动 |
| `redirect_https` | 重定向必须是 https，默认禁止跨主机 |
| `cipher_policy` | 仅前向保密 AEAD 套件，最低 TLS 1.2，禁用压缩 |
| `cert_expiry` | 证书有效期校验（含时钟偏移容差） |
| `validation` | 主机名 + 有效期 + pin + OCSP 的汇总布尔判定 |
| `error_map` | 内部异常到稳定错误码的映射，避免泄漏内部细节 |
| `audit` | 结构化安全决策审计（allow/deny + 原因 + 时间戳） |
| `session_reuse` | 会话复用策略，恢复连接必须重新通过全部校验 |
| `fallback` | 不安全回退总开关，默认拒绝，显式请求放行时抛异常 |

## 测试

```bash
python -m pytest -q
```

- `tests/test_tls_hostname_pin.py`：原始契约测试（15 个入口均返回非 None）。
- `tests/test_security_controls.py`：离线自包含的安全行为测试，自建 CA/叶子证书与本地 TLS 服务器，
  覆盖主机名、SPKI pin、OCSP fail-closed、连接/握手超时、SNI、重定向、密码套件、审计、回退等正反用例。
