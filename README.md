# pairwise-tls-hostname-pin

## 领域

安全

## 主题

出站 TLS 校验

## 说明

主机名校验、证书固定与 OCSP 失败关闭。

初始状态下 `security/tls_hostname_pin.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
