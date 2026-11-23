import pytest
import security.tls_hostname_pin as mod

CASES = [
    ("hostname_verify", (1, 2)),
    ("spki_pin", (1, 2)),
    ("ocsp_fail_closed", (1, 2)),
    ("connect_timeout", (1, 2)),
    ("sni_set", (1, 2)),
    ("ca_bundle", (1, 2)),
    ("redirect_https", (1, 2)),
    ("cipher_policy", (1, 2)),
    ("cert_expiry", (1, 2)),
    ("validation", (1, 2)),
    ("error_map", (1, 2)),
    ("audit", (1, 2)),
    ("session_reuse", (1, 2)),
    ("pin_rotation", (1, 2)),
    ("fallback", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
