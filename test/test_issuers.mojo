# The CA and leaf issuers return 0, the errno of a key or certificate file
# they could not write, or -1 when OpenSSL refused, so a caller can tell a
# full or missing directory from a failed signature.

from std.ffi import OwnedDLHandle, c_int
from std.testing import assert_equal

from tls.tls import _shim_path

comptime ENOENT = 2
comptime WRITABLE = "build/certs"
comptime MISSING = "build/no-such-issuer-dir"


def ca_new(lib: OwnedDLHandle, cert: String, key: String) raises -> Int:
    var name = String("issuer test ca")
    var cert_path = cert.copy()
    var key_path = key.copy()
    return Int(
        lib.get_function[c_int]("mts_ca_new")(
            name.as_c_string_span(),
            cert_path.as_c_string_span(),
            key_path.as_c_string_span(),
        )
    )


def leaf_issue(
    lib: OwnedDLHandle,
    ca_cert: String,
    ca_key: String,
    cert: String,
    key: String,
) raises -> Int:
    var server_name = String("issuer.test")
    var ca_cert_path = ca_cert.copy()
    var ca_key_path = ca_key.copy()
    var cert_path = cert.copy()
    var key_path = key.copy()
    return Int(
        lib.get_function[c_int]("mts_leaf_issue")(
            ca_cert_path.as_c_string_span(),
            ca_key_path.as_c_string_span(),
            server_name.as_c_string_span(),
            cert_path.as_c_string_span(),
            key_path.as_c_string_span(),
        )
    )


def test_ca_write_into_a_missing_directory_returns_its_errno() raises:
    var lib = OwnedDLHandle(_shim_path())
    var rc = ca_new(lib, MISSING + "/ca.pem", MISSING + "/ca.key")
    assert_equal(rc, ENOENT)


def test_leaf_write_into_a_missing_directory_returns_its_errno() raises:
    var lib = OwnedDLHandle(_shim_path())
    var ca_cert = String(WRITABLE, "/issuer-ca.pem")
    var ca_key = String(WRITABLE, "/issuer-ca.key")
    assert_equal(ca_new(lib, ca_cert, ca_key), 0)
    var rc = leaf_issue(
        lib, ca_cert, ca_key, MISSING + "/leaf.pem", MISSING + "/leaf.key"
    )
    assert_equal(rc, ENOENT)
    var issued = leaf_issue(
        lib,
        ca_cert,
        ca_key,
        String(WRITABLE, "/issuer-leaf.pem"),
        String(WRITABLE, "/issuer-leaf.key"),
    )
    assert_equal(issued, 0)


def main() raises:
    test_ca_write_into_a_missing_directory_returns_its_errno()
    test_leaf_write_into_a_missing_directory_returns_its_errno()
    print("test_issuers: all tests passed")
