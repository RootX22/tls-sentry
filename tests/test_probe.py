"""Probe tests.

The classification tests run against a locally-generated CA and leaf
certificates rather than against badssl.com. Network tests belong in their own
marked module: a unit suite that fails when the wifi drops trains people to
ignore red builds.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
from datetime import timedelta, timezone

import pytest

from tlssentry.probe import Result, Status, _parse_cert_time, check

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _make_cert(common_name, *, not_before, not_after, san=None, issuer_key=None,
               issuer_name=None, issuer_pubkey=None, is_ca=False):
    """Build a certificate. Self-signed unless an issuer key is supplied.

    These fixtures carry the full extension set a real CA issues — key usage,
    extended key usage, and crucially Subject/Authority Key Identifier. OpenSSL
    3.6 (which ships with Python 3.13) rejects a chain whose leaf has no
    Authority Key Identifier with "Missing Authority Key Identifier", so a
    minimal certificate that verified fine on older releases now fails. Every
    test then reports `untrusted`, which looks like a product bug and is not.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = issuer_name or subject

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
    )

    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
    )
    # AKI points at the signer's key — the issuer's for a signed leaf, its own
    # for anything self-signed.
    aki_source = issuer_pubkey or key.public_key()
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(aki_source), critical=False
    )

    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def _write(tmp_path, name, cert, key=None):
    cert_path = tmp_path / f"{name}.pem"
    data = cert.public_bytes(serialization.Encoding.PEM)
    if key is not None:
        data += key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    cert_path.write_bytes(data)
    return str(cert_path)


class TLSServer:
    """Minimal TLS server on a throwaway port, for one connection at a time."""

    def __init__(self, chain_path):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(chain_path)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                # The client only needs the handshake; it closes immediately
                # after reading the certificate, so errors here are expected.
                with self.ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ca")
    now = datetime.datetime.now(timezone.utc).replace(tzinfo=None)
    cert, key = _make_cert(
        "tls-sentry test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=3650),
        is_ca=True,
    )
    return {"cert": cert, "key": key, "path": _write(tmp, "ca", cert)}


def _serve_leaf(tmp_path, ca, *, days_left, san=("localhost",), self_signed=False):
    now = datetime.datetime.now(timezone.utc).replace(tzinfo=None)
    cert, key = _make_cert(
        "localhost",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=days_left),
        san=list(san),
        issuer_key=None if self_signed else ca["key"],
        issuer_name=None if self_signed else ca["cert"].subject,
        issuer_pubkey=None if self_signed else ca["key"].public_key(),
    )
    return TLSServer(_write(tmp_path, "leaf", cert, key))


def _check_against(server, ca_path, host="localhost", **kw):
    """Run check() with the test CA installed as the only trust root."""
    real_default = ssl.create_default_context

    def patched(*a, **k):
        ctx = real_default(*a, **k)
        ctx.load_verify_locations(cafile=ca_path)
        return ctx

    ssl.create_default_context = patched
    try:
        return check(host, server.port, timeout=5, **kw)
    finally:
        ssl.create_default_context = real_default


def test_valid_certificate_is_ok(tmp_path, ca):
    with _serve_leaf(tmp_path, ca, days_left=200) as srv:
        r = _check_against(srv, ca["path"])
    assert r.status == Status.OK
    assert 190 < r.days_left <= 200
    assert r.detail == ""


def test_certificate_inside_warning_window_is_expiring(tmp_path, ca):
    with _serve_leaf(tmp_path, ca, days_left=10) as srv:
        r = _check_against(srv, ca["path"], warn_days=21)
    assert r.status == Status.EXPIRING
    assert "10 day" in r.detail or "9 day" in r.detail


def test_warn_days_boundary_is_inclusive(tmp_path, ca):
    """A cert with exactly warn_days left must warn; one day more must pass.

    Off-by-one here means the last warning fires the day the cert dies.

    The threshold is derived from an actual probe rather than from the number
    the certificate was built with. `days_left` truncates, so a cert issued
    `not_after = now + 15 days` already reads as 14 by the time the handshake
    completes — asserting against the construction value tests the clock, not
    the boundary.
    """
    with _serve_leaf(tmp_path, ca, days_left=15) as srv:
        observed = _check_against(srv, ca["path"], warn_days=0).days_left
        assert observed is not None

        r = _check_against(srv, ca["path"], warn_days=observed)
        assert r.status == Status.EXPIRING, (
            f"{observed} days left with a {observed}-day window must warn"
        )

        r = _check_against(srv, ca["path"], warn_days=observed - 1)
        assert r.status == Status.OK, (
            f"{observed} days left with a {observed - 1}-day window should pass"
        )


def test_expired_certificate_reports_expiry_not_untrust(tmp_path, ca):
    """The whole point of the second-pass probe.

    An expired cert fails verification, so a naive implementation reports it as
    untrusted with no dates. It has to come back as EXPIRED with a day count.
    """
    with _serve_leaf(tmp_path, ca, days_left=-5) as srv:
        r = _check_against(srv, ca["path"])
    assert r.status == Status.EXPIRED
    assert r.days_left is not None and r.days_left < 0
    assert r.not_after is not None


def test_self_signed_certificate_is_untrusted(tmp_path, ca):
    with _serve_leaf(tmp_path, ca, days_left=100, self_signed=True) as srv:
        r = _check_against(srv, ca["path"])
    assert r.status == Status.UNTRUSTED
    # Still recovered the dates despite failing verification.
    assert r.days_left is not None


def test_hostname_mismatch_lists_the_names_presented(tmp_path, ca):
    with _serve_leaf(tmp_path, ca, days_left=100, san=("example.com",)) as srv:
        r = _check_against(srv, ca["path"], host="localhost")
    assert r.status == Status.HOSTNAME_MISMATCH
    assert "example.com" in r.detail


def test_connection_refused_is_unreachable_not_an_exception():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()                      # nothing is listening now

    r = check("127.0.0.1", port, timeout=3)
    assert r.status == Status.UNREACHABLE
    assert r.days_left is None


def test_dns_failure_is_unreachable():
    r = check("no-such-host-tls-sentry.invalid", timeout=3)
    assert r.status == Status.UNREACHABLE
    assert "dns" in r.detail.lower()


def test_parse_cert_time_returns_aware_utc():
    """Naive datetimes here would raise on subtraction against an aware now()."""
    dt = _parse_cert_time("Jun  1 12:00:00 2027 GMT")
    assert dt.tzinfo is not None
    assert dt.utcoffset() == timedelta(0)
    assert dt.year == 2027 and dt.month == 6


def test_severity_orders_worst_first():
    order = [Status.OK, Status.EXPIRING, Status.UNTRUSTED, Status.EXPIRED, Status.UNREACHABLE]
    sev = [Result(host="h", status=s).severity for s in order]
    assert sev == sorted(sev), "severity must be non-decreasing in this order"
    assert Result(host="h", status=Status.OK).severity == 0
