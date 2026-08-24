"""TLS probing: open a connection, keep the certificate, judge it.

The design decision that shapes this module: the handshake is done twice when
it fails. Once with verification on, to learn the real verdict, and — only if
that raises — once with verification off, to actually obtain the certificate so
we can report *why*. Without the second pass an expired certificate and an
unreachable host look identical, which is the failure mode that makes most
expiry monitors useless: they tell you something is wrong, not what.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10.0

# Certificate notBefore/notAfter are always in this format, always GMT.
_CERT_TIME = "%b %d %H:%M:%S %Y %Z"


class Status:
    """Verdicts, ordered by severity. Used for exit codes and sorting."""

    OK = "ok"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    UNTRUSTED = "untrusted"
    HOSTNAME_MISMATCH = "hostname_mismatch"
    UNREACHABLE = "unreachable"

    SEVERITY = {
        OK: 0,
        EXPIRING: 1,
        HOSTNAME_MISMATCH: 2,
        UNTRUSTED: 2,
        EXPIRED: 3,
        UNREACHABLE: 3,
    }


@dataclass
class Result:
    host: str
    port: int = DEFAULT_PORT
    status: str = Status.OK
    days_left: int | None = None
    not_after: datetime | None = None
    not_before: datetime | None = None
    issuer: str | None = None
    subject: str | None = None
    san: list[str] = field(default_factory=list)
    tls_version: str | None = None
    detail: str = ""

    @property
    def severity(self) -> int:
        return Status.SEVERITY.get(self.status, 3)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "days_left": self.days_left,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "issuer": self.issuer,
            "subject": self.subject,
            "san": self.san,
            "tls_version": self.tls_version,
            "detail": self.detail,
        }


def _parse_cert_time(value: str) -> datetime:
    """Parse a certificate timestamp into an aware UTC datetime.

    strptime's %Z accepts "GMT" but does not attach a timezone, so the result
    is naive and would blow up on subtraction against an aware `now`. Attaching
    UTC explicitly is correct: these fields are defined to be GMT.
    """
    return datetime.strptime(value, _CERT_TIME).replace(tzinfo=timezone.utc)


def _rdn_to_str(rdn) -> str:
    """Flatten the nested tuple structure OpenSSL uses for names."""
    parts = []
    for item in rdn or ():
        for key, value in item:
            if key in ("commonName", "organizationName"):
                parts.append(value)
    return ", ".join(parts)


def _extract(cert: dict, result: Result) -> None:
    """Copy the fields we report out of the parsed certificate."""
    if not cert:
        return

    if "notAfter" in cert:
        result.not_after = _parse_cert_time(cert["notAfter"])
        delta = result.not_after - datetime.now(timezone.utc)
        # Truncate toward negative infinity: a cert with 3 hours left has 0 days
        # left, and one that expired 3 hours ago is -1. Rounding up here would
        # report a dead certificate as still having a day.
        result.days_left = delta.days

    if "notBefore" in cert:
        result.not_before = _parse_cert_time(cert["notBefore"])

    result.issuer = _rdn_to_str(cert.get("issuer"))
    result.subject = _rdn_to_str(cert.get("subject"))
    result.san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]


def _fetch_unverified(host: str, port: int, timeout: float) -> tuple[dict, str]:
    """Second-pass handshake with verification disabled, to obtain the cert.

    Only ever called after a verified handshake has already failed. The point
    is diagnosis, not trust — nothing from here is treated as validated.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            # getpeercert() returns {} when the cert was never validated, so
            # the DER form has to be decoded to get at the fields.
            der = tls.getpeercert(binary_form=True)
            version = tls.version()

    if not der:
        return {}, version

    # ssl has no public DER->dict decoder. This private helper is the only way
    # to parse an unvalidated certificate without pulling in a dependency, and
    # it has been present and stable across 3.x. Guarded so a future removal
    # degrades to "no detail" rather than a crash.
    try:
        return ssl._ssl._test_decode_cert_bytes(der), version  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        pass

    try:
        import tempfile

        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as fh:
            fh.write(pem)
            fh.flush()
            return ssl._ssl._test_decode_cert(fh.name), version  # type: ignore[attr-defined]
    except Exception:
        return {}, version


def check(host: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT,
          warn_days: int = 21) -> Result:
    """Probe one host and return a verdict.

    Never raises for a remote-side problem: every failure mode is a Result with
    a status. A monitor that throws on the first bad host cannot check a list.
    """
    result = Result(host=host, port=port)
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                result.tls_version = tls.version()
        _extract(cert, result)

        if result.days_left is None:
            result.status = Status.UNTRUSTED
            result.detail = "handshake succeeded but no certificate was returned"
        elif result.days_left < 0:
            result.status = Status.EXPIRED
            result.detail = f"expired {abs(result.days_left)} day(s) ago"
        elif result.days_left <= warn_days:
            result.status = Status.EXPIRING
            result.detail = f"expires in {result.days_left} day(s)"
        else:
            result.status = Status.OK
        return result

    except ssl.SSLCertVerificationError as exc:
        # Verification failed. Re-probe without verification so the report can
        # say which of the several possible reasons it actually was.
        cert, version = {}, None
        try:
            cert, version = _fetch_unverified(host, port, timeout)
        except OSError:
            pass
        _extract(cert, result)
        result.tls_version = version

        reason = (exc.verify_message or str(exc)).lower()
        if "hostname mismatch" in reason or "doesn't match" in reason:
            result.status = Status.HOSTNAME_MISMATCH
            names = ", ".join(result.san) or result.subject or "none"
            result.detail = f"certificate is not valid for {host} (presented: {names})"
        elif result.days_left is not None and result.days_left < 0:
            # Expiry is reported as expiry even though it surfaced as a
            # verification failure — "untrusted" would bury the actual cause.
            result.status = Status.EXPIRED
            result.detail = f"expired {abs(result.days_left)} day(s) ago"
        elif "self signed" in reason or "self-signed" in reason:
            result.status = Status.UNTRUSTED
            result.detail = "self-signed certificate"
        else:
            result.status = Status.UNTRUSTED
            result.detail = exc.verify_message or "certificate verification failed"
        return result

    except (socket.timeout, TimeoutError):
        result.status = Status.UNREACHABLE
        result.detail = f"timed out after {timeout:g}s"
        return result
    except socket.gaierror as exc:
        result.status = Status.UNREACHABLE
        result.detail = f"dns lookup failed: {exc.strerror or exc}"
        return result
    except (ConnectionRefusedError, ConnectionResetError) as exc:
        result.status = Status.UNREACHABLE
        result.detail = f"connection failed: {type(exc).__name__}"
        return result
    except ssl.SSLError as exc:
        result.status = Status.UNREACHABLE
        result.detail = f"tls error: {exc.reason or exc}"
        return result
    except OSError as exc:
        result.status = Status.UNREACHABLE
        result.detail = f"{type(exc).__name__}: {exc}"
        return result
