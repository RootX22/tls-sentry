# tls-sentry

[![CI](https://github.com/RootX22/tls-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/RootX22/tls-sentry/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-0e75b6.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Dependencies: none](https://img.shields.io/badge/runtime%20deps-none-5ee1a0)

Check TLS certificates for expiry, trust, and hostname match. Tells you *what*
is wrong, not just that something is.

```console
$ tls-sentry github.com expired.badssl.com self-signed.badssl.com wrong.host.badssl.com
  XX  expired.badssl.com:443       -4152d   expired 4152 day(s) ago
  XX  self-signed.badssl.com:443     724d   self-signed certificate
  XX  wrong.host.badssl.com:443       63d   certificate is not valid for wrong.host.badssl.com (presented: *.badssl.com, badssl.com)
  OK  github.com:443                  37d

  4 checked — 1 expired  1 hostname_mismatch  1 ok  1 untrusted
$ echo $?
1
```

## Why

Certificate renewal automation fails silently. The first symptom is usually a
customer email, and by then you are debugging under pressure.

Most expiry checkers have a blind spot that makes them less useful than they
look: an expired certificate **fails TLS verification**, so a naive check gets
an exception and reports "connection failed" — indistinguishable from the host
being down. You learn something is wrong, not what.

tls-sentry handshakes twice. Once with verification on, to get the real verdict.
Then, only if that failed, once with verification off — purely to obtain the
certificate so it can tell you *why*. That is why the output above shows
`-4152d` for a certificate that no client would accept, and why a hostname
mismatch lists the names actually presented.

Nothing from the second handshake is treated as trusted. It exists for
diagnosis.

## Install

```bash
pip install git+https://github.com/RootX22/tls-sentry.git
```

Or just run it — there are **no runtime dependencies**, only the standard
library:

```bash
git clone https://github.com/RootX22/tls-sentry.git
python3 -m tlssentry example.com
```

That constraint is deliberate. This is the kind of thing that runs from cron on
a bare server, and needing a virtualenv first is how monitoring quietly stops
running.

## Usage

```bash
tls-sentry example.com api.example.com:8443
tls-sentry --file hosts.txt              # one target per line, # comments ok
tls-sentry --file - < hosts.txt          # or stdin
tls-sentry --json example.com            # machine-readable
tls-sentry -w 45 --file hosts.txt        # warn 45 days out instead of 21
tls-sentry --webhook https://hooks.example.com/x --file hosts.txt
```

| Flag | Default | Meaning |
|---|---|---|
| `-w, --warn-days` | `21` | Days before expiry to start warning |
| `-t, --timeout` | `10` | Per-host timeout in seconds |
| `-j, --jobs` | `8` | Parallel connections |
| `--json` | off | JSON to stdout |
| `--webhook URL` | — | POST findings (non-OK only) |
| `--fail-on` | `expiring` | `expiring`, `expired`, or `never` |

### Statuses

| Status | Meaning |
|---|---|
| `ok` | Valid, trusted, matches the hostname, outside the warning window |
| `expiring` | Valid but inside the warning window |
| `expired` | Past `notAfter` |
| `untrusted` | Chain does not validate — self-signed, unknown CA |
| `hostname_mismatch` | Valid certificate, wrong name for this host |
| `unreachable` | DNS failure, refused, timed out |

### Exit codes

`0` nothing at or above the threshold · `1` findings · `2` usage error.

`--fail-on expired` is the useful one for a pipeline you do not want going red
for weeks while a renewal is still comfortably in the future.

## In CI

```yaml
- name: Certificate check
  run: |
    pip install git+https://github.com/RootX22/tls-sentry.git
    tls-sentry --file hosts.txt --warn-days 30 --fail-on expired
```

## On a cron

```cron
0 8 * * * /usr/local/bin/tls-sentry --file /etc/tls-hosts.txt \
            --webhook "$SLACK_URL" --fail-on never >/dev/null
```

`--fail-on never` because cron mailing you a non-zero exit on top of the
webhook is just two notifications for one problem.

## As a library

```python
from tlssentry import check

r = check("example.com", warn_days=30)
print(r.status, r.days_left, r.detail)
print(r.san, r.issuer, r.tls_version)
```

`check()` never raises for a remote-side problem — every failure mode comes
back as a `Result` with a status. A monitor that throws on the first bad host
cannot check a list.

## Limitations

Worth knowing before you rely on it:

- **Leaf certificate only.** It reports the expiry of the certificate the host
  serves, not of the intermediates in its chain. An intermediate expiring
  sooner than the leaf will not be caught.
- **No OCSP or CRL.** A revoked-but-unexpired certificate reports `ok`.
- **No IPv6 literals.** `host:port` parsing rejects them rather than
  mis-parsing; hostnames that resolve to IPv6 are fine.
- **Trust store is the system's.** Results reflect what *this* machine trusts,
  which is usually what you want and occasionally surprising in a container
  with a stale `ca-certificates`.
- The unverified second handshake uses a private `ssl` helper to decode the
  certificate, because the standard library exposes no public way to parse one
  it did not validate. It is guarded: if that helper disappears, the tool
  degrades to reporting the status without the certificate detail rather than
  crashing.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

Classification tests generate a throwaway CA and leaf certificates locally
rather than reaching badssl.com — a unit suite that fails when the wifi drops
teaches people to ignore red builds. The live check against badssl.com is a
separate CI job marked `continue-on-error`, as a canary that the real world
still matches what the fixtures assume.

## Licence

MIT
