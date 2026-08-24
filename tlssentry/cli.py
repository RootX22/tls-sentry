"""Command-line interface."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import urllib.error
import urllib.request

from .probe import DEFAULT_PORT, DEFAULT_TIMEOUT, Result, Status, check

# Exit codes are part of the interface — CI gates on them.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_COLOURS = {
    Status.OK: "\033[32m",
    Status.EXPIRING: "\033[33m",
    Status.EXPIRED: "\033[31m",
    Status.UNTRUSTED: "\033[31m",
    Status.HOSTNAME_MISMATCH: "\033[31m",
    Status.UNREACHABLE: "\033[35m",
}
_RESET = "\033[0m"
_SYMBOLS = {
    Status.OK: "OK",
    Status.EXPIRING: "!!",
    Status.EXPIRED: "XX",
    Status.UNTRUSTED: "XX",
    Status.HOSTNAME_MISMATCH: "XX",
    Status.UNREACHABLE: "??",
}


def _use_colour(stream) -> bool:
    # Respect NO_COLOR (https://no-color.org) and never colour a pipe.
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def parse_target(raw: str) -> tuple[str, int]:
    """Split "host" or "host:port" into its parts.

    Bare IPv6 is not supported; it would need bracket syntax and there is no
    call for it yet. Rejecting it clearly beats mis-parsing it silently.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    if raw.count(":") > 1:
        raise ValueError(f"cannot parse target {raw!r} (IPv6 is not supported)")
    if ":" in raw:
        host, _, port = raw.partition(":")
        if not port.isdigit():
            raise ValueError(f"invalid port in {raw!r}")
        port_i = int(port)
        if not 1 <= port_i <= 65535:
            raise ValueError(f"port out of range in {raw!r}")
        return host, port_i
    return raw, DEFAULT_PORT


def load_targets(args) -> list[tuple[str, int]]:
    raw: list[str] = list(args.hosts)

    if args.file:
        if args.file == "-":
            raw.extend(sys.stdin.read().splitlines())
        else:
            with open(args.file) as fh:
                raw.extend(fh.read().splitlines())

    targets, seen = [], set()
    for line in raw:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        target = parse_target(line)
        if target not in seen:      # de-duplicate, keep first-seen order
            seen.add(target)
            targets.append(target)
    return targets


def render_text(results: list[Result], stream, warn_days: int) -> None:
    colour = _use_colour(stream)

    def paint(status: str, text: str) -> str:
        if not colour:
            return text
        return f"{_COLOURS.get(status, '')}{text}{_RESET}"

    width = max((len(f"{r.host}:{r.port}") for r in results), default=20)
    width = min(max(width, 20), 50)

    for r in results:
        target = f"{r.host}:{r.port}"
        days = "—" if r.days_left is None else f"{r.days_left}d"
        line = f"  {paint(r.status, _SYMBOLS.get(r.status, '??'))}  {target:<{width}}  {days:>7}"
        if r.detail:
            line += f"   {r.detail}"
        print(line, file=stream)

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print(file=stream)
    summary = "  ".join(f"{n} {s}" for s, n in sorted(counts.items()))
    print(f"  {len(results)} checked — {summary}", file=stream)
    if counts.get(Status.OK) == len(results):
        print(f"  all valid, none expiring within {warn_days} days", file=stream)


def post_webhook(url: str, results: list[Result], timeout: float) -> bool:
    """POST the non-OK results. Returns whether it succeeded.

    A failed webhook must not change the exit code — the certificate findings
    are the answer, and losing them because a chat service was down would be
    the wrong trade.
    """
    findings = [r.to_dict() for r in results if r.status != Status.OK]
    if not findings:
        return True

    body = json.dumps({
        "text": f"tls-sentry: {len(findings)} certificate finding(s)",
        "findings": findings,
    }).encode()

    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        print(f"warning: webhook failed: {exc}", file=sys.stderr)
        return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tls-sentry",
        description="Check TLS certificates for expiry, trust, and hostname match.",
        epilog="Exit codes: 0 nothing at or above the threshold, 1 findings, 2 usage error.",
    )
    p.add_argument("hosts", nargs="*", help="host or host:port")
    p.add_argument("-f", "--file", help="file of targets, one per line ('-' for stdin)")
    p.add_argument("-w", "--warn-days", type=int, default=21,
                   help="days before expiry to start warning (default: 21)")
    p.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"per-host timeout in seconds (default: {DEFAULT_TIMEOUT:g})")
    p.add_argument("-j", "--jobs", type=int, default=8,
                   help="parallel connections (default: 8)")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--webhook", help="POST findings to this URL")
    p.add_argument("--fail-on", choices=["expiring", "expired", "never"], default="expiring",
                   help="lowest severity that exits non-zero (default: expiring)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.warn_days < 0:
        print("tls-sentry: --warn-days cannot be negative", file=sys.stderr)
        return EXIT_USAGE
    if args.jobs < 1:
        print("tls-sentry: --jobs must be at least 1", file=sys.stderr)
        return EXIT_USAGE

    try:
        targets = load_targets(args)
    except (ValueError, OSError) as exc:
        print(f"tls-sentry: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not targets:
        print("tls-sentry: no targets given", file=sys.stderr)
        return EXIT_USAGE

    # Network-bound, so threads are the right tool and the pool is capped at
    # the number of targets to avoid spawning idle workers.
    workers = min(args.jobs, len(targets))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(check, host, port, args.timeout, args.warn_days): (host, port)
            for host, port in targets
        }
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Worst first, then alphabetical — the thing you need to act on is at the top.
    results.sort(key=lambda r: (-r.severity, r.host, r.port))

    if args.json:
        json.dump(
            {
                "warn_days": args.warn_days,
                "checked": len(results),
                "results": [r.to_dict() for r in results],
            },
            sys.stdout,
            indent=2,
        )
        print()
    else:
        render_text(results, sys.stdout, args.warn_days)

    if args.webhook:
        post_webhook(args.webhook, results, args.timeout)

    if args.fail_on == "never":
        return EXIT_OK
    threshold = (
        Status.SEVERITY[Status.EXPIRING] if args.fail_on == "expiring"
        else Status.SEVERITY[Status.EXPIRED]
    )
    return EXIT_FINDINGS if any(r.severity >= threshold for r in results) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
