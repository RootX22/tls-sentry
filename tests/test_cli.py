"""CLI tests — argument handling, output shape, and exit codes.

These never touch the network: `check` is patched, so what is under test is the
CLI's own logic rather than the internet's mood.
"""

from __future__ import annotations

import json

import pytest

from tlssentry import cli
from tlssentry.probe import Result, Status


def fake_results(mapping):
    """Patch cli.check to return a canned status per host."""
    def _check(host, port=443, timeout=10.0, warn_days=21):
        status = mapping.get(host, Status.OK)
        days = {
            Status.OK: 200,
            Status.EXPIRING: 5,
            Status.EXPIRED: -3,
            Status.UNTRUSTED: 100,
            Status.HOSTNAME_MISMATCH: 100,
            Status.UNREACHABLE: None,
        }[status]
        return Result(host=host, port=port, status=status, days_left=days)
    return _check


# ── target parsing ──────────────────────────────────────────────────────────

def test_parse_target_defaults_to_443():
    assert cli.parse_target("example.com") == ("example.com", 443)


def test_parse_target_accepts_explicit_port():
    assert cli.parse_target("example.com:8443") == ("example.com", 8443)


@pytest.mark.parametrize("bad", ["", "host:notaport", "host:0", "host:70000", "a:b:c"])
def test_parse_target_rejects_malformed(bad):
    with pytest.raises(ValueError):
        cli.parse_target(bad)


def test_targets_are_deduplicated_preserving_order(tmp_path, monkeypatch):
    f = tmp_path / "hosts.txt"
    f.write_text("b.com\na.com\nb.com\na.com:443\n")
    args = cli.build_parser().parse_args(["--file", str(f)])
    assert cli.load_targets(args) == [("b.com", 443), ("a.com", 443)]


def test_comments_and_blank_lines_are_ignored(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("# a comment\n\na.com  # trailing\n   \nb.com\n")
    args = cli.build_parser().parse_args(["--file", str(f)])
    assert cli.load_targets(args) == [("a.com", 443), ("b.com", 443)]


# ── exit codes ──────────────────────────────────────────────────────────────

def test_all_ok_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check", fake_results({}))
    assert cli.main(["a.com", "b.com"]) == cli.EXIT_OK


def test_expiring_exits_one_by_default(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check", fake_results({"a.com": Status.EXPIRING}))
    assert cli.main(["a.com"]) == cli.EXIT_FINDINGS


def test_fail_on_expired_ignores_merely_expiring(monkeypatch, capsys):
    """--fail-on expired must not trip on a warning.

    This is the flag that lets a pipeline warn for weeks without going red, so
    getting it wrong makes the tool unusable in CI.
    """
    monkeypatch.setattr(cli, "check", fake_results({"a.com": Status.EXPIRING}))
    assert cli.main(["a.com", "--fail-on", "expired"]) == cli.EXIT_OK

    monkeypatch.setattr(cli, "check", fake_results({"a.com": Status.EXPIRED}))
    assert cli.main(["a.com", "--fail-on", "expired"]) == cli.EXIT_FINDINGS


def test_fail_on_never_always_exits_zero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check", fake_results({"a.com": Status.EXPIRED}))
    assert cli.main(["a.com", "--fail-on", "never"]) == cli.EXIT_OK


def test_no_targets_is_a_usage_error(capsys):
    assert cli.main([]) == cli.EXIT_USAGE


def test_negative_warn_days_is_a_usage_error(capsys):
    assert cli.main(["a.com", "--warn-days", "-1"]) == cli.EXIT_USAGE


def test_zero_jobs_is_a_usage_error(capsys):
    assert cli.main(["a.com", "--jobs", "0"]) == cli.EXIT_USAGE


# ── output ──────────────────────────────────────────────────────────────────

def test_json_output_is_valid_and_complete(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check", fake_results({"bad.com": Status.EXPIRED}))
    cli.main(["good.com", "bad.com", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["checked"] == 2
    assert {r["host"] for r in payload["results"]} == {"good.com", "bad.com"}
    for r in payload["results"]:
        assert set(r) >= {"host", "port", "status", "days_left", "not_after"}


def test_worst_result_is_listed_first(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check", fake_results({
        "zzz-expired.com": Status.EXPIRED,
        "aaa-expiring.com": Status.EXPIRING,
    }))
    cli.main(["aaa-ok.com", "aaa-expiring.com", "zzz-expired.com", "--json"])
    results = json.loads(capsys.readouterr().out)["results"]
    assert results[0]["host"] == "zzz-expired.com", "alphabetical order must not beat severity"
    assert results[-1]["host"] == "aaa-ok.com"


def test_text_output_is_not_coloured_when_piped(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check", fake_results({"a.com": Status.EXPIRED}))
    cli.main(["a.com"])
    out = capsys.readouterr().out
    assert "\033[" not in out, "ANSI codes must not reach a non-tty"


def test_no_color_env_is_respected(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")

    class FakeTTY:
        def isatty(self):
            return True

    assert cli._use_colour(FakeTTY()) is False


# ── webhook ─────────────────────────────────────────────────────────────────

def test_webhook_failure_does_not_change_the_exit_code(monkeypatch, capsys):
    """A dead chat service must not swallow certificate findings."""
    monkeypatch.setattr(cli, "check", fake_results({"a.com": Status.EXPIRED}))

    def boom(*a, **k):
        raise OSError("webhook host is down")

    monkeypatch.setattr(cli.urllib.request, "urlopen", boom)
    assert cli.main(["a.com", "--webhook", "http://127.0.0.1:9/hook"]) == cli.EXIT_FINDINGS


def test_webhook_is_not_called_when_everything_is_ok(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check", fake_results({}))
    called = []
    monkeypatch.setattr(cli.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))
    cli.main(["a.com", "--webhook", "http://example.com/hook"])
    assert not called, "no findings means nothing to notify about"
