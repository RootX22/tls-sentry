# Security Policy

## Reporting a vulnerability

Email **henrry.220267@gmail.com** with `SECURITY` in the subject line, or open a
[private security advisory](../../security/advisories/new).

Please don't open a public issue for anything exploitable.

Include what you have: the affected file, what an attacker gets out of it, and
a way to reproduce if you have one. A rough report beats a polished one that
never gets sent.

I'll acknowledge within 72 hours and tell you whether I think it's a real issue
and roughly when it'll be fixed.

## Supported versions

The latest release on `main`. This is a small project — there are no backported
security branches.

## Scope

Findings that count:

- A check that reports a **pass** for a genuinely insecure configuration. A
  false pass is worse than no check at all, because it tells you the box is
  fine when it isn't.
- Command injection through a hostname, path, or config value that ends up in a
  shell expansion.
- Anything that writes to, modifies, or otherwise disturbs a host being audited.
  The tooling is designed to be read-only where it says it is; a violation of
  that is a bug regardless of impact.

Findings that don't:

- False **failures** (a check that's too strict). Still worth an issue, just not
  a security one.
- The fact that the tool needs root to read `/etc/shadow`. That's inherent to
  what it does.
- Findings that require an attacker to already have the root access the tool
  itself needs.
