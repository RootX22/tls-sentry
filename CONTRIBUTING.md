# Contributing

Bug reports and PRs welcome. It's a small project, so there isn't much process.

## Before you open a PR

Run the linter and the tests — CI runs exactly these, so if they pass locally
they'll pass there:

```bash
shellcheck -x *.sh lib/*.sh checks/*.sh scripts/*.sh 2>/dev/null
```

Then run the tool itself against a real box, both as your user and under
`sudo`. Behaviour differs between the two on purpose, and that difference is
where most bugs hide.

## Style

Match what's already there:

- `set -euo pipefail`, quoted expansions, `local` in functions.
- Comments explain **why**, not what. If a line needs a comment saying what it
  does, the line is probably too clever.
- Portability matters. `mv -T` and `find -printf` are GNU-only and have already
  caused one bug each here — if you reach for something GNU-specific, add a
  fallback or a comment saying why it's safe.

## Commit messages

Short first line, lowercase, describing what changed. If the *why* isn't
obvious from the diff, put it in the body. No strict format.

## Gotchas worth knowing

**`set -e` and arithmetic.** `(( x++ ))` evaluates to the value *before* the
increment, so when `x` is 0 it returns exit status 1 and kills the script. Same
for a bare `[[ cond ]] && thing` as the last statement in a function. Both have
bitten this codebase. Use `x=$(( x + 1 ))` and a real `if`.

**Checks must never write.** `sentinel-audit` is read-only. If a check needs to
know whether something is writable, that still doesn't justify writing to the
audited host outside a temp path you clean up.

**Grading is meaningful.** `fail` = exploitable or leaks credentials. `warn` =
weakens defence in depth, or is legitimate in some setups. `skip` = not
applicable. Don't use `fail` for something that's merely untidy — an auditor
people learn to ignore is useless.
