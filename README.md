# Agnostic Review Pipeline

A review pipeline any project can plug in: **code review**, **vulnerability
review**, and **commit message review** — plug in what you need, unplug what you
don't. The result is a single report ranked by severity: **Critical / High /
Medium / Low / Info**.

Multi-language (it inherits Semgrep and Trivy's coverage) and free end to end.

## Use

```yaml
# .github/workflows/review.yml
name: Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # needed for the PR diff and for commitlint

      - uses: supernurture/agnostic-pipeline-review@v1
        with:
          reviews: code,vulnerability     # <- plug in / unplug here
          fail-on: high                   # default
```

Project A writes `code,vulnerability`. Project B writes `commit-message`. No
other file has to change.

Needs a **Linux runner** (`ubuntu-latest`): the action uses `pipx`, `tar` and
`sha256sum`, and downloads the Linux build of Gitleaks.

### Limiting it to certain branches

GitHub has no "protected branches" filter — `branches:` only takes name
patterns. For `pull_request` it matches the branch being merged *into*:

```yaml
on:
  pull_request:
    branches: [main, "release/**"]
```

Often the thing you actually want is the opposite: let the review run on every
PR, and let **Require status checks to pass** in the branch protection rule
decide where it may block a merge. Running it everywhere is cheap and surfaces
findings earlier; only the protected branch enforces them.

## Available reviews

| Name | Engine | Coverage |
|---|---|---|
| `code` | [Semgrep OSS](https://semgrep.dev) | Bugs & risky patterns, 30+ languages |
| `vulnerability` | [Trivy](https://github.com/aquasecurity/trivy) + [Gitleaks](https://github.com/gitleaks/gitleaks) | Dependency CVEs, IaC misconfig, leaked secrets |
| `commit-message` | [commitlint](https://commitlint.js.org) | Conventional Commits |

Gitleaks scans the **working tree**, not the commit history. A secret that was
added and then deleted inside the same PR is not caught, even though merging
keeps it in the history forever. Catching that means `gitleaks git` and
`fetch-depth: 0` on every run; this pipeline takes the fast side of that trade
on purpose.

commitlint's **exit status** is what decides, not its output. Rules you set to
warning level are printed in the report and do not block the merge.

### Coding standard

Not a built-in review. Point `extra-sarif` at SARIF your own linter produced and
it is merged into the same report:

```yaml
      - run: ruff check --output-format sarif > ruff.sarif || true

      - uses: supernurture/agnostic-pipeline-review@v1
        with:
          reviews: code,vulnerability
          extra-sarif: ruff.sarif
```

Anything that writes SARIF works — Ruff natively, ESLint through
`@microsoft/eslint-formatter-sarif`, PMD with `-f sarif`, Clippy through
`clippy-sarif`. Comma- or space-separated, globs allowed. A path matching
nothing fails the run, the same rule the built-in scanners are held to.

These land in **their own section, off the CVSS scale**, for the same reason
commit messages do: style is not a security finding, and inventing a severity
for it would corrupt the gate. They also **do not fail the build** — if you want
a linter to block a merge, let its own step fail; that mechanism already exists.
A broken or empty SARIF still fails, though: `ruff check … > ruff.sarif` leaves
an empty file when ruff itself crashes, and a linter that silently did not run
must not pass for clean.
`scope` still applies, so they are limited to the changed files like the rest.

Deliberately not built in: hardcoding Ruff, ESLint and golangci-lint would give
a language-agnostic action a language matrix to maintain forever, and SARIF
support across those tools is uneven. A project that has a language already
knows its linter.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `reviews` | — | Required. Comma-separated. An unknown name fails the run. |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info`, or `none` |
| `semgrep-config` | `p/ci` | Semgrep ruleset, see [semgrep.dev/r](https://semgrep.dev/r) |
| `semgrep-version` | `1.173.0` | Engine version. The rules stay fresh — `p/ci` is pulled from the registry at run time |
| `gitleaks-version` | `8.30.1` | Version of the binary that gets downloaded (checksum verified) |
| `trivy-version` | `latest` | Trivy engine — see [Versions](#versions) |
| `commitlint-version` | `latest` | commitlint and `config-conventional`, pinned together |
| `scope` | `changed` | `changed` gates only on files in the PR diff, `all` on the whole tree — see [Scope](#scope) |
| `extra-sarif` | — | SARIF from your own linters — see [Coding standard](#coding-standard) |
| `pr-comment` | `false` | Post the report as one self-updating PR comment. Needs `pull-requests: write` |

The `report-dir` output holds `review-report.md` and each scanner's raw SARIF —
see [Export & share](#export--share).

### Scope

By default the gate looks only at findings in files the pull request actually
touches. Everything else is still counted and announced — never dropped in
silence:

```
> Not listed: 183 finding(s) in files this change does not touch.
```

This is what makes the pipeline usable on a repository that did not start with
it. Without scoping, a codebase with two years of history turns every pull
request red on day one, and by day three nobody reads the report at all. The
diff is the baseline, so there is no baseline file to maintain and nothing to
keep in sync.

It needs both ends of the pull request range in the local clone — that is what
`fetch-depth: 0` buys. Outside a pull request there is no range, and if the diff
cannot be produced for any reason the report covers everything: hiding findings
because a command failed would be the worst possible default here.

Use `scope: all` when you want the whole tree gated, for example on a nightly
run.

### Versions

Engines are pinned, their data is not, and that split is deliberate: a stale
ruleset or CVE database is more dangerous than a stale binary.

- `semgrep-version` and `gitleaks-version` pin a binary. The Semgrep rules
  (`p/ci`) are still pulled from the registry on every run.
- `trivy-version` and `commitlint-version` default to `latest`, because for
  those two the version *is* the freshness — the CVE database, and the rules
  commitlint applies by default. Pin them to reproduce an old run or to roll
  back a bad upstream release.

So the same commit can produce different findings a week later. That is the
point rather than a bug, but it does mean a green PR can turn red without
anyone touching it.

If a scanner that normally reports a CVSS score stops doing so, every band it
produces quietly falls back to the table in
[`scripts/report.mjs`](scripts/report.mjs). The report calls that out as a note
instead of letting the gate shift in silence — it does not fail the build, since
the findings are still real.

## Severity

No home-grown scale. The format is **SARIF 2.1.0**, and the bands come from
`properties.security-severity` — a CVSS score — using GitHub code scanning's
standard split:

| Band | CVSS score |
|---|---|
| Critical | ≥ 9.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |
| Info | no score / non-security finding |

Scanners that assign no score are mapped through the fallback table in
[`scripts/report.mjs`](scripts/report.mjs): a Gitleaks finding counts as
**Critical** (a leaked live credential is critical), Semgrep uses its own SARIF
level.

### One thing to know about `code` + `fail-on: high`

Most Semgrep security rules ship with severity `WARNING`, which becomes `warning`
in SARIF and **Medium** here. The consequence: with `fail-on: high` (the
default), **`reviews: code` on its own often blocks nothing** — it reports
without gating.

You can see it in this repo's own CI: with `reviews: code` and `fail-on: high`
the pipeline **passes** even though `examples/fixtures/` contains SQL injection,
`shell=True`, and `eval()` — not one of them is rated High.

Pick whichever you prefer:

- **Leave it at `high`** if code review is meant as input, and only serious
  security findings (secrets, CVEs) may block a merge.
- **Use `fail-on: medium`** if you want Semgrep findings to gate as well.

The default is deliberately left at `high` because the bands follow Semgrep's
own severity judgement — raising them would mean inventing severity, which
breaks the "follow the existing standard" principle this repo is built on.

## Report

Written to the GitHub **Job Summary**, so it is readable straight from the
workflow run page — no extra token, and it still works on private repos.

With `pr-comment: true` the same report is also posted as a **single pull
request comment that rewrites itself** on every run, so nobody has to open the
run page to see it. That one needs `pull-requests: write` in the workflow's
`permissions`. A fork's token never has it, and a missing permission is reported
as a warning — posting a comment must not decide whether a review passes.

```markdown
## Review Report

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 5 |
| Medium | 11 |
| Low | 3 |
| Info | 8 |
| **Total** | **29** |

Gate: fails at **High** and above.

### Critical (2)
- `src/db.py:42` — gitleaks/aws-access-token
  AWS access token found
- `requirements.txt:3` — Trivy/CVE-2020-14343
  PyYAML 5.1: arbitrary code execution
```

Commit message findings get their own section — commit style is not a security
finding, so it is not forced onto the CVSS scale.

### Export & share

Three ways, each with different access constraints:

**1. Send the run URL.** The Job Summary is shown on the workflow run page:
`https://github.com/<owner>/<repo>/actions/runs/<id>`. On a public repo anyone
can open it without logging in. Fastest thing to send to your team.

**2. Download it as an artifact.** Add one step on the consumer side — the
`report-dir` output already gives you the directory:

```yaml
      - uses: supernurture/agnostic-pipeline-review@v1
        id: review
        with:
          reviews: code,vulnerability

      - uses: actions/upload-artifact@v4
        if: always()          # without this the artifact is lost exactly when the review fails
        with:
          name: review-report
          path: ${{ steps.review.outputs.report-dir }}
```

What's inside:

| File | What for |
|---|---|
| `review-report.md` | Byte-for-byte the same report as the Job Summary — paste it into chat or a ticket |
| `*.sarif` | Each scanner's raw data, a standard format other tools can read |
| `commit.txt` | commitlint output, empty when every message passes |
| `commit.failed` | Present only when commitlint exited non-zero — this is what the gate reads |
| `changed.txt` | The PR's changed files, when `scope: changed` had a diff to work from |
| `style/` | The `extra-sarif` files you passed in |

Note: **downloading an artifact always requires a GitHub login**, public repos
included. So for recipients outside the team, option 1 or 3 is more practical.

**3. Copy the text.** `review-report.md` is plain Markdown holding `file:line`,
rule ids, and messages — a shape people can act on directly, and one you can
paste into an AI to ask for fixes. If the AI needs more context (code snippet,
CWE, suggested fix), send the `.sarif` instead: SARIF 2.1.0 is a standard format
many tools already understand.

## When the build fails

- A finding at or above `fail-on`
- A commit message violation — an error, not a warning-level rule
- **An enabled scanner produced no report**, or its SARIF is broken

That last point deliberately keeps failing the build even under `fail-on: none`:
a scanner that died does not mean "no findings", and a failure like that must
not slip through as green.

## Local lane (optional)

[`presets/pre-commit.yaml`](presets/pre-commit.yaml) runs the same scanners on a
developer machine as a fast pass/fail gate. Copy it to
`.pre-commit-config.yaml`, then:

```sh
pre-commit install --install-hooks -t pre-commit -t commit-msg
```

It does not produce the severity-ranked report — pre-commit only returns an exit
code. CI stays the source of truth.

## Adding a new kind of review

If the tool already writes SARIF and you can run it yourself, use
[`extra-sarif`](#coding-standard) instead — nothing here needs to change.

To make it a first-class review with its own severity bands, two places, and
only two:

1. Add a step in [`action.yml`](action.yml) that writes SARIF into `$REPORT_DIR`,
   plus its filename in `expect` in the validation step.
2. If the tool does not fill in `security-severity`, add one entry to
   `TOOL_FALLBACK` in [`scripts/report.mjs`](scripts/report.mjs).

A tool that already emits SARIF with `security-severity` needs no `report.mjs`
change at all.

## Development

```sh
node scripts/report.test.mjs
```

Needs Node ≥ 18.3 (`util.parseArgs`). GitHub runners already satisfy that with
no setup step.

`.github/workflows/self-test.yml` runs that self-check, then uses
`examples/fixtures/` to prove each scanner really finds something — and that the
findings disappear when its review is unplugged.

## License

[MIT](LICENSE). The scanners it calls carry their own licenses: Semgrep OSS
(LGPL-2.1), Trivy (Apache-2.0), Gitleaks (MIT), commitlint (MIT) — all of them
run as separate processes, not linked into this code.
