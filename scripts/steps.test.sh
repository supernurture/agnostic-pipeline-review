#!/usr/bin/env bash
# Self-check for steps.sh. Run with: bash scripts/steps.test.sh
#
# No subshells around a check: `fails` has to be incremented in this shell, or
# a failing assertion would print and still exit 0.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=scripts/steps.sh
. ./steps.sh

fails=0
check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then return 0; fi
  echo "FAIL $1"
  echo "  expected: $2"
  echo "  actual:   $3"
  fails=$((fails + 1))
}
exists() { [ -f "$1" ] && echo yes || echo no; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t

# A repo with two commits, to diff and to walk back from.
repo="$work/repo"
git init -q -b main "$repo"
cd "$repo" || exit 1
echo a > a.txt && git add a.txt && git commit -qm "feat: a"
base="$(git rev-parse HEAD)"
echo b > b.txt && git add b.txt && git commit -qm "feat: b"

# --- commit_range ---
out="$(FROM=aaa TO=bbb commit_range | tr '\n' ' ')"
check "explicit range from the event" "--from aaa --to bbb " "$out"

out="$(unset FROM TO; commit_range | tr '\n' ' ')"
check "derived range walks back one commit" "--from $base --to HEAD " "$out"

# A HEAD with no parent must ask for --last. Not a --from equal to --to:
# commitlint rejects that and dumps its usage text into the report. And not a
# literal "HEAD~1" either — a bare `git rev-parse` echoes an unresolved ref
# straight back on stdout, which is what made this branch unreachable before.
single="$work/single"
git init -q -b main "$single"
cd "$single" || exit 1
echo a > a.txt && git add a.txt && git commit -qm "feat: only"
out="$(unset FROM TO; commit_range | tr '\n' ' ')"
check "no parent commit" "--last " "$out"

# --- changed_files ---
cd "$repo" || exit 1
out_file="$work/changed.txt"

SCOPE=changed BASE="$base" HEAD=HEAD changed_lines "$out_file"
check "a real range succeeds" "0" "$?"
# b.txt is one new line, so the range is 1-1 — path, start, end, tab separated.
check "and reports the added range" "b.txt	1	1" "$(cat "$out_file" 2>/dev/null)"

# The point of the whole exercise: editing one line of a long file must not
# claim the rest of it. Ten lines, then a single edit in the middle.
printf 'l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\n' > manifest.txt
git add manifest.txt && git commit -qm "feat: manifest"
mid="$(git rev-parse HEAD)"
printf 'l1\nl2\nl3\nl4\nEDITED\nl6\nl7\nl8\nl9\nl10\n' > manifest.txt
git add manifest.txt && git commit -qm "fix: one line"

SCOPE=changed BASE="$mid" HEAD=HEAD changed_lines "$out_file"
check "one edited line in ten" "manifest.txt	5	5" "$(cat "$out_file" 2>/dev/null)"

# Several hunks in one file each get their own row
printf 'X\nl2\nl3\nl4\nEDITED\nl6\nl7\nl8\nl9\nY\n' > manifest.txt
git add manifest.txt && git commit -qm "fix: two more lines"
SCOPE=changed BASE="$mid" HEAD=HEAD changed_lines "$out_file"
check "multiple hunks" "manifest.txt	1	1 manifest.txt	5	5 manifest.txt	10	10" "$(tr '\n' ' ' < "$out_file" | sed 's/ $//')"

SCOPE=all BASE="$base" changed_lines "$out_file"
check "scope: all does not scope" "1" "$?"
check "and leaves no stale list" "no" "$(exists "$out_file")"

SCOPE=changed BASE='' changed_lines "$out_file"
check "no base sha means no scoping" "1" "$?"

SCOPE=changed BASE=deadbeef changed_lines "$out_file"
check "an unreachable base fails open" "1" "$?"
check "without leaving a partial list" "no" "$(exists "$out_file")"

# A range against itself has no added lines. That must fail open rather than
# scope to nothing — a parsing regression looks exactly the same from here, and
# silently suppressing every finding while staying green is the one outcome
# this pipeline must never produce.
SCOPE=changed BASE=HEAD HEAD=HEAD changed_lines "$out_file"
check "an empty diff fails open" "1" "$?"
check "leaving no empty list behind" "no" "$(exists "$out_file")"

# --- collect_extra_sarif ---
src="$work/src"
mkdir -p "$src/one" "$src/two"
echo '{}' > "$src/one/lint.sarif"
echo '{}' > "$src/two/lint.sarif"
dest="$work/style"
cd "$src" || exit 1

EXTRA="one/lint.sarif, two/lint.sarif" collect_extra_sarif "$dest"
check "two files sharing a basename" "0" "$?"
check "are numbered apart" "0-lint.sarif 1-lint.sarif" "$(cd "$dest" && echo *)"

rm -rf "$dest"
# A YAML block input arrives with newlines, not commas.
EXTRA="one/lint.sarif
two/lint.sarif" collect_extra_sarif "$dest"
check "a multi-line input" "0" "$?"
check "keeps every line" "0-lint.sarif 1-lint.sarif" "$(cd "$dest" && echo *)"

rm -rf "$dest"
EXTRA="one/*.sarif" collect_extra_sarif "$dest"
check "a glob is expanded" "0-lint.sarif" "$(cd "$dest" && echo *)"

rm -rf "$dest"
err="$(EXTRA="nope-*.sarif" collect_extra_sarif "$dest" 2>&1)"
check "a pattern matching nothing fails" "1" "$?"
case "$err" in
  *"::error::extra-sarif matched no file: 'nope-*.sarif'"*) ;;
  *) echo "FAIL the failure must name the pattern"; echo "  actual: $err"; fails=$((fails + 1)) ;;
esac

cd /
if [ "$fails" -eq 0 ]; then
  echo "steps.sh: all checks passed"
else
  echo "steps.sh: $fails check(s) failed"
  exit 1
fi
