# shellcheck shell=bash
# Branching logic lifted out of action.yml so it can be tested without a runner.
# Sourced, not executed: `. "$GITHUB_ACTION_PATH/scripts/steps.sh"`.
#
# Only the parts that decide something live here. Running curl, tar, pipx and
# the scanners themselves stays inline — there is nothing to assert about it
# that self-test.yml does not already cover end to end.

# Prints the commitlint range arguments, one per line.
#
# Reads FROM and TO, which a pull_request event fills in. With no parent commit
# — a shallow checkout, or the very first commit — commitlint refuses a --from
# equal to --to and prints its whole usage text, which would land in the report
# as a bogus violation. --last is what it asks for in that case.
commit_range() {
  local from to
  # --verify or nothing: a bare `git rev-parse HEAD~1` echoes "HEAD~1" back
  # on stdout when it cannot resolve it, which would make `from` look valid.
  from="${FROM:-$(git rev-parse --verify HEAD~1 2>/dev/null || true)}"
  to="${TO:-HEAD}"
  if [ -n "$from" ]; then
    printf '%s\n' --from "$from" --to "$to"
  else
    printf '%s\n' --last
  fi
}

# Writes the changed line ranges to $1 as `path<TAB>start<TAB>end` rows and
# succeeds, or removes that file and fails when there is nothing to scope to.
#
# Lines, not files. Scoping by filename means one new dependency drags every
# pre-existing CVE in the manifest into the report, and one touched line in an
# old file drags that file's whole backlog with it. Line ranges are also the
# established convention — reviewdog's `added` filter mode, golangci-lint's
# --new-from-rev — rather than something invented here.
#
# Failing means the report covers everything. Scoping needs both ends of the
# range in the local clone, which is what fetch-depth: 0 buys, and outside a
# pull request or a push there is no range at all. Hiding findings because a
# command failed would be the worst possible default.
changed_lines() {
  local out="$1" diff
  if [ "${SCOPE:-}" != changed ] || [ -z "${BASE:-}" ]; then
    rm -f "$out"
    return 1
  fi
  # --unified=0 so the hunk headers cover exactly the added and modified lines
  # with no context bleeding in. quotePath=false keeps non-ASCII paths readable
  # instead of \nnn escapes, which would never match a SARIF uri.
  diff="$(git -c core.quotePath=false diff --unified=0 "${BASE}...${HEAD:-HEAD}" 2>/dev/null)" || {
    rm -f "$out"
    return 1
  }
  printf '%s\n' "$diff" | awk '
    # `+++ /dev/null` is a deletion and has no added lines to attribute.
    /^\+\+\+ / { file = (substr($0, 1, 6) == "+++ b/") ? substr($0, 7) : ""; next }
    /^@@ / && file != "" {
      # @@ -old,len +new,len @@ — only the + side names lines that now exist.
      match($0, /\+[0-9]+(,[0-9]+)?/)
      split(substr($0, RSTART + 1, RLENGTH - 1), r, ",")
      len = (2 in r) ? r[2] : 1
      if (len > 0) printf "%s\t%d\t%d\n", file, r[1], r[1] + len - 1
    }' > "$out"
  # An empty result means fail open, not scope to nothing. A deletion-only
  # change reporting everything is a small price; a parsing regression that
  # silently suppressed every finding and stayed green would not be.
  [ -s "$out" ] || { rm -f "$out"; return 1; }
}

# Copies the SARIF named in EXTRA into $1.
collect_extra_sarif() {
  local dest="$1" pattern f found n=0
  local -a patterns
  mkdir -p "$dest"
  # Newlines too, not just commas: a YAML block input is the natural way to
  # list several files, and `read -a` would silently stop at the first line.
  read -r -a patterns <<< "$(echo "${EXTRA:-}" | tr ',
' '  ')"
  for pattern in ${patterns[@]+"${patterns[@]}"}; do
    found=0
    # shellcheck disable=SC2086  # unquoted on purpose: the pattern is a glob
    for f in $pattern; do
      [ -f "$f" ] || continue
      # Numbered so two linters cannot overwrite each other, and forced to
      # .sarif because that is what the report reads.
      cp "$f" "$dest/$n-$(basename "$f" .sarif).sarif"
      n=$((n + 1))
      found=1
    done
    # A path matching nothing is a broken pipeline, not an empty result — the
    # same rule the built-in scanners are held to.
    if [ "$found" != 1 ]; then
      echo "::error::extra-sarif matched no file: '$pattern'"
      return 1
    fi
  done
}
