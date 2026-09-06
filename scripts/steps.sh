# shellcheck shell=bash
# Branching logic lifted out of action.yml so it can be tested without a runner.
# Sourced, not executed: `. "$GITHUB_ACTION_PATH/scripts/steps.sh"`. Only the
# parts that decide something live here; self-test.yml covers the rest.

# Prints the commitlint range arguments, one per line.
#
# Reads FROM and TO, which a pull_request event fills in. With no parent commit
# commitlint refuses a --from equal to --to and prints its usage text, which
# would land in the report as a bogus violation. --last is the way out.
commit_range() {
  local from to
  # --verify: without it rev-parse echoes "HEAD~1" back and `from` looks valid.
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
# Lines, not files: by filename one new dependency drags every pre-existing CVE
# in the manifest along. Line ranges are the established convention too —
# reviewdog's `added` mode, golangci-lint's --new-from-rev.
#
# Failing means the report covers everything. Scoping needs both ends of the
# range locally (fetch-depth: 0), and outside a PR or push there is no range —
# hiding findings because a command failed would be the worst default.
changed_lines() {
  local out="$1" diff
  if [ "${SCOPE:-}" != changed ] || [ -z "${BASE:-}" ]; then
    rm -f "$out"
    return 1
  fi
  # --unified=0 keeps context lines out of the hunk headers. quotePath=false
  # keeps non-ASCII paths readable; \nnn escapes never match a SARIF uri.
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
  # Empty means fail open, not scope to nothing: a deletion-only change
  # reporting everything beats a regression that goes silently green.
  [ -s "$out" ] || { rm -f "$out"; return 1; }
}

# Copies the SARIF named in EXTRA into $1.
collect_extra_sarif() {
  local dest="$1" pattern f found n=0
  local -a patterns
  mkdir -p "$dest"
  # Newlines too: a YAML block is the natural way to list several files, and
  # `read -a` would stop at the first line.
  read -r -a patterns <<< "$(echo "${EXTRA:-}" | tr ',
' '  ')"
  for pattern in ${patterns[@]+"${patterns[@]}"}; do
    found=0
    # shellcheck disable=SC2086  # unquoted on purpose: the pattern is a glob
    for f in $pattern; do
      [ -f "$f" ] || continue
      # Numbered so two linters cannot overwrite each other.
      cp "$f" "$dest/$n-$(basename "$f" .sarif).sarif"
      n=$((n + 1))
      found=1
    done
    # A path matching nothing is a broken pipeline, not an empty result.
    if [ "$found" != 1 ]; then
      echo "::error::extra-sarif matched no file: '$pattern'"
      return 1
    fi
  done
}
