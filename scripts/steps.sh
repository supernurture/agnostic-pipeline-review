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

# Writes the pull request's changed files to $1 and succeeds, or removes that
# file and fails when there is nothing to scope to.
#
# Failing means the report covers everything. Scoping needs both ends of the
# range in the local clone, which is what fetch-depth: 0 buys, and outside a
# pull request there is no range at all. Hiding findings because a command
# failed would be the worst possible default here.
changed_files() {
  local out="$1"
  if [ "${SCOPE:-}" = changed ] && [ -n "${BASE:-}" ] \
    && git diff --name-only "${BASE}...${HEAD:-HEAD}" > "$out" 2>/dev/null; then
    return 0
  fi
  rm -f "$out"
  return 1
}

# Copies the SARIF named in EXTRA into $1.
collect_extra_sarif() {
  local dest="$1" pattern f found n=0
  local -a patterns
  mkdir -p "$dest"
  read -r -a patterns <<< "$(echo "${EXTRA:-}" | tr ',' ' ')"
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
