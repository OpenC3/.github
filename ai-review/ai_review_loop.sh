#!/usr/bin/env bash
# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.

# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

# Alternates Claude and Codex as reviewers on the checked-out PR branch. Each
# reviewer may edit files; the harness commits each turn's edits separately.
# The loop converges when a reviewer makes no changes after both reviewers have
# had at least one turn, or stops after MAX_TURNS.
#
# Required env: BASE_REF, CLAUDE_KEY_FILE, CODEX_KEY_FILE (files holding the API keys; deleted on start)
# Optional env: MAX_TURNS, CLAUDE_MODEL, CODEX_MODEL, CLAUDE_MAX_BUDGET_USD, CODEX_SANDBOX,
#               CI_FAILURES_FILE (failed CI job logs from ai_review_gate.sh), CI_FAILURE_COUNT,
#               REVIEW_INSTRUCTIONS (repository-specific guidance for the prompt), GITHUB_RUN_ID
#
# Writes $OUT_DIR/comment.md and sets the `status` and `commits` step outputs.

set -euo pipefail

: "${BASE_REF:?BASE_REF is required}"
: "${CLAUDE_KEY_FILE:?CLAUDE_KEY_FILE is required}"
: "${CODEX_KEY_FILE:?CODEX_KEY_FILE is required}"

# Keys are read from files deleted before any agent starts and are never exported: an exported
# variable stays readable in this process's /proc/<pid>/environ for the whole run, so Codex could
# read Claude's key (and the reverse) through its parent process.
CLAUDE_API_KEY="$(< "$CLAUDE_KEY_FILE")"
CODEX_API_KEY="$(< "$CODEX_KEY_FILE")"
rm -f "$CLAUDE_KEY_FILE" "$CODEX_KEY_FILE"
export -n CLAUDE_API_KEY CODEX_API_KEY
[[ -n "$CLAUDE_API_KEY" && -n "$CODEX_API_KEY" ]] || { echo "::error::An API key file is empty"; exit 1; }

# Agents can write inside the checkout, and the harness runs git outside their sandbox with the
# keys in memory. Never run hooks or an fsmonitor from .git, whoever wrote them, and ignore the
# global and system config so a file planted outside the checkout cannot add filters or drivers.
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null
export GIT_CONFIG_KEY_1=core.fsmonitor GIT_CONFIG_VALUE_1=false
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
# Pin the repository too: a .git/commondir file (read in any repository, not only worktrees) would
# otherwise point git at a config outside .git that the snapshot below never sees
REPO_TOP="$(git rev-parse --show-toplevel)"
export GIT_DIR="$REPO_TOP/.git" GIT_COMMON_DIR="$REPO_TOP/.git" GIT_WORK_TREE="$REPO_TOP"

# The runner reads these files after the step to set outputs, env and PATH for later steps, such as
# the push that holds the push token. Hide their paths from the agents; outputs are written below.
OUTPUT_FILE="${GITHUB_OUTPUT:-/dev/null}"
export -n GITHUB_OUTPUT GITHUB_ENV GITHUB_PATH GITHUB_STATE GITHUB_STEP_SUMMARY 2> /dev/null || true

MAX_TURNS="${MAX_TURNS:-6}"
CLAUDE_MODEL="${CLAUDE_MODEL:-claude-opus-5-5}"
CLAUDE_MAX_BUDGET_USD="${CLAUDE_MAX_BUDGET_USD:-5}"
CODEX_SANDBOX="${CODEX_SANDBOX:-workspace-write}"
OUT_DIR="${OUT_DIR:-${RUNNER_TEMP:-/tmp}/ai-review}"

# Run from the PR checkout; the prompt and schema live next to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_TEMPLATE="$SCRIPT_DIR/prompt.md"
SCHEMA="$SCRIPT_DIR/schema.json"
HISTORY="$OUT_DIR/history.md"
CI_FAILURES_FILE="${CI_FAILURES_FILE:-}"
RUN_ID="${GITHUB_RUN_ID:-local}"

mkdir -p "$OUT_DIR"
: > "$HISTORY"

MERGE_BASE="$(git merge-base "origin/$BASE_REF" HEAD)"
START_SHA="$(git rev-parse HEAD)"

# Each turn gets an empty HOME outside the checkout and OUT_DIR, so nothing an agent writes there
# (user settings, hooks, Codex config) is loaded by the next agent
AGENT_HOME="$(mktemp -d "${RUNNER_TEMP:-/tmp}/ai-review-home.XXXXXX")"
CODEX_AUTH="$AGENT_HOME/.codex/auth.json"
trap 'rm -rf "$AGENT_HOME"' EXIT
fresh_agent_home() {
  rm -rf "$AGENT_HOME"
  mkdir -p "$AGENT_HOME/.codex"
}

# Files that steer the agents or this review, in the reviewed repository or in OpenC3/.github
# itself; keep in sync with PROTECTED_PATHS in malicious_code_scan.py (tests/test_ai_review.py
# checks). A turn that changes one is discarded: the next agent would load it.
AGENT_CONFIG_RE='(^|/)(CLAUDE\.md|AGENTS\.md|\.mcp\.json)$|(^|/)\.(claude|codex|cursor)/'
AGENT_CONFIG_RE+='|^\.github/copilot-instructions\.md$|^(ai-review|malicious-code-scan)/'
AGENT_CONFIG_RE+='|^\.github/workflows/(ai[-_]review|malicious[-_]code[-_]scan)(-reusable)?\.ya?ml$'
# Workflows and actions run with secrets on the next CI run, and pushing them needs a token with
# the workflows scope; agents report needed changes instead
CI_CONFIG_RE='^\.github/(workflows|actions)/'

# Git config, hooks and alternates the agents could plant to run code the next time the harness
# calls git. They are copied at the start and compared after every turn.
GIT_CONTROL_PATHS=(config info hooks objects/info commondir)
snapshot_git() {
  local dest="$1" path
  rm -rf "$dest"
  mkdir -p "$dest"
  for path in "${GIT_CONTROL_PATHS[@]}"; do
    if [[ -e ".git/$path" || -L ".git/$path" ]]; then
      mkdir -p "$dest/$(dirname "$path")"
      cp -RP ".git/$path" "$dest/$path"
    fi
  done
}
GIT_SNAPSHOT="$OUT_DIR/git-snapshot"
snapshot_git "$GIT_SNAPSHOT"
git_unchanged() {
  snapshot_git "$OUT_DIR/git-current"
  diff -r --no-dereference "$GIT_SNAPSHOT" "$OUT_DIR/git-current" > /dev/null 2>&1
}

# Succeeds if stdin contains an API key. Agents can read files on the runner, so anything they
# write is checked before it is committed or posted. This only catches exact copies; an encoded
# key gets through, so the malicious code scan that gates this review remains the real defense.
# No grep -q: exiting early would SIGPIPE the writer, and pipefail would read that as no match.
leaks_secret() {
  local patterns
  patterns="$(printf '%s\n' "$CLAUDE_API_KEY" "$CODEX_API_KEY" | grep -v '^$' || true)"
  [[ -n "$patterns" ]] && grep -F -f <(echo "$patterns") > /dev/null
}

build_prompt() {
  local reviewer="$1" other="$2" turn="$3" file="$4"
  {
    cat "$PROMPT_TEMPLATE"
    echo
    echo "## Context"
    echo
    echo "- You are: $reviewer (turn $turn of at most $MAX_TURNS). The other reviewer is $other."
    echo "- Base branch: $BASE_REF"
    echo "- Merge base: $MERGE_BASE (review with \`git diff $MERGE_BASE...HEAD\`)"
    echo
    if [[ -n "${REVIEW_INSTRUCTIONS:-}" ]]; then
      # From the caller workflow on the default branch, so trusted like this template
      echo "## Repository guidance"
      echo
      echo "$REVIEW_INSTRUCTIONS"
      echo
    fi
    echo "## CI results for the commit under review"
    echo
    if [[ -n "$CI_FAILURES_FILE" && -s "$CI_FAILURES_FILE" ]]; then
      echo "CI failed. Fixing these failures is your first priority (unless a previous turn already did)."
      echo "Each section contains a failed job's log or a workflow failure without job logs:"
      echo
      cat "$CI_FAILURES_FILE"
    else
      echo "All CI checks passed."
    fi
    echo
    echo "## Previous turns"
    echo
    if [[ -s "$HISTORY" ]]; then
      cat "$HISTORY"
    else
      echo "None. You are the first reviewer."
    fi
  } > "$file"
}

validate_result() {
  # Require exactly one result matching the review schema, including on CLI failures
  # that leave an empty, partial, or otherwise valid-looking JSON file behind.
  jq -e -s --slurpfile schema "$SCHEMA" '
    length == 1 and (.[0] |
      type == "object" and
      keys == ($schema[0].required | sort) and
      (.verdict as $verdict | $schema[0].properties.verdict.enum | index($verdict) != null) and
      (.summary | type == "string") and
      (.issues_fixed | type == "array" and all(.[]; type == "string")) and
      (.unresolved_concerns | type == "array" and all(.[]; type == "string")))
  ' "$1" > /dev/null
}

run_claude() {
  local prompt_file="$1" result_file="$2" raw="$OUT_DIR/claude-raw-$3.json"
  # Project settings and MCP servers could come from the PR or an earlier agent turn and would run
  # hooks outside any sandbox, so only the runner's own settings are loaded
  HOME="$AGENT_HOME" ANTHROPIC_API_KEY="$CLAUDE_API_KEY" \
    claude -p \
      --model "$CLAUDE_MODEL" \
      --setting-sources user \
      --strict-mcp-config \
      --output-format json \
      --json-schema "$(cat "$SCHEMA")" \
      --max-budget-usd "$CLAUDE_MAX_BUDGET_USD" \
      --permission-mode acceptEdits \
      --allowedTools "Read(./**)" "Edit(./**)" "Write(./**)" "Glob" "Grep" \
        "Bash(git diff:*)" "Bash(git log:*)" "Bash(git show:*)" "Bash(git status:*)" "Bash(git blame:*)" \
      --disallowedTools "Read(~/.codex/**)" "Read(//proc/**)" "Bash(git diff --no-index:*)" \
        "Bash(git *--output*)" \
      < "$prompt_file" > "$raw" || return $?
  if jq -e '.is_error == true' "$raw" > /dev/null; then
    jq -r '.result // "unknown error"' "$raw" >&2
    return 1
  fi
  jq -e '.structured_output' "$raw" > "$result_file" || return $?
  validate_result "$result_file"
}

run_codex() {
  local prompt_file="$1" result_file="$2"
  local model_args=()
  [[ -n "${CODEX_MODEL:-}" ]] && model_args=(--model "$CODEX_MODEL")
  # Codex reads the key from auth.json, which exists only for its own turn so Claude cannot read it
  export HOME="$AGENT_HOME" CODEX_HOME="$AGENT_HOME/.codex"
  printf '%s' "$CODEX_API_KEY" | codex login --with-api-key > /dev/null
  codex exec \
    ${model_args[@]+"${model_args[@]}"} \
    --sandbox "$CODEX_SANDBOX" \
    -c 'approval_policy="never"' \
    --ephemeral \
    --output-schema "$SCHEMA" \
    --output-last-message "$result_file" \
    - < "$prompt_file" && rc=0 || rc=$?
  codex logout > /dev/null 2>&1 || true
  rm -f "$CODEX_AUTH"
  (( rc == 0 )) || return "$rc"
  validate_result "$result_file"
}

record_turn() {
  local turn="$1" reviewer="$2" result_file="$3" commit="$4"
  {
    echo "### Turn $turn: $reviewer ($( [[ -n "$commit" ]] && echo "commit $commit" || echo "no changes" ))"
    echo
    jq -r '.summary' "$result_file"
    jq -r '.issues_fixed[]? | "- Fixed: \(.)"' "$result_file"
    jq -r '.unresolved_concerns[]? | "- Concern: \(.)"' "$result_file"
    echo
  } >> "$HISTORY"
}

reviewers=(Claude Codex)
reviewed_claude=0
reviewed_codex=0
status="max_turns"
tampered=0
turn=0

while (( turn < MAX_TURNS )); do
  reviewer="${reviewers[turn % 2]}"
  other="${reviewers[(turn + 1) % 2]}"
  turn=$((turn + 1))
  prompt_file="$OUT_DIR/prompt-$turn.md"
  result_file="$OUT_DIR/result-$turn.json"
  build_prompt "$reviewer" "$other" "$turn" "$prompt_file"
  fresh_agent_home

  echo "::group::Turn $turn: $reviewer"
  before_sha="$(git rev-parse HEAD)"
  if [[ "$reviewer" == "Claude" ]]; then
    run_claude "$prompt_file" "$result_file" "$turn" && rc=0 || rc=$?
  else
    # Subshell so the agent HOME does not leak into the harness
    (run_codex "$prompt_file" "$result_file") && rc=0 || rc=$?
  fi
  echo "::endgroup::"

  # Checked before git runs again: planted config could run code when it does. Stop without
  # committing, cleaning up, or pushing anything, since any of those would run git.
  if ! git_unchanged; then
    echo "::error::$reviewer changed git's config or hooks on turn $turn; stopping without committing or pushing"
    echo "### Turn $turn: $reviewer changed git's config or hooks; the run was stopped and nothing was pushed" >> "$HISTORY"
    rm -f "$result_file"
    status="error"
    tampered=1
    break
  fi

  discard=""
  if (( rc == 0 )); then
    git add -A
    # An agent that wrote a key into the tree or its result must not get it committed or posted
    # --text: a NUL byte or a -diff attribute would otherwise print "Binary files differ" instead of the key
    if { git diff --cached --text --no-ext-diff --no-textconv "$before_sha" && cat "$result_file"; } | leaks_secret; then
      discard="it contained an API key"
    else
      changed="$(git diff --cached --name-only --no-renames "$before_sha")"
      if grep -Eq "$AGENT_CONFIG_RE" <<< "$changed"; then
        discard="it changed files that configure the AI agents or this review"
      elif grep -Eq "$CI_CONFIG_RE" <<< "$changed"; then
        discard="it changed CI workflows or actions"
      fi
    fi
  fi
  git reset -q

  if (( rc != 0 )) || [[ -n "$discard" ]]; then
    if [[ -n "$discard" ]]; then
      echo "::error::Discarding $reviewer's turn $turn because $discard"
      echo "### Turn $turn: $reviewer's turn was discarded because $discard" >> "$HISTORY"
    else
      echo "::error::$reviewer failed on turn $turn (exit $rc)"
      echo "### Turn $turn: $reviewer failed (exit $rc)" >> "$HISTORY"
    fi
    rm -f "$result_file"
    # Keep whatever the agent left half-done out of the branch
    git reset --hard "$before_sha" > /dev/null
    git clean -fdq
    status="error"
    break
  fi

  # An agent is told not to commit, but fold any commits it made anyway into this turn
  git reset --soft "$before_sha"
  git add -A
  commit=""
  if ! git diff --cached --quiet; then
    git commit -q -F - <<EOF
fix(review): apply $reviewer review fixes (turn $turn)

$(jq -r '.issues_fixed[]? | "- \(.)"' "$result_file")

AI-Review-Bot: true
AI-Review-Run: $RUN_ID
EOF
    commit="$(git rev-parse --short HEAD)"
  fi

  if [[ "$reviewer" == "Claude" ]]; then reviewed_claude=1; else reviewed_codex=1; fi
  record_turn "$turn" "$reviewer" "$result_file" "$commit"
  cat "$result_file"

  if [[ -z "$commit" && $reviewed_claude == 1 && $reviewed_codex == 1 ]]; then
    status="converged"
    break
  fi
done

# After tampering, report no commits so nothing is pushed, and do not run git again
commits=0
(( tampered )) || commits="$(git rev-list --count "$START_SHA..HEAD")"

{
  echo "<!-- ai-adversarial-review -->"
  # The marker stops later runs from reviewing this commit again, so leave it off when a reviewer
  # failed (an API outage, say) and a rerun could succeed. Tampering is not retried.
  if [[ "$status" != "error" ]] || (( tampered )); then
    echo "<!-- ai-review-sha: $START_SHA -->"
  fi
  echo "## AI adversarial review"
  echo
  if [[ -n "$CI_FAILURES_FILE" && -s "$CI_FAILURES_FILE" ]]; then
    echo "CI had ${CI_FAILURE_COUNT:-some} failure(s) on the reviewed commit; the reviewers were asked to fix them."
    echo
  fi
  case "$status" in
    converged) echo "✅ Claude and Codex converged after $turn turn(s) with $commits fix commit(s)." ;;
    max_turns) echo "⚠️ Stopped after the maximum of $MAX_TURNS turns without converging ($commits fix commit(s)). A human should look at the last few turns." ;;
    error)
      if (( tampered )); then
        echo "❌ A reviewer changed git's config or hooks on turn $turn. The run was stopped and no fixes were pushed."
      else
        echo "❌ A reviewer failed on turn $turn. Fixes from earlier turns ($commits commit(s)) were kept."
      fi
      ;;
  esac
  echo
  echo "Reviewed commit: \`$START_SHA\`"
  echo
  # Concerns from each reviewer's most recent successful turn need a human decision
  concerns="$(for ((t = turn; t >= 1 && t > turn - 2; t--)); do
    jq -r '.unresolved_concerns[]? | "- \(.)"' "$OUT_DIR/result-$t.json" 2> /dev/null || true
  done | sort -u)"
  if [[ -n "$concerns" ]]; then
    echo "### Open concerns for a human"
    echo
    echo "$concerns"
    echo
  fi
  echo "<details><summary>Turn-by-turn log</summary>"
  echo
  cat "$HISTORY"
  echo "</details>"
} > "$OUT_DIR/comment.md"

echo "status=$status" >> "$OUTPUT_FILE"
echo "commits=$commits" >> "$OUTPUT_FILE"
