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
# Every turn runs in a throwaway container (see sandbox/Dockerfile) that holds
# nothing worth escaping for:
# - Its network has no route out. The only other member is an API proxy
#   (sandbox/api_proxy.py) holding that turn's key, so no agent ever sees a key.
# - The agent works on a copy of the tree, with the repository's .git mounted
#   read-only, so it cannot plant git config or hooks for the harness. The copy
#   comes back without any .git, and fresh from the last commit each turn, so
#   nothing an agent leaves outside the commits reaches the next agent.
# - This job has no token that can write to GitHub. The fix commits leave as
#   patches for the publish job (ai_review_publish.sh), which checks them again
#   on a fresh runner before pushing.
#
# Required env: BASE_REF, CLAUDE_API_KEY, CODEX_API_KEY, SANDBOX_IMAGE (built from sandbox/)
# Optional env: MAX_TURNS, TIME_LIMIT_MINUTES, CLAUDE_MODEL, CODEX_MODEL, CLAUDE_MAX_BUDGET_USD, CODEX_SANDBOX,
#               CI_FAILURES_FILE (failed CI job logs from ai_review_gate.sh), CI_FAILURE_COUNT,
#               REVIEW_INSTRUCTIONS (repository-specific guidance for the prompt), GITHUB_RUN_ID,
#               RESULT_DIR, ANTHROPIC_UPSTREAM and OPENAI_UPSTREAM (where the proxy sends each API's calls)
#
# Writes $RESULT_DIR/status (converged, max_turns or error), $RESULT_DIR/body.md (the review
# summary) and $RESULT_DIR/patches/*.patch (the fix commits, if any). They are rewritten after every
# turn, so a job killed partway through still hands the publish job the fixes committed so far.

set -euo pipefail

: "${BASE_REF:?BASE_REF is required}"
: "${CLAUDE_API_KEY:?CLAUDE_API_KEY is required}"
: "${CODEX_API_KEY:?CODEX_API_KEY is required}"
: "${SANDBOX_IMAGE:?SANDBOX_IMAGE is required}"

MAX_TURNS="${MAX_TURNS:-6}"
# Keep under the job's timeout-minutes, leaving time for the setup steps and the upload
TIME_LIMIT_MINUTES="${TIME_LIMIT_MINUTES:-75}"
CLAUDE_MODEL="${CLAUDE_MODEL:-claude-opus-5-5}"
CLAUDE_MAX_BUDGET_USD="${CLAUDE_MAX_BUDGET_USD:-5}"
# The container is the sandbox; Codex's own needs user namespaces, which containers do not get
CODEX_SANDBOX="${CODEX_SANDBOX:-danger-full-access}"
OUT_DIR="${OUT_DIR:-${RUNNER_TEMP:-/tmp}/ai-review}"
RESULT_DIR="${RESULT_DIR:-$OUT_DIR/result}"
ANTHROPIC_UPSTREAM="${ANTHROPIC_UPSTREAM:-https://api.anthropic.com}"
OPENAI_UPSTREAM="${OPENAI_UPSTREAM:-https://api.openai.com}"

# Run from the PR checkout; the prompt, schema and policy live next to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_TEMPLATE="$SCRIPT_DIR/prompt.md"
SCHEMA="$SCRIPT_DIR/schema.json"
POLICY="$SCRIPT_DIR/patch_policy.py"
HISTORY="$OUT_DIR/history.md"
CI_FAILURES_FILE="${CI_FAILURES_FILE:-}"
RUN_ID="${GITHUB_RUN_ID:-local}"

# Keep the runner's system and user git config (such as its LFS filter) out of the harness's git
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

REPO="$(git rev-parse --show-toplevel)"
mkdir -p "$OUT_DIR"
rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR/patches"
: > "$HISTORY"

MERGE_BASE="$(git merge-base "origin/$BASE_REF" HEAD)"
START_SHA="$(git rev-parse HEAD)"

SANDBOX_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/ai-review-sandbox.XXXXXX")"
WORK="$SANDBOX_DIR/work"
TURN_OUT="$SANDBOX_DIR/out"
NETWORK="ai-review-$$"
PROXY="ai-review-proxy-$$"
AGENT="ai-review-agent-$$"
watchdog_pid=""
# The agent may have taken its own permissions away from what it wrote
remove_sandbox_files() {
  chmod -R u+rwX "$WORK" "$TURN_OUT" 2> /dev/null || true
  rm -rf "$WORK" "$TURN_OUT"
}
cleanup() {
  stop_watchdog
  docker rm -f "$AGENT" "$PROXY" > /dev/null 2>&1 || true
  docker network rm "$NETWORK" > /dev/null 2>&1 || true
  remove_sandbox_files
  rm -rf "$SANDBOX_DIR"
}
# Removes the agent's container once the review's time is up, which ends its turn. It tries for a
# minute in case the time runs out before the container starts. The sleeps run in the background
# so the trap can stop them with the watchdog rather than leave them behind.
start_watchdog() {
  (
    trap 'kill "$sleeper" 2> /dev/null; exit' TERM
    sleep "$1" & sleeper=$!
    wait "$sleeper"
    for _ in $(seq 12); do
      docker rm -f "$AGENT" || true
      sleep 5 & sleeper=$!
      wait "$sleeper"
    done
  ) > /dev/null 2>&1 < /dev/null &
  watchdog_pid=$!
}
stop_watchdog() {
  [[ -n "$watchdog_pid" ]] && kill "$watchdog_pid" 2> /dev/null || true
  watchdog_pid=""
}
trap cleanup EXIT
# --internal: containers on this network cannot reach anything outside it
docker network create --internal "$NETWORK" > /dev/null

# Copies a tree without any .git, at any depth
copy_tree() {
  (cd "$1" && tar --exclude=.git -cf - .) | (cd "$2" && tar -xpf -)
}

# The agent's copy of the last commit. .git is a mount point, created here so docker does not
# create it as root.
prepare_work() {
  remove_sandbox_files
  mkdir -p "$WORK/.git" "$TURN_OUT"
  copy_tree "$REPO" "$WORK"
}

# Replaces the checkout's tree with the agent's. Fails on anything git add could not take (a FIFO,
# an unreadable file); the caller then resets the checkout.
import_work() {
  [[ -z "$(find "$WORK" -path "$WORK/.git" -prune -o ! -type f ! -type d ! -type l -print)" ]] || return 1
  find "$REPO" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  copy_tree "$WORK" "$REPO"
}

# Runs an image in a throwaway container: no capabilities, a read-only root, an empty HOME, the
# agent's copy of the tree with the repository's .git read-only, and the turn's output directory.
# Host paths are mounted at the same paths so arguments need no translating. The mounts may show a
# different owner inside (Docker Desktop), which git would otherwise refuse.
sandbox() {
  docker run --rm -i \
    --name "$AGENT" \
    --network "$NETWORK" \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --read-only \
    --tmpfs /tmp:exec \
    --tmpfs /home/agent:exec,mode=1777 \
    --pids-limit 4096 \
    -e HOME=/home/agent \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0="$WORK" \
    -v "$WORK:$WORK" \
    -v "$REPO/.git:$WORK/.git:ro" \
    -v "$TURN_OUT:$TURN_OUT" \
    -w "$WORK" \
    "$@"
}

# Starts the proxy for one turn with one key. It is created on the default bridge, which reaches
# the internet, and then joins the agents' network, where agents reach it by name.
start_proxy() {
  local upstream="$1" auth="$2" key="$3" routes="$4"
  docker rm -f "$PROXY" > /dev/null 2>&1 || true
  # -e without a value passes the key from this environment rather than the command line
  PROXY_API_KEY="$key" docker run -d --name "$PROXY" \
    --user 65534:65534 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --read-only \
    -e PROXY_UPSTREAM="$upstream" \
    -e PROXY_AUTH="$auth" \
    -e PROXY_API_KEY \
    -e PROXY_ROUTES="$routes" \
    "$SANDBOX_IMAGE" python3 /opt/ai-review/api_proxy.py > /dev/null
  docker network connect "$NETWORK" "$PROXY"
  local attempt
  for attempt in $(seq 50); do
    if docker exec "$PROXY" python3 -c "import socket; socket.create_connection(('127.0.0.1', 8080), 1)" \
      > /dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "::error::The API proxy did not start after $attempt attempts" >&2
  docker logs "$PROXY" >&2 || true
  return 1
}

stop_proxy() {
  docker logs "$PROXY" 2>&1 | grep -F refused >&2 || true
  docker rm -f "$PROXY" > /dev/null 2>&1 || true
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
  start_proxy "$ANTHROPIC_UPSTREAM" x-api-key "$CLAUDE_API_KEY" 'POST /v1/messages(/count_tokens)?|HEAD /api/hello' || return 1
  # Settings and MCP servers from the PR are not loaded, so the PR cannot change the tools below
  sandbox \
    -e ANTHROPIC_BASE_URL="http://$PROXY:8080" \
    -e ANTHROPIC_API_KEY=placeholder-the-proxy-adds-the-key \
    -e CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    "$SANDBOX_IMAGE" \
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
  start_proxy "$OPENAI_UPSTREAM" bearer "$CODEX_API_KEY" 'POST /v1/responses(/compact)?|GET /v1/models' || return 1
  cp "$SCHEMA" "$TURN_OUT/schema.json"
  sandbox \
    -e AI_REVIEW_PROXY_KEY=placeholder-the-proxy-adds-the-key \
    "$SANDBOX_IMAGE" \
    codex exec \
      ${model_args[@]+"${model_args[@]}"} \
      -c 'model_provider="ai_review_proxy"' \
      -c "model_providers.ai_review_proxy={ name = \"OpenAI via the AI review proxy\", base_url = \"http://$PROXY:8080/v1\", env_key = \"AI_REVIEW_PROXY_KEY\", wire_api = \"responses\" }" \
      --sandbox "$CODEX_SANDBOX" \
      -c 'approval_policy="never"' \
      --ephemeral \
      --output-schema "$TURN_OUT/schema.json" \
      --output-last-message "$TURN_OUT/result.json" \
      - < "$prompt_file" || return $?
  cp "$TURN_OUT/result.json" "$result_file" || return $?
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

# Writes the summary and status for the publish job; the patches are written as each fix is committed
write_result() {
  local state="$1" commits concerns
  commits="$(git rev-list --count "$START_SHA..HEAD")"
  {
    echo "## AI adversarial review"
    echo
    if [[ -n "$CI_FAILURES_FILE" && -s "$CI_FAILURES_FILE" ]]; then
      echo "CI had ${CI_FAILURE_COUNT:-some} failure(s) on the reviewed commit; the reviewers were asked to fix them."
      echo
    fi
    case "$state" in
      converged) echo "✅ Claude and Codex converged after $turn turn(s) with $commits fix commit(s)." ;;
      max_turns) echo "⚠️ Stopped after the maximum of $MAX_TURNS turns without converging ($commits fix commit(s)). A human should look at the last few turns." ;;
      error) echo "❌ A reviewer failed on turn $turn. Fixes from earlier turns ($commits commit(s)) were kept." ;;
      timeout) echo "❌ The review ran out of its $TIME_LIMIT_MINUTES minutes. Fixes from earlier turns ($commits commit(s)) were kept." ;;
      running) echo "❌ The review was stopped during turn $((turn + 1)), probably by the job's time limit. Fixes from earlier turns ($commits commit(s)) were kept." ;;
    esac
    echo
    echo "Reviewed commit: \`$START_SHA\`"
    echo
    # Concerns from each reviewer's most recent successful turn need a human decision
    # (reviewers alternate turns; a failed or discarded turn has no result file)
    concerns="$(for start in "$turn" "$((turn - 1))"; do
      for ((t = start; t >= 1; t -= 2)); do
        if [[ -f "$OUT_DIR/result-$t.json" ]]; then
          jq -r '.unresolved_concerns[]? | "- \(.)"' "$OUT_DIR/result-$t.json" 2> /dev/null || true
          break
        fi
      done
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
  } > "$RESULT_DIR/body.md"
  # A review that did not finish is reported as failed, so the commit is not marked reviewed
  case "$state" in
    converged | max_turns) echo "$state" ;;
    *) echo error ;;
  esac > "$RESULT_DIR/status"
}

reviewers=(Claude Codex)
reviewed_claude=0
reviewed_codex=0
status="max_turns"
turn=0
time_limit=$((TIME_LIMIT_MINUTES * 60))

while (( turn < MAX_TURNS )); do
  # In case the job is killed during this turn
  write_result running
  if (( SECONDS >= time_limit )); then
    status="timeout"
    break
  fi
  reviewer="${reviewers[turn % 2]}"
  other="${reviewers[(turn + 1) % 2]}"
  turn=$((turn + 1))
  prompt_file="$OUT_DIR/prompt-$turn.md"
  result_file="$OUT_DIR/result-$turn.json"
  build_prompt "$reviewer" "$other" "$turn" "$prompt_file"
  prepare_work
  before_sha="$(git rev-parse HEAD)"

  echo "::group::Turn $turn: $reviewer"
  start_watchdog $((time_limit - SECONDS))
  if [[ "$reviewer" == "Claude" ]]; then
    run_claude "$prompt_file" "$result_file" "$turn" && rc=0 || rc=$?
  else
    run_codex "$prompt_file" "$result_file" && rc=0 || rc=$?
  fi
  stop_watchdog
  stop_proxy
  echo "::endgroup::"

  discard=""
  if (( rc == 0 )); then
    if ! import_work; then
      discard="it left files that could not be copied back (a FIFO or an unreadable file, say)"
    else
      git add -A
      # Fail closed: a policy check that crashes refuses the turn too
      if ! reason="$(python3 "$POLICY" "$before_sha")"; then
        discard="${reason:-the change policy check failed}"
      fi
    fi
  fi

  if (( rc != 0 )) || [[ -n "$discard" ]]; then
    status="error"
    if [[ -n "$discard" ]]; then
      echo "::error::Discarding $reviewer's turn $turn because $discard"
      echo "### Turn $turn: $reviewer's turn was discarded because $discard" >> "$HISTORY"
    elif (( SECONDS >= time_limit )); then
      echo "::error::$reviewer's turn $turn ran out of time"
      echo "### Turn $turn: $reviewer ran out of time" >> "$HISTORY"
      status="timeout"
    else
      echo "::error::$reviewer failed on turn $turn (exit $rc)"
      echo "### Turn $turn: $reviewer failed (exit $rc)" >> "$HISTORY"
    fi
    rm -f "$result_file"
    git reset -q --hard "$before_sha"
    git clean -fdqx
    break
  fi

  commit=""
  if ! git diff --cached --quiet; then
    # One line per fix: git am would take a line starting with --- or diff - as the start of the patch
    git commit -q -F - <<EOF
fix(review): apply $reviewer review fixes (turn $turn)

$(jq -r '.issues_fixed[]? | gsub("[\r\n]+"; " ") | "- \(.)"' "$result_file")

AI-Review-Bot: true
AI-Review-Run: $RUN_ID
EOF
    commit="$(git rev-parse --short HEAD)"
    git format-patch -q --binary -1 --start-number "$(git rev-list --count "$START_SHA..HEAD")" \
      -o "$RESULT_DIR/patches" HEAD
  fi
  # Ignored files git add skipped; the next turn starts from the commit alone
  git clean -fdqx

  if [[ "$reviewer" == "Claude" ]]; then reviewed_claude=1; else reviewed_codex=1; fi
  record_turn "$turn" "$reviewer" "$result_file" "$commit"
  cat "$result_file"

  if [[ -z "$commit" && $reviewed_claude == 1 && $reviewed_codex == 1 ]]; then
    status="converged"
    break
  fi
done

write_result "$status"
echo "AI review finished: $status, $(git rev-list --count "$START_SHA..HEAD") fix commit(s)"
