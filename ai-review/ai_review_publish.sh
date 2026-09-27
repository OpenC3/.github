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

# Publishes what the review loop (ai_review_loop.sh) produced, from a fresh runner that no agent
# touched. Everything in RESULT_DIR comes from the agents' runner and is checked here as if an
# agent wrote all of it, so this holds even if an agent escaped its sandbox:
# - The status must be one the loop reports.
# - The summary cannot carry the markers later runs trust; this script writes those.
# - The fix commits must be the harness's own, change nothing patch_policy.py refuses, and
#   contain no secret. Only then are they pushed.
#
# Run from a checkout of HEAD_SHA that stores no credentials.
# Required env: RESULT_DIR, HEAD_SHA, HEAD_REF, GITHUB_REPOSITORY, COMMENT_FILE
# Optional env: PUSH_TOKEN, SECRETS (values that must never be published, one per line)
#
# Writes COMMENT_FILE, sets the `status` step output, and exits 1 if fixes could not be published.

set -euo pipefail

: "${RESULT_DIR:?}"
: "${HEAD_SHA:?}"
: "${HEAD_REF:?}"
: "${GITHUB_REPOSITORY:?}"
: "${COMMENT_FILE:?}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY="$SCRIPT_DIR/patch_policy.py"
BOT="github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"
OUTPUT_FILE="${GITHUB_OUTPUT:-/dev/null}"
# Nothing from the runner's system or user config (such as its LFS filter)
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_COMMITTER_NAME="github-actions[bot]"
export GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"

notes=()
failed=0

status=""
if [[ -f "$RESULT_DIR/status" ]]; then
  read -r status < "$RESULT_DIR/status" || true
fi
case "$status" in
  converged | max_turns | error) ;;
  *)
    notes+=("The review did not finish, so there is no result to publish. See the workflow run log.")
    status="error"
    ;;
esac

# Succeeds if stdin contains one of SECRETS. No grep -q: exiting early would SIGPIPE the writer,
# and pipefail would read that as no match.
contains_secret() {
  local patterns
  patterns="$(printf '%s\n' "${SECRETS:-}" | grep -v '^$' || true)"
  [[ -n "$patterns" ]] && grep -F -f <(echo "$patterns") > /dev/null
}

# Applies the fix commits and checks them; if they may not be pushed, prints why and fails
apply_fixes() {
  local patches=("$@") commit
  if ! git am -q --no-3way "${patches[@]}" > /dev/null 2>&1; then
    git am --abort > /dev/null 2>&1 || true
    echo "they did not apply to $HEAD_SHA"
    return 1
  fi
  if git log --format='%an <%ae>' "$HEAD_SHA..HEAD" | grep -vxF "$BOT" > /dev/null; then
    echo "they were not all made by the review harness"
    return 1
  fi
  for commit in $(git rev-list "$HEAD_SHA..HEAD"); do
    # The gate counts fix rounds by this trailer
    if ! git log -1 --format=%B "$commit" | grep -x 'AI-Review-Bot: true' > /dev/null; then
      echo "commit $commit is missing the AI-Review-Bot trailer"
      return 1
    fi
  done
  local reason
  if ! reason="$(python3 "$POLICY" "$HEAD_SHA" HEAD)"; then
    echo "${reason:-the change policy check failed}"
    return 1
  fi
  # --text: a NUL byte or a -diff attribute would otherwise hide a file's contents from the grep
  if git log -p --text --no-ext-diff --no-textconv --format=%B "$HEAD_SHA..HEAD" | contains_secret; then
    echo "they contained a secret. Rotate the repository's API keys and tokens"
    return 1
  fi
}

[[ "$(git rev-parse HEAD)" == "$HEAD_SHA" ]] || { echo "::error::Not a checkout of $HEAD_SHA"; exit 1; }
shopt -s nullglob
patches=("$RESULT_DIR"/patches/*.patch)
shopt -u nullglob
if (( ${#patches[@]} )); then
  if ! reason="$(apply_fixes "${patches[@]}")"; then
    notes+=("The fix commits were not pushed because $reason.")
    echo "::error::Not pushing the fix commits: $reason"
    failed=1
  elif [[ -z "${PUSH_TOKEN:-}" ]]; then
    notes+=("The fix commits above were not pushed because AI_REVIEW_PUSH_TOKEN is not set.")
    echo "::warning::AI_REVIEW_PUSH_TOKEN is not set; not pushing the fix commits"
  # Plain (non-force) push: if the author pushed meanwhile this fails rather than clobbering their work
  elif ! git push -q "https://x-access-token:${PUSH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "HEAD:refs/heads/${HEAD_REF}"; then
    notes+=("The fix commits above could not be pushed (the branch probably moved); they were discarded.")
    failed=1
  fi
fi
# A rerun may succeed where publishing failed, so do not mark the commit reviewed
(( failed )) && status="error"

{
  echo "<!-- ai-adversarial-review -->"
  # The marker stops later runs from reviewing this commit again, so leave it off when a reviewer
  # failed (an API outage, say) and a rerun could succeed
  [[ "$status" == "error" ]] || echo "<!-- ai-review-sha: $HEAD_SHA -->"
  if [[ -f "$RESULT_DIR/body.md" ]]; then
    # Escape comment openers so the summary cannot add a marker of its own; stay under GitHub's limit
    head -c 60000 "$RESULT_DIR/body.md" | sed 's/<!--/\&lt;!--/g'
  else
    echo "## AI adversarial review"
  fi
  for note in ${notes[@]+"${notes[@]}"}; do
    printf '\n> [!WARNING]\n> %s\n' "$note"
  done
} > "$COMMENT_FILE"
# The summary quotes agent output
if contains_secret < "$COMMENT_FILE"; then
  echo "::error::The review summary contains a secret; posting a redacted summary"
  printf '%s\n' "<!-- ai-adversarial-review -->" "## AI adversarial review" "" \
    "❌ The review summary contained a secret and was not posted. Rotate the repository's API keys and tokens." \
    > "$COMMENT_FILE"
  status="error"
  failed=1
fi

echo "status=$status" >> "$OUTPUT_FILE"
exit "$failed"
