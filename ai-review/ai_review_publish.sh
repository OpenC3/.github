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
# FIX_MODE picks where the fixes go:
# - pull_request (default): a new branch off HEAD_SHA, ai-review/pr-<PR_NUMBER>-<run id>, and a PR
#   from it into HEAD_REF, so the author decides whether to take them. It closes the earlier fix
#   PRs for the same PR that it supersedes. A PR whose own branch is a fix branch (a later round
#   fixing CI on a fix PR) gets its fixes pushed straight to that branch.
# - push: straight onto HEAD_REF.
#
# Run from a checkout of HEAD_SHA that stores no credentials.
# Required env: RESULT_DIR, HEAD_SHA, HEAD_REF, GITHUB_REPOSITORY, COMMENT_FILE,
#               PR_NUMBER (for FIX_MODE=pull_request)
# Optional env: FIX_MODE, PUSH_TOKEN (also opens the fix PR, so CI runs on it), GITHUB_RUN_ID,
#               PR_AUTHOR (asked to review the fix PR),
#               SECRETS (values that must never be published, one per line)
#
# Writes COMMENT_FILE, sets the `status` step output, and exits 1 if fixes could not be published.

set -euo pipefail

: "${RESULT_DIR:?}"
: "${HEAD_SHA:?}"
: "${HEAD_REF:?}"
: "${GITHUB_REPOSITORY:?}"
: "${COMMENT_FILE:?}"

FIX_MODE="${FIX_MODE:-pull_request}"
FIX_BRANCH_PREFIX="ai-review/pr-"
case "$FIX_MODE" in
  pull_request) : "${PR_NUMBER:?}" ;;
  push) ;;
  *) echo "::error::fix_mode must be pull_request or push, not '$FIX_MODE'"; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY="$SCRIPT_DIR/patch_policy.py"
BOT="github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"
OUTPUT_FILE="${GITHUB_OUTPUT:-/dev/null}"
# Nothing from the runner's system or user config (such as its LFS filter)
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_COMMITTER_NAME="github-actions[bot]"
export GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"

notes=()
info=()
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
  if ! git am -q --no-3way --keep-cr "${patches[@]}" > /dev/null 2>&1; then
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

remote="https://x-access-token:${PUSH_TOKEN:-}@github.com/${GITHUB_REPOSITORY}.git"

# Pushes the fixes to a branch of their own and opens a PR from it into HEAD_REF; prints what it
# did, or why it failed. The PR is opened with PUSH_TOKEN: one opened with GITHUB_TOKEN would start
# neither CI nor the Malicious Code Scan.
open_fix_pr() {
  local branch="${FIX_BRANCH_PREFIX}${PR_NUMBER}-${GITHUB_RUN_ID:-local}" url body old
  # Only this run makes a branch of this name, so a rerun of the job may replace it
  if ! git push -q --force "$remote" "HEAD:refs/heads/${branch}"; then
    echo "the branch $branch could not be pushed"
    return 1
  fi
  export GH_TOKEN="$PUSH_TOKEN"
  url="$(gh pr list --repo "$GITHUB_REPOSITORY" --head "$branch" --state open --json url --jq '.[0].url // empty' 2> /dev/null || true)"
  if [[ -z "$url" ]]; then
    body="$(printf '%s\n' \
      "Fixes from the AI review of #${PR_NUMBER} at ${HEAD_SHA}. Merge this PR to apply them to \`${HEAD_REF}\`; the review summary is on #${PR_NUMBER}." \
      "" "$(git log --reverse --format='- %s' "$HEAD_SHA..HEAD")")"
    if ! url="$(gh pr create --repo "$GITHUB_REPOSITORY" --base "$HEAD_REF" --head "$branch" \
      --title "AI review fixes for #${PR_NUMBER}" --body "$body" 2> /dev/null | tail -n 1)" || [[ -z "$url" ]]; then
      echo "the fix PR from $branch could not be opened (does AI_REVIEW_PUSH_TOKEN have pull-requests:write?)"
      return 1
    fi
    # Asked separately, so an author who cannot be a reviewer (a bot, say) does not stop the PR
    if [[ -n "${PR_AUTHOR:-}" ]] &&
      ! gh pr edit "$url" --repo "$GITHUB_REPOSITORY" --add-reviewer "$PR_AUTHOR" > /dev/null 2>&1; then
      echo "::warning::Could not request a review of the fix PR from @$PR_AUTHOR" >&2
    fi
  fi
  # Earlier fix PRs for this PR are out of date now; closing them is only housekeeping
  while read -r old; do
    [[ -n "$old" ]] || continue
    gh pr close "$old" --repo "$GITHUB_REPOSITORY" --delete-branch --comment "Superseded by $url" > /dev/null 2>&1 ||
      echo "::warning::Could not close the superseded fix PR #$old" >&2
  done < <(gh pr list --repo "$GITHUB_REPOSITORY" --base "$HEAD_REF" --state open --json number,headRefName \
    --jq ".[] | select((.headRefName | startswith(\"${FIX_BRANCH_PREFIX}${PR_NUMBER}-\")) and .headRefName != \"$branch\") | .number" \
    2> /dev/null || true)
  echo "The fixes from this review are in $url, a PR into \`${HEAD_REF}\`. Merge it to apply them."
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
  elif [[ "$FIX_MODE" == "push" || "$HEAD_REF" == "$FIX_BRANCH_PREFIX"* ]]; then
    # Plain (non-force) push: if the author pushed meanwhile this fails rather than clobbering their work
    if ! git push -q "$remote" "HEAD:refs/heads/${HEAD_REF}"; then
      notes+=("The fix commits above could not be pushed (the branch probably moved); they were discarded.")
      failed=1
    fi
  elif ! reason="$(open_fix_pr)"; then
    notes+=("The fix commits above were not published because $reason.")
    echo "::error::Not publishing the fix commits: $reason"
    failed=1
  else
    info+=("$reason")
  fi
fi
# A rerun may succeed where publishing failed, so do not mark the commit reviewed
(( failed )) && status="error"

{
  echo "<!-- ai-adversarial-review -->"
  # The marker stops later runs from reviewing this commit again, so leave it off when a reviewer
  # failed (an API outage, say) and a rerun could succeed
  [[ "$status" == "error" ]] || echo "<!-- ai-review-sha: $HEAD_SHA -->"
  heading="## AI adversarial review"
  body=""
  if [[ -f "$RESULT_DIR/body.md" ]]; then
    # Escape comment openers so the summary cannot add a marker of its own; stay under GitHub's limit
    body="$(head -c 60000 "$RESULT_DIR/body.md" | sed 's/<!--/\&lt;!--/g')"
  fi
  # The link to the fix PR goes under the heading, above the turn-by-turn history
  if [[ -z "$body" || "${body%%$'\n'*}" == "$heading" ]]; then
    echo "$heading"
    body="$(tail -n +2 <<< "$body")"
  fi
  for note in ${info[@]+"${info[@]}"}; do
    printf '\n> [!NOTE]\n> %s\n\n' "$note"
  done
  [[ -z "$body" ]] || printf '%s\n' "$body"
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
