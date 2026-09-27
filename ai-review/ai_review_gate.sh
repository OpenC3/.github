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

# Decides whether the AI review loop should run for a PR and collects failed
# CI job logs for the reviewers. Every CI workflow completion triggers the AI
# Review workflow, so this lets only the run that sees all CI finished proceed.
#
# Required env: GH_TOKEN, GITHUB_REPOSITORY, EVENT_NAME, OUT_DIR
# One of: PR_NUMBER, HEAD_SHA
# Optional env: FORCE (review even if this commit was already reviewed), REVIEW_WORKFLOW,
#               SCAN_WORKFLOW, SCAN_CONTEXT, MAX_CI_ROUNDS, LOG_LINES
#
# Step outputs: skip, reason, pr, head_sha, head_ref, base_ref, ci_failures

set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
: "${EVENT_NAME:?}"
: "${OUT_DIR:?}"

REVIEW_WORKFLOW="${REVIEW_WORKFLOW:-AI Review}"
SCAN_WORKFLOW="${SCAN_WORKFLOW:-Malicious Code Scan}"
SCAN_CONTEXT="${SCAN_CONTEXT:-security/malicious-code-scan}"
FORCE="${FORCE:-false}"
MAX_CI_ROUNDS="${MAX_CI_ROUNDS:-3}"
LOG_LINES="${LOG_LINES:-150}"
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
repo="$GITHUB_REPOSITORY"
PR_NUMBER="${PR_NUMBER:-}"
HEAD_SHA="${HEAD_SHA:-}"

mkdir -p "$OUT_DIR"
CI_FILE="$OUT_DIR/ci_failures.md"
: > "$CI_FILE"

output() { echo "$1=$2" >> "$GITHUB_OUTPUT"; }
skip() {
  echo "Skipping AI review: $1"
  output skip true
  output reason "$1"
  exit 0
}

if [[ -z "$PR_NUMBER" ]]; then
  PR_NUMBER="$(gh api "repos/$repo/commits/$HEAD_SHA/pulls" --jq '[.[] | select(.state == "open")][0].number // empty')"
  [[ -n "$PR_NUMBER" ]] || skip "no open PR for $HEAD_SHA"
fi

pr="$(gh api "repos/$repo/pulls/$PR_NUMBER")"
pr_field() { jq -r "$1" <<< "$pr"; }

[[ "$(pr_field .state)" == "open" ]] || skip "PR #$PR_NUMBER is not open"
# Fork PRs must never run with secrets and a write token
[[ "$(pr_field .head.repo.full_name)" == "$repo" ]] || skip "PR #$PR_NUMBER is from a fork"
[[ "$(pr_field .draft)" == "false" ]] || skip "PR #$PR_NUMBER is a draft"
[[ "$(pr_field .user.login)" != "dependabot[bot]" ]] || skip "PR #$PR_NUMBER is from dependabot"
if pr_field '.labels[].name' | grep -qx 'skip-ai-review'; then
  skip "PR #$PR_NUMBER has the skip-ai-review label"
fi

pr_head="$(pr_field .head.sha)"
if [[ -n "$HEAD_SHA" && "$HEAD_SHA" != "$pr_head" ]]; then
  skip "CI finished for $HEAD_SHA but the PR head has moved to $pr_head"
fi
HEAD_SHA="$pr_head"

# Never hand a PR to agents holding secrets and a write token until the malicious code scan passes
IFS=$'\t' read -r scan_state scan_url < <(gh api "repos/$repo/commits/$HEAD_SHA/status" \
  --jq ".statuses[] | select(.context == \"$SCAN_CONTEXT\") | [.state, .target_url // \"\"] | @tsv") || true
# Any workflow with statuses: write, a PR's own included, can post this status. Only accept one that
# links to a pull_request_target run of the scan workflow, which comes from the default branch, and
# that run has not failed. The run object for pull_request_target does not record the PR head, so
# this cannot prove the run scanned this commit; the scan's pending status on each push covers that.
if [[ "$scan_state" == "success" ]]; then
  run_prefix="${GITHUB_SERVER_URL:-https://github.com}/$repo/actions/runs/"
  scan_run="${scan_url#"$run_prefix"}"
  scan_run_info=""
  if [[ "$scan_url" == "$run_prefix"* && "$scan_run" =~ ^[0-9]+$ ]]; then
    scan_run_info="$(gh api "repos/$repo/actions/runs/$scan_run" --jq '[.event, .name, .conclusion // ""] | @tsv' || true)"
  fi
  IFS=$'\t' read -r run_event run_name run_conclusion <<< "$scan_run_info"
  # The scan dispatches this review before its own run finishes, so only that dispatch may accept a
  # run with no conclusion yet. Otherwise a status forged while the real scan is still running, and
  # pointed at that run, would start the review on a commit the scan may still block.
  allowed_conclusion="^success$"
  [[ "$EVENT_NAME" == "workflow_dispatch" ]] && allowed_conclusion="^(success)?$"
  if [[ "$run_event" != "pull_request_target" || "$run_name" != "$SCAN_WORKFLOW" ||
    ! "$run_conclusion" =~ $allowed_conclusion ]]; then
    skip "the malicious code scan status on $HEAD_SHA was not posted by a passing $SCAN_WORKFLOW run"
  fi
fi
case "$scan_state" in
  success) ;;
  "") skip "the malicious code scan has not reported on $HEAD_SHA" ;;
  pending) skip "the malicious code scan is still running on $HEAD_SHA" ;;
  *) skip "the malicious code scan blocked $HEAD_SHA ($scan_state)" ;;
esac

# Paginate: every CI completion adds an AI Review run for this commit, which can push CI runs off page one
runs="$(gh api "repos/$repo/actions/runs?head_sha=$HEAD_SHA&per_page=100" --paginate \
  --jq ".workflow_runs[] | select(.name != \"$REVIEW_WORKFLOW\" and .name != \"$SCAN_WORKFLOW\")" | jq -s .)"
total="$(jq length <<< "$runs")"
# Built-in (dynamic) runs such as CodeQL default setup may not trigger workflow_run, so waiting on
# one that finishes last would never start the review; their failures are still collected below
pending="$(jq '[.[] | select(.status != "completed" and .event != "dynamic")] | length' <<< "$runs")"
if (( total == 0 )) && [[ "$EVENT_NAME" != "workflow_dispatch" ]]; then
  skip "no CI runs found for $HEAD_SHA yet"
fi
(( pending == 0 )) || skip "$pending of $total CI run(s) for $HEAD_SHA still in progress"

marker="<!-- ai-review-sha: $HEAD_SHA -->"
# Only the workflow's own summary can attest that this commit was reviewed.
if [[ "$FORCE" != "true" ]] &&
  gh api "repos/$repo/issues/$PR_NUMBER/comments" --paginate --jq '
    .[] | select(.user.login == "github-actions[bot]" and .user.type == "Bot")
    | .body | select(startswith("<!-- ai-adversarial-review -->"))' | grep -F "$marker" > /dev/null; then
  skip "$HEAD_SHA was already reviewed"
fi

# Collect failed job logs, with a workflow-level fallback for failures before jobs start.
failures=0
while IFS=$'\t' read -r run_id run_name run_conclusion run_url; do
  [[ -n "$run_id" ]] || continue
  failures_before=$failures
  jobs="$(gh api "repos/$repo/actions/runs/$run_id/jobs" --paginate \
    --jq '.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out") | [.id, .name, .html_url] | @tsv')" \
    || jobs=""
  while IFS=$'\t' read -r job_id job_name job_url; do
    [[ -n "$job_id" ]] || continue
    failures=$((failures + 1))
    {
      echo "### $run_name / $job_name"
      echo
      echo "$job_url"
      echo
      echo '```'
      # Strip the timestamp prefix and ANSI colors to save tokens
      gh api "repos/$repo/actions/jobs/$job_id/logs" 2> /dev/null \
        | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z //; s/\x1b\[[0-9;]*m//g' \
        | tail -n "$LOG_LINES" || echo "(log unavailable)"
      echo '```'
      echo
    } >> "$CI_FILE"
  done <<< "$jobs"
  if (( failures == failures_before )); then
    failures=$((failures + 1))
    {
      echo "### $run_name / workflow failure"
      echo
      echo "$run_url"
      echo
      echo "Workflow conclusion: $run_conclusion. No failed job logs are available."
      echo "Inspect the workflow configuration and run annotations for failures before jobs started."
      echo
    } >> "$CI_FILE"
  fi
done < <(jq -r '.[] | select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "startup_failure")
  | [.id, .name, .conclusion, .html_url] | @tsv' <<< "$runs")

# When the head commit is the loop's own fix, only go again to fix CI, and only a few times
head_message="$(gh api "repos/$repo/commits/$HEAD_SHA" --jq .commit.message)"
if grep -q '^AI-Review-Bot: true$' <<< "$head_message"; then
  (( failures > 0 )) || skip "head commit is an AI review fix and CI passed"
  # Count distinct loop runs among the consecutive AI review commits at the tip of the PR
  rounds="$(gh api "repos/$repo/pulls/$PR_NUMBER/commits" --paginate --jq '[.[].commit.message]' | jq -s '
    add | reverse
    | (map(test("(?m)^AI-Review-Bot: true$") | not) | index(true)) as $human
    | (if $human == null then . else .[:$human] end)
    | map(capture("(?m)^AI-Review-Run: (?<id>\\S+)$").id) | unique | length')"
  if (( rounds >= MAX_CI_ROUNDS )); then
    skip "CI still failing after $rounds AI fix round(s) (max $MAX_CI_ROUNDS)"
  fi
fi

echo "PR #$PR_NUMBER at $HEAD_SHA: $total CI run(s) complete, $failures CI failure(s)"
output skip false
output pr "$PR_NUMBER"
output head_sha "$HEAD_SHA"
output head_ref "$(pr_field .head.ref)"
output base_ref "$(pr_field .base.ref)"
output ci_failures "$failures"
