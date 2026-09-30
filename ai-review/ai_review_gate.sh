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
# CI job logs and SonarQube findings for the reviewers. Every CI workflow completion triggers the AI
# Review workflow, so this lets only the run that sees all CI finished proceed.
# The Malicious Code Scan does not trigger the review, so that run waits for a
# scan still running on the PR head. A manual (workflow_dispatch) run fails
# instead of skipping, so it is not mistaken for a review that passed.
#
# Required env: GH_TOKEN, GITHUB_REPOSITORY, EVENT_NAME, OUT_DIR
# One of: PR_NUMBER, HEAD_SHA
# Optional env: FORCE (review even if this commit was already reviewed), REVIEW_WORKFLOW,
#               SCAN_WORKFLOW, SCAN_CONTEXT, MAX_CI_ROUNDS, LOG_LINES,
#               SCAN_WAIT_MINUTES (how long to wait for a running scan), SCAN_POLL_SECONDS,
#               SONAR_PROJECT_KEY (default: from the SonarQube check run), SONAR_TOKEN (for a private
#               project), SONAR_HOST_URL, SONAR_APP (the check run's app slug),
#               SONAR_WAIT_MINUTES (how long to wait for a running analysis)
#
# Step outputs: skip, reason, pr, author, head_sha, head_ref, base_ref, ci_failures, sonar_findings

set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
: "${EVENT_NAME:?}"
: "${OUT_DIR:?}"

REVIEW_WORKFLOW="${REVIEW_WORKFLOW:-AI Review}"
SCAN_WORKFLOW="${SCAN_WORKFLOW:-Malicious Code Scan}"
SCAN_CONTEXT="${SCAN_CONTEXT:-security/malicious-code-scan}"
FORCE="${FORCE:-false}"
MAX_CI_ROUNDS="${MAX_CI_ROUNDS:-3}"
SCAN_WAIT_MINUTES="${SCAN_WAIT_MINUTES:-10}"
SCAN_POLL_SECONDS="${SCAN_POLL_SECONDS:-30}"
LOG_LINES="${LOG_LINES:-150}"
SONAR_PROJECT_KEY="${SONAR_PROJECT_KEY:-}"
SONAR_HOST_URL="${SONAR_HOST_URL:-https://sonarcloud.io}"
SONAR_APP="${SONAR_APP:-sonarqubecloud}"
SONAR_WAIT_MINUTES="${SONAR_WAIT_MINUTES:-10}"
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
repo="$GITHUB_REPOSITORY"
PR_NUMBER="${PR_NUMBER:-}"
HEAD_SHA="${HEAD_SHA:-}"

mkdir -p "$OUT_DIR"
CI_FILE="$OUT_DIR/ci_failures.md"
SONAR_FILE="$OUT_DIR/sonar_findings.md"
: > "$CI_FILE"
: > "$SONAR_FILE"

output() { echo "$1=$2" >> "$GITHUB_OUTPUT"; }
skip() {
  output skip true
  output reason "$1"
  if [[ "$EVENT_NAME" == "workflow_dispatch" ]]; then
    echo "::error::Not reviewing: $1"
    exit 1
  fi
  echo "::notice::Skipping AI review: $1"
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

# Paginate: every CI completion adds an AI Review run for this commit, which can push CI runs off page one
runs="$(gh api "repos/$repo/actions/runs?head_sha=$HEAD_SHA&per_page=100" --paginate \
  --jq ".workflow_runs[] | select(.name != \"$REVIEW_WORKFLOW\" and .name != \"$SCAN_WORKFLOW\")" | jq -s .)"
total="$(jq length <<< "$runs")"
# Only pull_request runs start this review when they finish (the pr job drops the rest), so waiting on
# a push or built-in (dynamic, e.g. CodeQL default setup) run that finishes last would never start it.
# Failures from every run are still collected below.
pending="$(jq '[.[] | select(.status != "completed" and .event == "pull_request")] | length' <<< "$runs")"
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

# Never hand a PR to agents holding secrets and a write token until the malicious code scan passes.
# Nothing triggers this review when the scan finishes, so if CI finished first, wait for it here.
scan_status() {
  gh api "repos/$repo/commits/$HEAD_SHA/status" --paginate \
    --jq ".statuses[] | select(.context == \"$SCAN_CONTEXT\")" | jq -s '.[0] // {}'
}
# The scan marks the commit pending when it starts; before then (queued for a runner, or behind
# the scan of an earlier push) there is only its run. Any unfinished scan in the repository counts,
# which at worst waits out SCAN_WAIT_MINUTES for a PR that has no scan coming.
scan_queued() {
  gh api "repos/$repo/actions/runs?event=pull_request_target&per_page=20" \
    --jq "[.workflow_runs[] | select(.name == \"$SCAN_WORKFLOW\" and .status != \"completed\")] | length"
}
deadline=$((SECONDS + SCAN_WAIT_MINUTES * 60))
while true; do
  scan_status="$(scan_status)"
  scan_state="$(jq -r '.state // ""' <<< "$scan_status")"
  [[ "$scan_state" == "pending" || ( -z "$scan_state" && "$(scan_queued)" != "0" ) ]] || break
  (( SECONDS < deadline )) || break
  # A push abandons the scan of this commit, which then never reports
  [[ "$(gh api "repos/$repo/pulls/$PR_NUMBER" --jq .head.sha)" == "$HEAD_SHA" ]] ||
    skip "the PR head moved past $HEAD_SHA while waiting for the malicious code scan"
  echo "Waiting for the malicious code scan on $HEAD_SHA (${scan_state:-queued})"
  sleep "$SCAN_POLL_SECONDS"
done
# Status URLs are caller-controlled. Require the trusted scan run's artifact to attest the exact
# status ID, PR and head, so pointing a forged status at an old passing run cannot authorize review.
if [[ "$scan_state" == "success" ]]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if ! python3 "$script_dir/../malicious-code-scan/scan_record.py" \
    --workflow "$SCAN_WORKFLOW" --pr "$PR_NUMBER" --head "$HEAD_SHA" --context "$SCAN_CONTEXT" \
    --state success <<< "$scan_status" > /dev/null; then
    skip "the malicious code scan status on $HEAD_SHA has no verified record from a passing $SCAN_WORKFLOW run; run $SCAN_WORKFLOW for PR #$PR_NUMBER from the Actions tab"
  fi
fi
case "$scan_state" in
  success) ;;
  "") skip "the malicious code scan has not reported on $HEAD_SHA; run $SCAN_WORKFLOW for PR #$PR_NUMBER from the Actions tab" ;;
  pending) skip "the malicious code scan was still running on $HEAD_SHA after ${SCAN_WAIT_MINUTES} minute(s); run AI Review by hand once it passes" ;;
  *) skip "the malicious code scan blocked $HEAD_SHA ($scan_state)" ;;
esac

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

# SonarQube reports through its GitHub App as a check run, not an Actions run, so the runs above
# never include it. Wait for its analysis of this commit, then collect what it found on the PR.
# Sonar trouble (no check run, an outage, no checks: read) only leaves its findings out.
sonar_findings=0
sonar_check() {
  gh api "repos/$repo/commits/$HEAD_SHA/check-runs?per_page=100" --paginate \
    --jq ".check_runs[] | select(.app.slug == \"$SONAR_APP\")" | jq -s '.[0] // {}'
}
# The token goes through stdin rather than the command line. Anything but a JSON object fails, so
# the callers' jq cannot stop the gate on an error page.
sonar_api() {
  if [[ -n "${SONAR_TOKEN:-}" ]]; then
    printf 'header = "Authorization: Bearer %s"\n' "$SONAR_TOKEN"
  fi | curl -fsS --max-time 30 -K - "$SONAR_HOST_URL/api/$1" | jq -ce 'objects'
}
if ! sonar="$(sonar_check)"; then
  echo "::warning::Could not read the check runs on $HEAD_SHA (does the workflow have checks: read?); SonarQube findings are left out"
  sonar='{}'
fi
deadline=$((SECONDS + SONAR_WAIT_MINUTES * 60))
while [[ "$(jq -r '.status // "completed"' <<< "$sonar")" != "completed" ]] && (( SECONDS < deadline )); do
  [[ "$(gh api "repos/$repo/pulls/$PR_NUMBER" --jq .head.sha)" == "$HEAD_SHA" ]] ||
    skip "the PR head moved past $HEAD_SHA while waiting for the SonarQube analysis"
  echo "Waiting for the SonarQube analysis on $HEAD_SHA ($(jq -r .status <<< "$sonar"))"
  sleep "$SCAN_POLL_SECONDS"
  sonar="$(sonar_check)" || sonar='{}'
done
sonar_status="$(jq -r '.status // ""' <<< "$sonar")"
if [[ -n "$sonar_status" && "$sonar_status" != "completed" ]]; then
  echo "::warning::The SonarQube analysis of $HEAD_SHA was still $sonar_status after ${SONAR_WAIT_MINUTES} minute(s); its findings are left out"
elif [[ -n "$sonar_status" ]]; then
  project="$SONAR_PROJECT_KEY"
  if [[ -z "$project" ]]; then
    project="$(python3 -c 'import sys, urllib.parse as u; print(u.parse_qs(u.urlsplit(sys.argv[1]).query).get("id", [""])[0])' \
      "$(jq -r '.details_url // ""' <<< "$sonar")")"
  fi
  if [[ ! "$project" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    echo "::warning::No usable SonarQube project key ('$project'); set sonar_project_key. SonarQube findings are left out"
  else
    query="$(jq -rn --arg k "$project" --arg pr "$PR_NUMBER" '"projectKey=\($k | @uri)&pullRequest=\($pr | @uri)"')"
    # Paths come back as <project>:<path>; messages are kept to one line. $project is jq's.
    # shellcheck disable=SC2016
    defs='def loc: (.component | ltrimstr($project + ":")) + (if .line then ":\(.line)" else "" end);
      def text: gsub("[\r\n]+"; " ");'
    if gate="$(sonar_api "qualitygates/project_status?$query")"; then
      failed="$(jq -r '.projectStatus.conditions // [] | .[] | select(.status == "ERROR")
        | "- \(.metricKey) is \(.actualValue) (fails when \(.comparator) \(.errorThreshold))"' <<< "$gate")"
      if [[ -n "$failed" ]]; then
        sonar_findings=$((sonar_findings + $(wc -l <<< "$failed")))
        printf '### Quality gate failed\n\n%s\n\n' "$failed" >> "$SONAR_FILE"
      fi
    else
      echo "::warning::Could not read the SonarQube quality gate for $project PR #$PR_NUMBER"
    fi
    if issues="$(sonar_api "issues/search?${query/projectKey=/componentKeys=}&issueStatuses=OPEN,CONFIRMED&ps=500")"; then
      count="$(jq '.issues | length' <<< "$issues")"
      if (( count > 0 )); then
        sonar_findings=$((sonar_findings + count))
        {
          echo "### Open issues ($(jq '.paging.total // .total // (.issues | length)' <<< "$issues"))"
          echo
          jq -r --arg project "$project" "$defs"' .issues[] | "- **\(.severity // "?")** \(loc): \(.message | text) (rule \(.rule))"' <<< "$issues"
          echo
        } >> "$SONAR_FILE"
      fi
    else
      echo "::warning::Could not read the SonarQube issues for $project PR #$PR_NUMBER"
    fi
    # Listed but not counted: one that is safe needs a human to mark it in SonarQube, which no fix
    # commit can do, so counting it would send every fix round back for another
    if hotspots="$(sonar_api "hotspots/search?$query&status=TO_REVIEW&ps=500")"; then
      if (( $(jq '.hotspots | length' <<< "$hotspots") > 0 )); then
        {
          echo "### Security hotspots to review"
          echo
          jq -r --arg project "$project" "$defs"' .hotspots[] | "- **\(.vulnerabilityProbability // "?")** \(loc): \(.message | text) (rule \(.ruleKey))"' <<< "$hotspots"
          echo
        } >> "$SONAR_FILE"
      fi
    else
      echo "::warning::Could not read the SonarQube security hotspots for $project PR #$PR_NUMBER"
    fi
  fi
fi

# When the head commit is the loop's own fix, only go again to fix CI or SonarQube findings, and only a few times
head_message="$(gh api "repos/$repo/commits/$HEAD_SHA" --jq .commit.message)"
if grep -q '^AI-Review-Bot: true$' <<< "$head_message"; then
  (( failures + sonar_findings > 0 )) || skip "head commit is an AI review fix and CI passed"
  # Count distinct loop runs among the consecutive AI review commits at the tip of the PR
  rounds="$(gh api "repos/$repo/pulls/$PR_NUMBER/commits" --paginate --jq '[.[].commit.message]' | jq -s '
    add | reverse
    | (map(test("(?m)^AI-Review-Bot: true$") | not) | index(true)) as $human
    | (if $human == null then . else .[:$human] end)
    | map(capture("(?m)^AI-Review-Run: (?<id>\\S+)$").id) | unique | length')"
  if (( rounds >= MAX_CI_ROUNDS )); then
    skip "CI or SonarQube still failing after $rounds AI fix round(s) (max $MAX_CI_ROUNDS)"
  fi
fi

echo "PR #$PR_NUMBER at $HEAD_SHA: $total CI run(s) complete, $failures CI failure(s), $sonar_findings SonarQube finding(s)"
output skip false
output pr "$PR_NUMBER"
output author "$(pr_field .user.login)"
output head_sha "$HEAD_SHA"
output head_ref "$(pr_field .head.ref)"
output base_ref "$(pr_field .base.ref)"
output ci_failures "$failures"
output sonar_findings "$sonar_findings"
