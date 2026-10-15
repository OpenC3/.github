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

# Scans the PR the gate let through for obfuscated code, prompt injection, and other malicious
# changes (malicious-code-scan/malicious_code_scan.py) before any agent sees it. Run from a
# checkout of the PR's base branch: the PR's commits are fetched into it and read with git diff as
# data, never checked out or run.
#
# Blocking findings stop the review: the PR's AI review comment says so (with a marker the gate
# reads, so later CI completions do not pay for the same scan again) and the step fails. A
# maintainer (write access or above) accepts them by adding the `malicious-scan-override` label
# after that comment, then running AI Review by hand. A label added before the comment covers an
# earlier commit, not this one, and is removed.
#
# Required env: GH_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, HEAD_SHA, SCANNER (path to the scanner)
# Optional env: ANTHROPIC_API_KEY and the scanner's SCAN_* settings, GITHUB_SERVER_URL,
#               GITHUB_RUN_ID, GITHUB_STEP_SUMMARY, RUNNER_TEMP
#
# Step outputs: passed (true only when the review may go ahead), stale (the PR head moved on)

set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
: "${PR_NUMBER:?}"
: "${HEAD_SHA:?}"
: "${SCANNER:?}"

OVERRIDE_LABEL="malicious-scan-override"
REVIEW_MARKER="<!-- ai-adversarial-review -->"
BLOCKED_MARKER="<!-- ai-review-scan-blocked: $HEAD_SHA -->"
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-https://github.com}"
repo="$GITHUB_REPOSITORY"
run_url="${GITHUB_SERVER_URL}/${repo}/actions/runs/${GITHUB_RUN_ID:-}"

output() { echo "$1=$2" >> "$GITHUB_OUTPUT"; }
stale() {
  echo "::notice::The PR head moved past $HEAD_SHA; the new commit gets its own review"
  output passed false
  output stale true
  exit 0
}

pr="$(gh api "repos/$repo/pulls/$PR_NUMBER")"
[[ "$(jq -r .head.sha <<< "$pr")" == "$HEAD_SHA" ]] || stale
base="$(jq -r .base.sha <<< "$pr")"
if [[ ! "$base" =~ ^[0-9a-f]{40,64}$ ]]; then
  echo "::error::Could not read the base commit of PR #$PR_NUMBER"
  exit 1
fi

# The checkout kept no credentials, and a private repository needs them; pass the token to this
# fetch only
auth="$(printf 'x-access-token:%s' "${GH_TOKEN:-}" | base64 | tr -d '\n')"
echo "::add-mask::$auth"
git -c "http.${GITHUB_SERVER_URL}/.extraheader=AUTHORIZATION: basic ${auth}" \
  fetch -q --no-tags --no-recurse-submodules origin "+refs/pull/${PR_NUMBER}/head:refs/remotes/pr/head"
[[ "$(git rev-parse refs/remotes/pr/head)" == "$HEAD_SHA" ]] || stale

# Attacker-controlled, so passed through env and never interpolated into a command. jq -j and the x
# sentinel keep trailing newlines.
PR_TITLE="$(jq -j '.title' <<< "$pr"; printf x)"
PR_TITLE="${PR_TITLE%x}"
PR_BODY="$(jq -j '.body // ""' <<< "$pr"; printf x)"
PR_BODY="${PR_BODY%x}"
export PR_TITLE PR_BODY

# A scanner error fails this step, which is not a pass
scan_output="$(mktemp)"
trap 'rm -f "$scan_output"' EXIT
GITHUB_OUTPUT="$scan_output" uv run --script --locked --no-build "$SCANNER" \
  --base "$base" --head "$HEAD_SHA" --summary "${GITHUB_STEP_SUMMARY:-/dev/null}" \
  --json "${RUNNER_TEMP:-/tmp}/malicious_scan.json"
blocking="$(sed -n 's/^blocking=//p' "$scan_output")"
warnings="$(sed -n 's/^warnings=//p' "$scan_output")"
if [[ ! "$blocking" =~ ^[0-9]+$ ]]; then
  echo "::error::The scanner did not report its result"
  exit 1
fi

if (( blocking == 0 )); then
  echo "Malicious code scan of $HEAD_SHA: no blocking findings (${warnings:-0} warning(s))"
  output passed true
  exit 0
fi

# The review summary comment, which only this workflow writes
summary_comment="$(gh api "repos/$repo/issues/$PR_NUMBER/comments" --paginate \
  --jq ".[] | select(.user.login == \"github-actions[bot]\" and .user.type == \"Bot\")
    | select(.body | startswith(\"$REVIEW_MARKER\")) | {id, updated_at, body}" | jq -s 'last // {}')"

# An override counts only if a maintainer added the label after this commit was reported blocked,
# so a label meant for an earlier commit cannot pass one pushed after it
rejected=""
if jq -e --arg label "$OVERRIDE_LABEL" 'any(.labels[]; .name == $label)' <<< "$pr" > /dev/null; then
  labeled="$(gh api "repos/$repo/issues/$PR_NUMBER/events" --paginate \
    --jq ".[] | select(.event == \"labeled\" and .label.name == \"$OVERRIDE_LABEL\") | {actor: .actor.login, created_at}" |
    jq -s 'last // {}')"
  sender="$(jq -r '.actor // ""' <<< "$labeled")"
  label_time="$(jq -r '.created_at // ""' <<< "$labeled")"
  blocked_time=""
  if jq -e --arg marker "$BLOCKED_MARKER" '.body // "" | contains($marker)' <<< "$summary_comment" > /dev/null; then
    blocked_time="$(jq -r '.updated_at // ""' <<< "$summary_comment")"
  fi
  # Labels only need triage access; accepting a security finding needs write. Fails closed if the
  # permission cannot be read.
  permission=""
  if [[ "$sender" =~ ^[A-Za-z0-9-]+(\[bot\])?$ ]]; then
    permission="$(gh api "repos/$repo/collaborators/$sender/permission" --jq .permission 2> /dev/null || true)"
  fi
  time_re='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
  if [[ "$permission" != "admin" && "$permission" != "write" ]]; then
    rejected="the \`$OVERRIDE_LABEL\` label was added by @${sender:-unknown}, who does not have write access"
  elif [[ ! "$label_time" =~ $time_re || ! "$blocked_time" =~ $time_re || ! "$label_time" > "$blocked_time" ]]; then
    rejected="the \`$OVERRIDE_LABEL\` label was added before ${HEAD_SHA:0:7} was reported blocked"
  else
    echo "::notice::Malicious code scan: ${blocking} blocking finding(s) on $HEAD_SHA accepted by @$sender"
    echo "Override by @$sender: ${blocking} blocking finding(s) accepted" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
    output passed true
    exit 0
  fi
  gh api -X DELETE "repos/$repo/issues/$PR_NUMBER/labels/$OVERRIDE_LABEL" > /dev/null || true
fi

body="${REVIEW_MARKER}
${BLOCKED_MARKER}
## Adversarial AI Review

The malicious code scan found ${blocking} blocking finding(s) in ${HEAD_SHA}, so the AI review did not run. The findings are in the [scan report](${run_url}).

If they are safe, a maintainer with write access can add the \`${OVERRIDE_LABEL}\` label and then run AI Review for #${PR_NUMBER} from the Actions tab. A new push is scanned again."
if [[ -n "$rejected" ]]; then
  body+=$'\n\n'"The override was not accepted: ${rejected}. Add the label again to accept these findings."
fi
comment_id="$(jq -r '.id // ""' <<< "$summary_comment")"
if [[ -n "$comment_id" ]]; then
  gh api -X PATCH "repos/$repo/issues/comments/$comment_id" -f body="$body" > /dev/null
else
  gh api -X POST "repos/$repo/issues/$PR_NUMBER/comments" -f body="$body" > /dev/null
fi
output passed false
echo "::error::Malicious code scan: ${blocking} blocking finding(s) on $HEAD_SHA${rejected:+; override rejected: $rejected}"
exit 1
