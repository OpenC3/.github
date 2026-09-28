# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE.md for more details.
#
# This file may also be used under the terms of a commercial license
# if purchased from OpenC3, Inc.

"""Authenticate a scan status against the record uploaded by its trusted workflow run.

Status writers choose target_url and description themselves. Neither proves who posted a status.
The scan therefore uploads an immutable artifact containing the ID GitHub assigned to its status,
along with the repository, PR, head, and result. An unrelated workflow cannot upload artifacts into
that run. Missing/expired records fail closed; rerun the scan to produce a new one.

A trusted run is one of the scan workflow on pull_request_target, or on workflow_dispatch from a
commit of the default branch (dispatched from any other ref, the caller workflow could be the PR's).

Reads one status JSON object from stdin and prints its description only after verification.
Uses gh for authentication and downloads; archive contents are read in memory, never extracted.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import zipfile


def api(path: str, *options: str) -> bytes:
    return subprocess.run(["gh", "api", path, *options], capture_output=True, check=True).stdout


def trusted_run(run: dict, args: argparse.Namespace) -> bool:
    if run.get("name") != args.workflow:
        return False
    if run.get("event") == "pull_request_target":
        return True
    if run.get("event") != "workflow_dispatch":
        return False
    default_branch = json.loads(api(f"repos/{args.repository}"))["default_branch"]
    head = run.get("head_sha") or ""
    if run.get("head_branch") != default_branch or not re.fullmatch(r"[0-9a-f]{40,64}", head):
        return False
    # head_branch alone could be a tag of the same name; the commit itself must be on the branch
    status = api(f"repos/{args.repository}/compare/{head}...{default_branch}", "--jq", ".status")
    return status.decode().strip() in ("ahead", "identical")


def verified_description(status: dict, args: argparse.Namespace) -> str:
    if status.get("state") != args.state or status.get("context") != args.context:
        raise ValueError("unexpected status state or context")
    status_id = status["id"]
    if type(status_id) is not int or status_id <= 0:
        raise ValueError("invalid status ID")
    prefix = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{args.repository}/actions/runs/"
    url = status.get("target_url") or ""
    if not url.startswith(prefix) or not re.fullmatch(r"[0-9]+", url[len(prefix) :]):
        raise ValueError("status does not link to a scan run")
    run_id = int(url[len(prefix) :])
    run_path = f"repos/{args.repository}/actions/runs/{run_id}"
    run = json.loads(api(run_path))
    if not trusted_run(run, args):
        raise ValueError("status does not link to the trusted scan workflow")

    name = f"malicious-scan-status-{status_id}"
    pages = json.loads(api(f"{run_path}/artifacts?per_page=100", "--paginate", "--slurp"))
    artifacts = [a for page in pages for a in page["artifacts"] if a["name"] == name and not a["expired"]]
    if len(artifacts) != 1:
        raise ValueError("scan status has no unique, unexpired record")
    artifact = artifacts[0]
    if type(artifact["id"]) is not int or artifact["workflow_run"]["id"] != run_id:
        raise ValueError("record belongs to another run")
    archive = api(f"repos/{args.repository}/actions/artifacts/{artifact['id']}/zip")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        if zipped.namelist() != ["malicious-scan-record.json"]:
            raise ValueError("unexpected scan record archive")
        if zipped.getinfo("malicious-scan-record.json").file_size > 65536:
            raise ValueError("scan record is too large")
        record = json.loads(zipped.read("malicious-scan-record.json"))
    expected = {
        "version": 1,
        "repository": args.repository,
        "pr": args.pr,
        "head_sha": args.head,
        "run_id": run_id,
        "status_id": status_id,
        "state": args.state,
        "context": args.context,
        "description": status.get("description"),
        "created_at": status.get("created_at"),
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise ValueError("scan record does not match this status, PR, and commit")
    attempt = record["run_attempt"]
    if type(attempt) is not int or attempt < 1:
        raise ValueError("invalid scan attempt")
    # A later rerun must not change the provenance or conclusion of an earlier status.
    if attempt != run["run_attempt"]:
        run = json.loads(api(f"{run_path}/attempts/{attempt}"))
        if not trusted_run(run, args):
            raise ValueError("untrusted scan attempt")
    if run.get("conclusion") != args.state:
        raise ValueError("scan attempt has not concluded with the reported result")
    return record["description"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"), required=False)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--head", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--state", required=True, choices=("success", "failure"))
    args = parser.parse_args()
    try:
        description = verified_description(json.load(sys.stdin), args)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.CalledProcessError,
        zipfile.BadZipFile,
    ) as e:
        print(f"Unverified scan status: {e}", file=sys.stderr)
        return 1
    print(description)
    return 0


if __name__ == "__main__":
    sys.exit(main())
