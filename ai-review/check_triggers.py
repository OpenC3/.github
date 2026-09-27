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

"""Warn when the AI Review caller misses a workflow that runs on pull_request.

The review starts when a listed CI workflow completes and every CI run has
finished, so a workflow left out of the caller's workflow_run list that happens
to finish last means the review never starts. Standard library only; the YAML
is matched line by line, which covers how workflows in OpenC3 repositories are
written.

Usage: check_triggers.py <workflows dir> <caller workflow file name>
Prints a GitHub warning annotation per missing workflow and exits 0 either way.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# Built-in workflows that may appear in a caller's list without a file in the repository
BUILTIN = {"CodeQL"}


def workflow_name(text: str, path: Path) -> str:
    match = re.search(r"^name:\s*['\"]?(.+?)['\"]?\s*$", text, re.M)
    # GitHub names an unnamed workflow after its path
    return match.group(1) if match else f".github/workflows/{path.name}"


def on_block(text: str) -> str:
    match = re.search(r"^(?:on|['\"]on['\"]):(.*?)(?=^\S|\Z)", text, re.M | re.S)
    return match.group(1) if match else ""


def runs_on_pull_request(text: str) -> bool:
    block = on_block(text)
    # `on: pull_request`, `on: [push, pull_request]`, or a `pull_request:` key; not pull_request_target
    return bool(re.search(r"^\s*(\[[^]]*)?\bpull_request\b(?!_)", block, re.M))


def listed_workflows(text: str) -> set[str]:
    lines = on_block(text).splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"\s*workflows:\s*(\[.*\])?\s*(#.*)?$", line)
        if not match:
            continue
        if match.group(1):
            items = match.group(1)[1:-1].split(",")
        else:
            items = []
            for item in lines[index + 1 :]:
                if item.strip().startswith("#"):
                    continue
                dash = re.match(r"\s*-\s*(.+)$", item)
                if not dash:
                    break
                items.append(dash.group(1))
        return {item.split(" #", 1)[0].strip().strip("'\"") for item in items if item.strip()}
    return set()


def missing_triggers(workflows_dir: Path, caller: str) -> tuple[set[str], set[str]]:
    """Return (pull_request workflows the caller does not list, listed names that match no workflow)."""
    triggered = set()
    names = set()
    listed: set[str] = set()
    for path in sorted([*workflows_dir.glob("*.yml"), *workflows_dir.glob("*.yaml")]):
        text = path.read_text(encoding="utf-8")
        name = workflow_name(text, path)
        names.add(name)
        if path.name == caller:
            listed = listed_workflows(text)
        elif runs_on_pull_request(text):
            triggered.add(name)
    return triggered - listed, listed - names - BUILTIN


def main() -> int:
    workflows_dir, caller = Path(sys.argv[1]), sys.argv[2]
    if not (workflows_dir / caller).is_file():
        print(f"::notice::{caller} is not in {workflows_dir}; not checking the workflow_run list")
        return 0
    missing, unknown = missing_triggers(workflows_dir, caller)
    for name in sorted(missing):
        print(
            f"::warning file=.github/workflows/{caller}::'{name}' runs on pull_request but is not in this "
            "workflow's workflow_run list; if it finishes last, the AI review never starts"
        )
    for name in sorted(unknown):
        print(f"::warning file=.github/workflows/{caller}::'{name}' is listed but no workflow has that name")
    if not missing and not unknown:
        print("The workflow_run list covers every pull_request workflow")
    return 0


if __name__ == "__main__":
    sys.exit(main())
