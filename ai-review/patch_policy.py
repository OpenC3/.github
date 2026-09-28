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

"""Decide whether a set of AI review changes may be published.

The review loop runs this after every turn to discard a turn early, and the publish job runs it
again on the fix commits it is about to push. The publish job's check is the one that counts: it
runs on a fresh runner that no agent touched, so it holds even if an agent escaped its sandbox.

Usage: patch_policy.py <base> [<head>]   (without <head>, checks the staged changes)
Prints why the changes are refused and exits 1, or exits 0 if they may be published.
Standard library only.
"""

from __future__ import annotations

import re
import subprocess
import sys


# Files that steer the agents or this review, in the reviewed repository or in OpenC3/.github
# itself; the next agent would load them. Keep in sync with PROTECTED_PATHS in
# malicious_code_scan.py (tests/test_ai_review.py checks).
AGENT_CONFIG_PATHS = [
    r"(^|/)CLAUDE(\.local)?\.md$",
    r"(^|/)AGENTS(\.override)?\.md$",
    r"(^|/)\.claude/",
    r"(^|/)\.codex/",
    r"(^|/)\.cursor/",
    r"(^|/)\.mcp\.json$",
    r"^\.github/copilot-instructions\.md$",
    r"^(ai-review|malicious-code-scan)/",
    r"^\.github/workflows/(ai[-_]review|malicious[-_]code[-_]scan)(-reusable|-run)?\.ya?ml$",
]
AGENT_CONFIG_RE = [re.compile(p) for p in AGENT_CONFIG_PATHS]
# Workflows and actions run with secrets on the next CI run; agents report needed changes instead
CI_CONFIG_RE = re.compile(r"^\.github/(workflows|actions)/")
# Symlinks and submodules can point CI at files outside the change; a human adds those
LINK_MODES = {"120000", "160000"}


def changes(base: str, head: str | None) -> list[tuple[str, str, str]]:
    """(old mode, new mode, path) for each changed path, from git's raw diff."""
    args = ["git", "-c", "core.quotePath=false", "diff", "--raw", "-z", "--no-renames", "--no-ext-diff"]
    args += [base, head] if head else ["--cached", base]
    fields = subprocess.run(args, capture_output=True, check=True).stdout.decode("utf-8", "replace")
    fields = fields.split("\0")
    result = []
    # Each entry is ":<old mode> <new mode> <old sha> <new sha> <status>" then its path
    for header, path in zip(fields[0::2], fields[1::2], strict=False):
        if header.startswith(":"):
            old_mode, new_mode = header[1:].split(" ")[:2]
            result.append((old_mode, new_mode, path))
    return result


def violation(old_mode: str, new_mode: str, path: str) -> str | None:
    """Why this change may not be published, or None."""
    if any(r.search(path) for r in AGENT_CONFIG_RE):
        return f"it changed files that configure the AI agents or this review ({path})"
    if CI_CONFIG_RE.search(path):
        return f"it changed CI workflows or actions ({path})"
    if old_mode in LINK_MODES or new_mode in LINK_MODES or re.search(r"(^|/)\.gitmodules$", path):
        return f"it changed a symlink or submodule ({path})"
    return None


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    for old_mode, new_mode, path in changes(argv[1], argv[2] if len(argv) == 3 else None):
        reason = violation(old_mode, new_mode, path)
        if reason:
            print(reason)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
