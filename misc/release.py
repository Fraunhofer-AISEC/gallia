#!/usr/bin/env python3

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import ArgumentParser, Namespace
from enum import Enum, unique, auto
from subprocess import run
from typing import Any, NoReturn


DRY_RUN = False


@unique
class BumpMode(Enum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    PREPATCH = "prepatch"
    PREMINOR = "preminor"
    PREMAJOR = "premajor"


@unique
class ReleaseNotes(Enum):
    INTERACTIVE = auto()
    GENERATE = auto()


def die(msg: str) -> NoReturn:
    print(msg)
    sys.exit(1)


def run_wrapper(*args: Any, **kwargs: Any) -> Any:
    if DRY_RUN:
        return print(f"would run: {args} {kwargs}")
    return run(*args, **kwargs)


def git_pull() -> None:
    run_wrapper(["git", "pull"], check=True)


def check_project(mode: BumpMode) -> None:
    p = run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        check=True,
        capture_output=True,
    )
    current_branch = p.stdout.decode().strip()

    if mode == BumpMode.PATCH or mode == BumpMode.PREPATCH:
        if not current_branch.endswith("-maint"):
            die("minor or patch releases must be cut from maintenance branch!")
    elif (
        mode == BumpMode.MAJOR
        or mode == BumpMode.PREMAJOR
        or mode == BumpMode.MINOR
        or mode == BumpMode.PREMINOR
    ):
        if current_branch != "master":
            die("major releases must be cut from master branch!")

    p = run(
        ["git", "diff", "--no-ext-diff", "--quiet", "--exit-code"],
    )
    if p.returncode != 0:
        die("commit your changes first!")


def get_current_version() -> str:
    p = run(["poetry", "version"], check=True, capture_output=True)
    version_str = p.stdout.decode().strip()
    return version_str.split(" ", 2)[1]


def bump_version(mode: BumpMode) -> None:
    if DRY_RUN:
        return print(f"would bump: {mode}")
    run(["poetry", "version", mode.value])


def commit_bump(version: str) -> None:
    run_wrapper(
        ["git", "commit", "-a", "-m", f"chore: Bump v{version} release"],
        check=True,
    )
    run_wrapper(
        ["git", "tag", "-a", "-m", f"gallia v{version}", f"v{version}"],
        check=True,
    )


def github_release(version: str, mode: BumpMode, notes: ReleaseNotes) -> None:
    run_wrapper(["git", "push", "--follow-tags"], check=True)

    cmd = ["gh", "release", "create"]
    if notes == ReleaseNotes.GENERATE:
        cmd += ["--generate-notes"]
    if mode.value.startswith("pre"):
        cmd += ["--prerelease"]
    cmd += [f"v{version}"]

    run_wrapper(cmd, check=True)


def parse_args() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="dry run, do not change anything",
    )
    parser.add_argument(
        "-g",
        "--generate-notes",
        action="store_true",
        help="auto generate release notes",
    )
    parser.add_argument(
        "RULE",
        choices=list(map(lambda x: x.value, list(BumpMode))),
        help="bumprule for the next version",
    )
    args = parser.parse_args()
    return args


def main() -> None:
    args = parse_args()
    if args.dry_run:
        global DRY_RUN
        DRY_RUN = True

    rule = BumpMode(args.RULE)
    notes = ReleaseNotes.GENERATE if args.generate_notes else ReleaseNotes.INTERACTIVE

    check_project(rule)
    git_pull()

    bump_version(rule)
    new_version = get_current_version()

    commit_bump(new_version)
    github_release(new_version, rule, notes)
    git_pull()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
