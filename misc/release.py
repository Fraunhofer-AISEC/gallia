#!/usr/bin/env python3

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import ArgumentParser, Namespace
from enum import Enum, unique
from subprocess import run
from typing import Any, NoReturn


DRY_RUN = False


@unique
class BumpMode(Enum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


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

    if mode == BumpMode.PATCH or mode == BumpMode.MINOR:
        if not current_branch.endswith("-maint"):
            die("minor or patch releases must be cut from master branch!")
    elif mode == BumpMode.MAJOR:
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


def github_release(version: str) -> None:
    run_wrapper(["git", "push", "--follow-tags"], check=True)

    cmd = ["gh", "release", "create", "--generate-notes"]
    pre = True if any(x in version.lower() for x in ("a", "b", "rc")) else False
    if pre:
        cmd += ["--prerelease"]
    cmd += [f"v{version}"]

    run_wrapper(cmd, check=True)


def parse_args() -> Namespace:
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="dry run, do not change anything",
    )
    group.add_argument(
        "-M",
        "--major",
        action="store_true",
        help="bump to next major version",
    )
    group.add_argument(
        "-m",
        "--minor",
        action="store_true",
        help="bump to next minor version",
    )
    group.add_argument(
        "-p",
        "--patch",
        action="store_true",
        help="bump to next patch version",
    )
    args = parser.parse_args()
    if args.patch is False and args.minor is False and args.major is False:
        parser.error("please set -M, -m, or -p!")
    return args


def main() -> None:
    args = parse_args()
    if args.dry_run:
        global DRY_RUN
        DRY_RUN = True

    if args.patch is True:
        mode = BumpMode.PATCH
    elif args.patch is True:
        mode = BumpMode.MINOR
    elif args.patch is True:
        mode = BumpMode.MAJOR

    check_project(mode)
    git_pull()

    bump_version(mode)
    new_version = get_current_version()

    commit_bump(new_version)
    github_release(new_version)
    git_pull()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
