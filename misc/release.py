#!/usr/bin/env python3

import re
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from subprocess import run
from typing import NoReturn


def die(msg: str) -> NoReturn:
    print(msg)
    sys.exit(1)


def git_pull() -> None:
    run(["git", "pull"], check=True)


def check_project() -> None:
    p = run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        check=True,
        capture_output=True,
    )
    if p.stdout.decode().strip() != "master":
        die("releases must be cut from master branch!")

    p = run(
        ["git", "diff", "--no-ext-diff", "--quiet", "--exit-code"],
    )
    if p.returncode != 0:
        die("commit your changes first!")


def get_current_version(path: Path) -> str:
    data = path.read_text()
    m = re.search(r'version = "(.+)"', data)
    if not m:
        die("pyproject.toml is broken")
    return m.group(1)


def read_new_version(current: str) -> str:
    print(f"Current version: {current}")
    return input("New version: ")


def bump_version(path: Path, old: str, new: str) -> None:
    content = path.read_text()
    path.write_text(content.replace(old, new))


def commit_bump(path: Path, version: str) -> None:
    run(
        ["git", "commit", "-m", f"chore: Bump v{version} release", str(path)],
        check=True,
    )
    run(
        ["git", "tag", "-a", "-m", f"gallia v{version}", f"v{version}"],
        check=True,
    )


def github_release(version: str) -> None:
    run(["git", "push", "--follow-tags"], check=True)

    cmd = ["gh", "release", "create", "--generate-notes"]
    pre = True if any(x in version.lower() for x in ("a", "b", "rc")) else False
    if pre:
        cmd += ["--prerelease"]
    cmd += [f"v{version}"]

    run(cmd, check=True)


def parse_args() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument("path", type=Path, help="path to pyproject.toml")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    check_project()
    git_pull()

    cur_version = get_current_version(args.path)
    new_version = read_new_version(cur_version)

    bump_version(args.path, cur_version, new_version)
    commit_bump(args.path, new_version)
    github_release(new_version)
    git_pull()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
