#!/usr/bin/env python3

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import subprocess
from typing import Any
from urllib.parse import quote, urljoin


class CLIWrapper:
    def __init__(self, repo_id: str, pr: int) -> None:
        self.repo_id = repo_id
        self.repo = repo_id.split("/", maxsplit=1)[1]
        self.user = repo_id.split("/", maxsplit=1)[0]
        self.repo_api_base = f"/repos/{self.repo_id}/"
        self.pr = pr

    @staticmethod
    def call_gh_api(endpoint: str) -> Any:
        try:
            p = subprocess.run(
                [
                    "gh",
                    "api",
                    "-H",
                    "Accept: application/vnd.github+json",
                    "-H",
                    "X-GitHub-Api-Version: 2022-11-28",
                    endpoint,
                ],
                check=True,
                capture_output=True,
            )
            return json.loads(p.stdout)
        except subprocess.CalledProcessError as e:
            print(f"{endpoint=}")
            print(f"stdout={e.stdout.decode()}")
            print(f"stderr={e.stderr.decode()}")
            raise

    def get_files(self) -> list[str]:
        raw_resp = self.call_gh_api(urljoin(self.repo_api_base, f"pulls/{self.pr}/files"))
        return [r["filename"] for r in raw_resp if "filename" in r]

    def get_mr_sha(self) -> str:
        raw_resp = self.call_gh_api(urljoin(self.repo_api_base, f"pulls/{self.pr}"))
        return raw_resp["merge_commit_sha"]

    def get_authors(self, file: str) -> list[str]:
        raw_resp = self.call_gh_api(
            urljoin(self.repo_api_base, f"commits?path={quote(file)}&sha{self.get_mr_sha()}")
        )
        authors = []
        for commit in raw_resp:
            if "author" not in commit:
                continue
            if isinstance(commit["author"], dict) and "login" not in commit["author"]:
                continue

            author = commit["author"]["login"]
            if "[bot]" in author:
                continue
            authors.append(author)
        return authors

    def get_team_members(self, team: str) -> list[str]:
        raw_resp = self.call_gh_api(f"/orgs/{self.user}/teams/{team}/members")
        return [r["login"] for r in raw_resp if "login" in r]

    def get_mr_author(self) -> str:
        raw_resp = self.call_gh_api(urljoin(self.repo_api_base, f"pulls/{self.pr}"))
        return raw_resp["user"]["login"]

    def add_reviewer(self, reviewer: str) -> None:
        subprocess.run(
            ["gh", "-R", self.repo_id, "pr", "edit", str(self.pr), "--add-reviewer", reviewer],
            check=True,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="Repo name in the form user/repo or org/repo")
    parser.add_argument("--pr-id", type=int, required=True, help="Pull request ID")
    parser.add_argument(
        "--author-limit",
        type=int,
        help="Limit to this number of authors",
        default=3,
    )
    mgroup = parser.add_mutually_exclusive_group()
    mgroup.add_argument("--team", help="Optional team in orgas")
    mgroup.add_argument("--team-members", nargs="*", help="Team member list")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cli = CLIWrapper(args.repo, args.pr_id)

    print("Querying authors of touched files…")
    all_authors_set = set()
    for file in cli.get_files():
        for author in cli.get_authors(file):
            all_authors_set.add(author)

    all_authors = list(all_authors_set)

    print(f"Found authors: {all_authors}")
    print(f"Limiting to {args.author_limit} authors…")
    all_authors = all_authors[: args.author_limit]

    if args.team is not None:
        team_members = cli.get_team_members(args.team)
    elif args.team_members is not None:
        team_members: list[str] = args.team_members
    else:
        team_members = []

    print(f"Found team members: {team_members}")

    pr_author = cli.get_mr_author()
    for author in all_authors:
        if team_members and author not in team_members:
            print(f"Skipping {author}: no team member")
            continue

        if author != pr_author:
            print(f"Assigning reviewer: {author}")
            cli.add_reviewer(author)


if __name__ == "__main__":
    main()
