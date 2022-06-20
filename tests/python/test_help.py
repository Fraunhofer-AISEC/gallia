# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# mypy: allow-untyped-defs

import subprocess
from importlib.metadata import entry_points


def check(command: list[str]) -> None:
    print(f"Checking \"{' '.join(command)}\"")
    subprocess.run(command, stdout=subprocess.DEVNULL, check=True)


def test_help() -> None:
    all_entries = entry_points()
    check(["gallia", "-h"])

    # for some reason, the entry points appear multiple times; thus we use a set to reduce them
    scripts = set(
        map(
            lambda x: x.name,
            filter(lambda x: "gallia" in str(x.module), all_entries["console_scripts"]),
        )
    )
    for entry in scripts:
        check([entry, "-h"])

    for group in ["gallia_scanners"]:
        for entry in all_entries[group]:
            check(["gallia", entry.name, "-h"])
