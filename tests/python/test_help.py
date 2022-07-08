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
    check(["gallia", "-h"])

    all_entries = entry_points()
    for entry in all_entries["console_scripts"]:
        if (e := entry.name).startswith("gallia_"):
            check([e, "-h"])
