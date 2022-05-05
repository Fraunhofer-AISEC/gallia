#!/usr/bin/env python3

import subprocess
from importlib.metadata import entry_points


def check(command: list[str]) -> None:
    print(f"Checking \"{' '.join(command)}\"")
    subprocess.run(command, stdout=subprocess.DEVNULL, check=True)


def main() -> None:
    all_entries = entry_points()

    for entry in all_entries["console_scripts"]:
        if "udscan" in str(entry.module):
            check([entry.name, "-h"])

    for group in ["gallia_scanners", "gallia_scripts"]:
        for entry in all_entries[group]:
            check(["gallia", entry.name, "-h"])


if __name__ == "__main__":
    main()
