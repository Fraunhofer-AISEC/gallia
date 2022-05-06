# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import sys
from importlib.metadata import entry_points

import argcomplete


def main() -> None:
    parser = argparse.ArgumentParser()
    sp = parser.add_subparsers(
        metavar="CHOICE",
    )

    all_entries = entry_points()

    if "_ARGCOMPLETE" in os.environ:
        comp_line = os.environ["COMP_LINE"]
        comp_point = int(os.environ["COMP_POINT"])

        # For completion only the names are required, which results in a noticeably faster response
        # compared to the full loading process, which is necessary for the help
        for group in ("gallia_scanners", "gallia_scripts"):
            for entry in all_entries[group]:
                _parser = sp.add_parser(entry.name)

        if len(comp_line.lstrip().split(" ")) < 3:
            argcomplete.autocomplete(parser)
        else:
            entry_prefix_length = comp_line.find(" ") + 1

            os.environ["COMP_LINE"] = comp_line[entry_prefix_length:]
            os.environ["COMP_POINT"] = str(comp_point - entry_prefix_length)

            chosen_entry = comp_line.split()[1]

            try:
                entry_point = next(
                    i.load()
                    for i in all_entries["gallia_scanners"]
                    if i.name == chosen_entry
                )
                sys.exit(entry_point().run())
            except StopIteration:
                try:
                    entry_point = next(
                        i.load()
                        for i in all_entries["gallia_scripts"]
                        if i.name == chosen_entry
                    )
                    sys.exit(entry_point())
                except StopIteration:
                    pass
    else:
        if "gallia_scanners" in all_entries:
            for entry in all_entries["gallia_scanners"]:
                scanner_class = entry.load()

                _parser = sp.add_parser(
                    entry.name,
                    help=scanner_class.__doc__,
                )
                _parser.set_defaults(func=scanner_class().run)

        if "gallia_scripts" in all_entries:
            for entry in all_entries["gallia_scripts"]:
                entry_point = entry.load()

                _parser = sp.add_parser(
                    entry.name,
                    help=entry_point.__doc__,
                )
                _parser.set_defaults(func=entry_point)

        # Only pass a single argument to the args parser, otherwise it gets confused
        # with arguments belonging to one of the subparsers.
        if len(sys.argv) < 2:
            parser.print_help()
            parser.exit()

        args = parser.parse_args([sys.argv[1]])

        # Combine the first two arguments for subsequent parsers to work correctly
        sys.argv[0] += f" {sys.argv[1]}"
        sys.argv.pop(1)

        if not hasattr(args, "func"):
            parser.print_help()
            parser.exit()
        sys.exit(args.func())
