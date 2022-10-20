#!/usr/bin/env python3
import argparse
import sys

from argparse import Namespace
from gallia.config import load_config_file
from gallia.command import Script


class MyFanyCommand(Script):
    COMMAND = "MyFanyCommand"
    LOGGER_NAME = "MyFanyCommand"

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--foo",
            type=str,
            default=self.get_config_value("MyFanyCommand.foo", None),
        )

    def main(self, args: Namespace) -> None:
        print("main")


def main() -> None:
    config, _ = load_config_file()

    parser = argparse.ArgumentParser()
    runner = MyFanyCommand(parser, config)
    sys.exit(runner.entry_point(parser.parse_args()))


if __name__ == "__main__":
    main()
