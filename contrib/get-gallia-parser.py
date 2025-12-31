import argparse
import sys
from collections.abc import Sequence
from typing import Any

from gallia.cli.gallia import (
    create_parser,
    load_commands,
    show_config,
    show_plugins,
    template,
    version,
)


def get_parser() -> argparse.ArgumentParser:
    parser = create_parser(load_commands())

    top_level_options = {
        "--version": (version, "show version and exit"),
        "--show-plugins": (show_plugins, "show registered plugins"),
        "--show-config": (show_config, "show loaded config"),
        "--template": (template, "generate a annotated config template"),
    }

    for name, (func, help_) in top_level_options.items():

        class Action(argparse.Action):
            cmd = staticmethod(func)

            def __call__(
                self,
                parser: argparse.ArgumentParser,
                namespace: argparse.Namespace,
                values: str | Sequence[Any] | None,
                option_string: str | None = None,
            ) -> None:
                self.cmd()
                sys.exit(0)

        parser.add_argument(
            name,
            nargs=0,
            action=Action,
            help=help_,
        )
    return parser
