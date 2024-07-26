# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0


import sys
from typing import Any

import argcomplete
from pydantic import Field, create_model
from pydantic_argparse import ArgumentParser, BaseCommand

from gallia.config import load_config_file
from gallia.log import Loglevel, setup_logging
from gallia.plugins.plugin import Command, CommandTree, load_commands

setup_logging(Loglevel.DEBUG)

config, _ = load_config_file()
gallia_tree_model_counter = 0
extra_defaults = {}


def create_parser_from_command_tree(command_tree: CommandTree) -> type[BaseCommand]:
    global gallia_tree_model_counter
    gallia_tree_model_counter += 1
    args: dict[str, tuple[type, Field]] = {}

    for key, value in command_tree.subtree.items():
        if isinstance(value, Command):
            args[key] = (value.config | None, Field(None, description=value.description))
            config_attributes = value.config.attributes_from_config(config)
            env_attributes = value.config.attributes_from_env()
            config_attributes.update(env_attributes)
            extra_defaults[value.config] = config_attributes
            setattr(value.config, "_class", value.command)
        else:
            model_type = create_parser_from_command_tree(value)
            args[key] = (model_type | None, Field(None, description=value.description))

    return create_model(
        f"gallia_tree_model_{gallia_tree_model_counter}", __base__=BaseCommand, **args
    )


def create_plugin_parser() -> tuple[type[BaseCommand], dict[type, dict[str, Any]]]:
    gallia_commands = CommandTree("gallia", load_commands())

    return create_parser_from_command_tree(gallia_commands), extra_defaults


def main() -> None:
    model, extra_defaults = create_plugin_parser()
    parser = ArgumentParser(model=model, extra_defaults=extra_defaults)
    argcomplete.autocomplete(parser)
    _, config = parser.parse_typed_args()
    sys.exit(config._class(config).entry_point())


if __name__ == "__main__":
    main()
