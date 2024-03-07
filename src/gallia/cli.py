# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0


import importlib
import sys
from dataclasses import dataclass
from typing import Any

import argcomplete
from pydantic import Field
from pydantic_argparse import ArgumentParser, BaseCommand

from gallia.config import load_config_file
from gallia.log import Loglevel, setup_logging

setup_logging(Loglevel.DEBUG)

from gallia.configs.rdbi_config import ReadByIdentifierPrimitiveConfig
from gallia.configs.wdbi_config import WriteByIdentifierPrimitiveConfig

config, _ = load_config_file()


@dataclass
class Import:
    module: str
    class_name: str

    def get_class(self):
        return getattr(importlib.import_module(self.module), self.class_name)


# Mockup
def create_parser_tree() -> tuple[type[BaseCommand], dict[type, dict[str, Any]]]:
    setattr(
        ReadByIdentifierPrimitiveConfig,
        "_class_import",
        Import("gallia.configs.rdbi", "ReadByIdentifierPrimitive"),
    )
    setattr(
        WriteByIdentifierPrimitiveConfig,
        "_class_import",
        Import("gallia.configs.wdbi", "WriteByIdentifierPrimitive"),
    )

    extra_defaults = {}

    for cls in [ReadByIdentifierPrimitiveConfig, WriteByIdentifierPrimitiveConfig]:
        config_attributes = cls.attributes_from_config(config)
        env_attributes = cls.attributes_from_env()
        config_attributes.update(env_attributes)
        extra_defaults[cls] = config_attributes

    class Primitive(BaseCommand):
        rdbi: ReadByIdentifierPrimitiveConfig | None = Field(
            None,
            description="Read data at a specific ID using the UDS service RDBI (0x22)",
        )
        wdbi: WriteByIdentifierPrimitiveConfig | None = Field(
            None,
            description="Write data at a specific ID using the UDS service WDBI (0x2e)",
        )
        # iocbi: ...
        # ...

    class Gallia(BaseCommand):
        primitive: Primitive | None = Field(None, description="Simple UDS scripts")
        # scan
        # discover
        # ...

    return Gallia, extra_defaults


def main() -> None:
    model, extra_defaults = create_parser_tree()
    parser = ArgumentParser(model=model, extra_defaults=extra_defaults)
    argcomplete.autocomplete(parser)
    _, config = parser.parse_typed_args()
    sys.exit(config._class_import.get_class()(config).entry_point())


if __name__ == "__main__":
    main()
