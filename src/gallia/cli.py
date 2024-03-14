# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0


import sys
from typing import Any

import argcomplete
from pydantic import Field
from pydantic_argparse import ArgumentParser, BaseCommand

from gallia.config import load_config_file
from gallia.log import Loglevel, setup_logging

from gallia.commands.primitive.uds.rdbi import ReadByIdentifierPrimitive, ReadByIdentifierPrimitiveConfig
from gallia.commands.primitive.uds.wdbi import WriteByIdentifierPrimitive, WriteByIdentifierPrimitiveConfig
from gallia.commands.primitive.uds.dtc import DTCPrimitive, ReadDTCPrimitiveConfig, ClearDTCPrimitiveConfig, ControlDTCPrimitiveConfig


setup_logging(Loglevel.DEBUG)
config, _ = load_config_file()


# Mockup
def create_parser_tree() -> tuple[type[BaseCommand], dict[type, dict[str, Any]]]:
    setattr(
        ReadByIdentifierPrimitiveConfig,
        "_class",
        ReadByIdentifierPrimitive
    )
    setattr(
        WriteByIdentifierPrimitiveConfig,
        "_class",
        WriteByIdentifierPrimitive
    )
    for cls in [ReadDTCPrimitiveConfig, ClearDTCPrimitiveConfig, ControlDTCPrimitiveConfig]:
        setattr(
            cls,
            "_class",
            DTCPrimitive
        )

    extra_defaults = {}

    for cls in [ReadByIdentifierPrimitiveConfig, WriteByIdentifierPrimitiveConfig, ReadDTCPrimitiveConfig, ClearDTCPrimitiveConfig, ControlDTCPrimitiveConfig]:
        config_attributes = cls.attributes_from_config(config)
        env_attributes = cls.attributes_from_env()
        config_attributes.update(env_attributes)
        extra_defaults[cls] = config_attributes

    class DTC(BaseCommand):
        read: ReadDTCPrimitiveConfig | None = Field(None, description="Read DTCs")
        clear: ClearDTCPrimitiveConfig | None = Field(None, description="Clear DTCs")
        control: ControlDTCPrimitiveConfig | None = Field(None, description="Control DTCs")

    class Primitive(BaseCommand):
        rdbi: ReadByIdentifierPrimitiveConfig | None = Field(
            None,
            description="Read data at a specific ID using the UDS service RDBI (0x22)",
        )
        wdbi: WriteByIdentifierPrimitiveConfig | None = Field(
            None,
            description="Write data at a specific ID using the UDS service WDBI (0x2e)",
        )
        dtc: DTC | None = Field(
            None,
            description="Read, delete or control DTCs"
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
    sys.exit(config._class(config).entry_point())


if __name__ == "__main__":
    main()
