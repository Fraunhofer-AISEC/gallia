import asyncio
import importlib
import json
import sys
from typing import Any, Self

import aiosqlite
from pydantic import model_validator

from gallia.command import BaseCommand
from gallia.command.base import Script, ScriptConfig
from gallia.command.config import Field
from gallia.log import get_logger

logger = get_logger(__name__)


class RerunnerConfig(ScriptConfig):
    id: int = Field(positional=True, description="The id of the run_meta entry in the db to rerun")

    @model_validator(mode="after")
    def check_transport_requirements(self) -> Self:
        if self.db is None:
            raise ValueError("This script requires a database connection")

        return self


class Rerunner(Script):
    CONFIG_TYPE = RerunnerConfig
    SHORT_HELP = "Rerun a previous gallia command based on its run_meta in the database"

    def __init__(self, config: RerunnerConfig):
        super().__init__(config)
        self.config: RerunnerConfig = config

    def main(self) -> None:
        query = "SELECT script, config " "FROM run_meta " "WHERE id = ?"
        parameters = (self.config.id,)

        assert self.db_handler is not None

        connection = self.db_handler.connection

        assert connection is not None

        cursor: aiosqlite.Cursor = asyncio.run(connection.execute(query, parameters))
        row = asyncio.run(cursor.fetchone())

        if row is None:
            logger.error(f"There id no run_meta entry with the id {self.config.id}")
            return

        script: str = row[0]
        config: dict[str, Any] = json.loads(row[1])
        script_parts = script.split(".")
        module = ".".join(script_parts[:-1])
        class_name = script_parts[-1]

        logger.info(f"Rerunning run {self.config.id} ({class_name}) with: {config}")

        gallia_class: type[BaseCommand] = getattr(importlib.import_module(module), class_name)
        command = gallia_class(gallia_class.CONFIG_TYPE(**config))

        sys.exit(command.entry_point())
