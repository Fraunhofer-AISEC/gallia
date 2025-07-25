# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

from gallia.command.config import GalliaBaseModel
from gallia.db.log import LogMode
from gallia.log import get_logger
from gallia.services.uds.core.service import (
    PositiveResponse,
    SubFunctionRequest,
    SubFunctionResponse,
    UDSRequest,
    UDSResponse,
)
from gallia.services.uds.core.utils import bytes_repr as bytes_repr_
from gallia.services.uds.ecu import ECUProperties
from gallia.utils import handle_task_error, set_task_handler_ctx_variable


def bytes_repr(data: bytes | bytearray) -> str:
    return bytes_repr_(data, False, None)


schema_version = "4.0"

DB_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS version (
  schema text unique,
  version text
);
CREATE TABLE IF NOT EXISTS ecu (
  id integer primary key,
  name text,
  oem text,
  manufacturer text,
  oem_uid text
);
CREATE TABLE IF NOT EXISTS address (
  id integer primary key,
  url text not null unique,
  ecu int references ecu(id) on update cascade on delete set null
);
CREATE TABLE IF NOT EXISTS run_meta (
  id integer primary key,
  script text not null,
  config json not null check(json_valid(config)),
  start_time real not null,
  start_timezone text not null,
  end_time real,
  end_timezone text check((end_timezone is null) = (end_time is null)),
  exit_code int,
  path text,
  exclude boolean
);
CREATE TABLE IF NOT EXISTS error_log (
  level int not null,
  time real not null,
  timezone text not null,
  message text not null,
  meta int references run_meta(id) not null
);
CREATE TABLE IF NOT EXISTS discovery_run (
  id integer primary key,
  protocol text not null,
  meta int references run_meta(id) on update cascade on delete cascade
);
CREATE TABLE IF NOT EXISTS scan_run (
  id integer primary key,
  address int references address(id) on update cascade on delete set null,
  properties_pre json check(properties_pre is null or json_valid(properties_pre)),
  properties_post json check(properties_post is null or json_valid(properties_post)),
  meta int references run_meta(id) on update cascade on delete cascade
);
CREATE TABLE IF NOT EXISTS discovery_result (
  id integer primary key,
  run int not null references discovery_run(id) on update cascade on delete cascade,
  address int not null references address(id) on update cascade on delete cascade
);
CREATE TABLE IF NOT EXISTS scan_result (
  id integer primary key,
  run int not null references scan_run(id) on update cascade on delete cascade,
  log_mode text not null check(log_mode in ('implicit', 'explicit', 'emphasized')),
  state json check(state is null or json_valid(state)),
  request_pdu blob not null,
  request_time real not null,
  request_timezone text not null,
  request_data json check(json_valid(request_data)) not null,
  response_pdu blob,
  response_time real,
  response_timezone text check((response_timezone is null) = (response_time is null)),
  response_data json check(response_data is null or json_valid(response_data)),
  exception text
);
CREATE INDEX IF NOT EXISTS ix_scan_result_request_pdu ON scan_result(request_pdu);
CREATE TABLE IF NOT EXISTS session_transition (
  run int not null references scan_run(id) on update cascade on delete cascade,
  destination int not null,
  steps json check(json_valid(steps))
);

CREATE VIEW IF NOT EXISTS run_stats AS
SELECT
  ru.id AS run,
  ecu.name AS ECU,
  rm.script,
  rm.arguments,
  strftime('%Y-%m-%d %H:%M:%f', rm.start_time, 'unixepoch', 'localtime') AS start,
  strftime('%Y-%m-%d %H:%M:%f', rm.end_time, 'unixepoch', 'localtime') AS end,
  cast((CASE WHEN end_time IS NULL THEN strftime('%s','now') ELSE end_time END - start_time) / 86400 AS int) || ' ' ||
    time(CASE WHEN end_time IS NULL THEN strftime('%s','now') ELSE end_time END - start_time, 'unixepoch') AS duration,
  exit_code,
  ru.properties_pre = ru.properties_post AS equal_props,
  n_msgs
FROM
  run_meta rm,
  scan_run ru LEFT JOIN (SELECT run, count(*) AS n_msgs FROM scan_result GROUP BY run) sc ON ru.id = sc.run,
  address ad LEFT JOIN ecu ON ecu.id = ad.ecu
WHERE ru.meta = rm.id
AND ad.id = ru.address
GROUP BY ru.id;


INSERT OR IGNORE INTO version VALUES('main', '{schema_version}');
"""

logger = get_logger(__name__)


class DBHandler:
    def __init__(self, database: Path):
        self.tasks: list[asyncio.Task[None]] = []
        self.path = database
        self.connection: aiosqlite.Connection | None = None
        self.scan_run: int | None = None
        self.target: str | None = None
        self.discovery_run: int | None = None
        self.meta: int | None = None
        self._executor_task: asyncio.Task[None] | None = None
        self._execute_queue: asyncio.Queue[tuple[str, tuple[Any, ...]]] | None = None

    async def connect(self) -> None:
        """It is important that `connect` and `disconnect` are called in the same event loop!"""

        if self.connection is not None:
            logger.warning("Already connected to the database")
            return

        self.path.parent.mkdir(exist_ok=True, parents=True)
        self.connection = await aiosqlite.connect(self.path)
        await self.connection.execute("PRAGMA foreign_keys = 1")

        # Allows to read the database in parallel to a scan without causing delays or even losing data
        # This setting is persistent for the database and leads to the creation of extra files
        # See https://www.sqlite.org/wal.html for further information
        await self.connection.execute("PRAGMA journal_mode = WAL")

        await self.connection.execute("PRAGMA busy_timeout = 10000")

        await self.connection.executescript(DB_SCHEMA)
        await self.check_version()

        # This queue is meant to be used for usage-heavy executes that are not time-sensitive, e.g. UDS messages
        self._execute_queue = asyncio.Queue()
        self._executor_task = asyncio.create_task(self._executor_func())
        self._executor_task.add_done_callback(
            handle_task_error,
            context=set_task_handler_ctx_variable(__name__, "DbHandler"),
        )

    async def _executor_func(self) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self._execute_queue is not None, "Queue was not started"

        try:
            while True:
                (query, query_parameter) = await self._execute_queue.get()

                try:
                    await self.connection.execute(query, query_parameter)
                    await self.connection.commit()
                except aiosqlite.OperationalError:
                    logger.warning(
                        f"Could not log message for {query_parameter[5]} to database. Retrying ..."
                    )
                    # TODO: This could lead to an infinite loop when there are recurring OperationalErrors!
                    await self._execute_queue.put((query, query_parameter))
                finally:
                    # Inform the the queue that the query was fully processed to track progress
                    self._execute_queue.task_done()

        except asyncio.CancelledError:
            logger.debug("Database worker cancelled")
        except asyncio.IncompleteReadError as e:
            logger.debug(f"Database worker received EOF: {e}")
        except Exception as e:
            logger.critical(f"Database worker died: {e!r}")

    async def disconnect(self) -> None:
        """It is important that `connect` and `disconnect` are called in the same event loop!"""

        assert self.connection is not None, "Not connected to the database"
        assert self._execute_queue is not None, "Queue is already detached"
        assert self._executor_task is not None, "Task is already detached"

        logger.info("Syncing database…")
        try:
            # Wait for all queries in the queue to be written to the database and cancel task afterwards.
            # TODO: this could block infinitely if there are OperationalErrors writing to the database in
            # the `_executor_func()`
            await self._execute_queue.join()
            self._executor_task.cancel()
            await self._executor_task
        except Exception as e:
            logger.error(f"Could not properly clean up the database task: {e!r}")
        finally:
            self._execute_queue = None
            self._executor_task = None

        try:
            await self.connection.commit()
        finally:
            await self.connection.close()
            self.connection = None
        logger.info("Database closed")

    async def check_version(self) -> None:
        assert self.connection is not None, "Not connected to the database"

        query = 'SELECT version FROM version WHERE schema = "main"'
        cursor: aiosqlite.Cursor = await self.connection.execute(query)
        row = await cursor.fetchone()

        if row is None:
            raise ValueError("No schema version is specified in the database!")

        version = row[0]

        # This could be a much more complex version to support some older version as well
        # Additionally one might bind certain features to this version or trigger a database migration, etc
        if version != schema_version:
            raise ValueError(
                f"The version of the database schema is not supported! ({version} != {schema_version})"
            )

    async def insert_run_meta(  # noqa: PLR0913
        self,
        script: str,
        config: GalliaBaseModel,
        start_time: datetime,
        path: Path | None,
    ) -> None:
        assert self.connection is not None, "Not connected to the database"

        query = (
            "INSERT INTO "
            "run_meta(script, config, start_time, start_timezone, path, exclude) "
            "VALUES (?, ?, ?, ?, ?, FALSE)"
        )
        cursor = await self.connection.execute(
            query,
            (
                script,
                config.model_dump_json(),
                start_time.timestamp(),
                start_time.tzname(),
                str(path),
            ),
        )

        self.meta = cursor.lastrowid

        await self.connection.commit()

    async def complete_run_meta(
        self, end_time: datetime, exit_code: int, path: Path | None
    ) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.meta is not None, "Run meta not yet created"

        query = "UPDATE run_meta SET end_time = ?, end_timezone = ?, exit_code = ?, path = ? WHERE id = ?"
        await self.connection.execute(
            query,
            (end_time.timestamp(), end_time.tzname(), exit_code, str(path), self.meta),
        )
        await self.connection.commit()

    async def insert_scan_run(self, target: str) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.meta is not None, "Run meta not yet created"

        await self.connection.execute("INSERT OR IGNORE INTO address(url) VALUES(?)", (target,))

        query = (
            "INSERT INTO scan_run(address, meta) VALUES ((SELECT id FROM address WHERE url = ?), ?)"
        )
        cursor = await self.connection.execute(query, (target, self.meta))

        self.scan_run = cursor.lastrowid
        self.target = target
        await self.connection.commit()

    async def insert_scan_run_properties_pre(self, properties_pre: ECUProperties) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.scan_run is not None, "Scan run not yet created"

        query = "UPDATE scan_run SET properties_pre = ? WHERE id = ?"
        await self.connection.execute(query, (properties_pre.to_json(), self.scan_run))
        await self.connection.commit()

    async def complete_scan_run(self, properties_post: ECUProperties) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.scan_run is not None, "Scan run not yet created"

        query = "UPDATE scan_run SET properties_post = ? WHERE id = ?"
        await self.connection.execute(query, (properties_post.to_json(), self.scan_run))
        await self.connection.commit()

    async def insert_discovery_run(self, protocol: str) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.meta is not None, "Run meta not yet created"

        query = "INSERT INTO discovery_run(protocol, meta) VALUES (?, ?)"
        cursor = await self.connection.execute(query, (protocol, self.meta))
        self.discovery_run = cursor.lastrowid
        await self.connection.commit()

    async def insert_discovery_result(self, target: str) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.discovery_run is not None, "Discovery run not yet created"

        await self.connection.execute("INSERT OR IGNORE INTO address(url) VALUES(?)", (target,))

        query = "INSERT INTO discovery_result(address, run) VALUES ((SELECT id FROM address WHERE url = ?), ?)"

        await self.connection.execute(query, (target, self.discovery_run))
        await self.connection.commit()

    async def insert_scan_result(  # noqa: PLR0913
        self,
        state: dict[str, Any],
        request: UDSRequest,
        response: UDSResponse | None,
        exception: Exception | None,
        send_time: datetime,
        receive_time: datetime | None,
        log_mode: LogMode,
    ) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self._execute_queue is not None, "Queue not yet created"
        assert self.scan_run is not None, "Scan run not yet created"

        request_attributes: dict[str, Any] = {
            "service_id": request.service_id,
            "data": bytes_repr(request.data),
        }
        response_attributes: dict[str, Any] = {}

        if isinstance(request, SubFunctionRequest):
            request_attributes["sub_function"] = request.sub_function

        for attr, value in request.__dict__.items():
            if not attr.startswith("_"):
                request_attributes[attr] = value

                if isinstance(value, bytes | bytearray):
                    request_attributes[attr] = bytes_repr(value)
                elif (
                    isinstance(value, list)
                    and len(value) > 0
                    and isinstance(value[0], bytes | bytearray)
                ):
                    request_attributes[attr] = [bytes_repr(v) for v in value]

        if response is not None:
            response_attributes = {"service_id": response.service_id}

            if isinstance(response, PositiveResponse):
                response_attributes["data"] = bytes_repr(response.data)

            if isinstance(response, SubFunctionResponse):
                response_attributes["sub_function"] = response.sub_function

            for attr, value in response.__dict__.items():
                if not attr.startswith("_") and attr not in ["trigger_request"]:
                    response_attributes[attr] = value

                    if isinstance(value, bytes | bytearray):
                        response_attributes[attr] = bytes_repr(value)
                    elif (
                        isinstance(value, list)
                        and len(value) > 0
                        and isinstance(value[0], bytes | bytearray)
                    ):
                        response_attributes[attr] = [bytes_repr(v) for v in value]

        query = (
            "INSERT INTO scan_result(run, state, request_pdu, request_time, request_timezone, request_data, "
            "response_pdu, response_time, response_timezone, response_data, exception, log_mode) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        # This has do be done here, in order to make sure, that only "immutable" objects are passed to a different task
        query_parameter = (
            self.scan_run,
            json.dumps(state),
            bytes_repr(request.pdu),
            send_time.timestamp(),
            send_time.tzname(),
            json.dumps(request_attributes),
            bytes_repr(response.pdu) if response is not None else None,
            receive_time.timestamp() if response is not None and receive_time is not None else None,
            receive_time.tzname() if response is not None and receive_time is not None else None,
            json.dumps(response_attributes) if response is not None else None,
            repr(exception) if exception is not None else None,
            log_mode.name,
        )

        await self._execute_queue.put((query, query_parameter))

    async def insert_session_transition(self, destination: int, steps: list[int]) -> None:
        assert self.connection is not None, "Not connected to the database"

        query = "INSERT INTO session_transition VALUES(?, ?, ?)"
        parameters = (self.scan_run, destination, json.dumps(steps))
        await self.connection.execute(query, parameters)

    async def get_sessions(self) -> list[int]:
        assert self.connection is not None, "Not connected to the database"
        assert self.target is not None, "Scan run not yet created, target unknown"

        query = (
            "SELECT DISTINCT destination "
            "FROM session_transition st, "
            "     scan_run sr, "
            "     address ad "
            "WHERE st.run = sr.id AND sr.address = ad.id "
            "AND ad.url = ?"
        )
        parameters = (self.target,)

        cursor: aiosqlite.Cursor = await self.connection.execute(query, parameters)
        return [x[0] for x in await cursor.fetchall()]

    async def get_session_transition(self, destination: int) -> list[int] | None:
        assert self.connection is not None, "Not connected to the database"
        assert self.target is not None, "Scan run not yet created, target unknown"

        query = (
            "SELECT steps "
            "FROM session_transition st, "
            "     scan_run sr, "
            "     address ad "
            "WHERE st.run = sr.id AND sr.address = ad.id "
            "AND st.destination = ? AND ad.url = ?"
        )
        parameters = (destination, self.target)
        cursor: aiosqlite.Cursor = await self.connection.execute(query, parameters)
        row = await cursor.fetchone()

        if row is None:
            return None

        result: list[int] = json.loads(row[0])
        return result
