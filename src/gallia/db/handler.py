# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

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
from gallia.services.uds.core.utils import g_repr


def bytes_repr(data: bytes) -> str:
    return bytes_repr_(data, False, None)


schema_version = "1.0"

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
  arguments json not null check(json_valid(arguments)),
  start_time real not null,
  start_timezone text not null,
  end_time real,
  end_timezone text check((end_timezone is null) = (end_time is null)),
  exit_code int,
  path text
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
  protocol str not null,
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


class DBHandler:
    def __init__(self, database: Path):
        self.tasks: list[asyncio.Task[None]] = []
        self.path = database
        self.connection: aiosqlite.Connection | None = None
        self.scan_run: int | None = None
        self.target: str | None = None
        self.discovery_run: int | None = None
        self.meta: int | None = None
        self.logger = get_logger("db")

    async def connect(self) -> None:
        assert self.connection is None, "Already connected to the database"

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

    async def disconnect(self) -> None:
        assert self.connection is not None, "Not connected to the database"

        for task in self.tasks:
            try:
                await task
            except Exception as e:
                self.logger.error(f"Inside task: {g_repr(e)}")

        try:
            await self.connection.commit()
        finally:
            await self.connection.close()
            self.connection = None

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

    async def insert_run_meta(
        self, script: str, arguments: list[str], start_time: datetime, path: Path
    ) -> None:
        assert self.connection is not None, "Not connected to the database"

        query = (
            "INSERT INTO run_meta(script, arguments, start_time, start_timezone, path) VALUES "
            "(?, ?, ?, ?, ?)"
        )
        cursor = await self.connection.execute(
            query,
            (
                script,
                json.dumps(arguments),
                start_time.timestamp(),
                start_time.tzname(),
                str(path),
            ),
        )

        self.meta = cursor.lastrowid

        await self.connection.commit()

    async def complete_run_meta(self, end_time: datetime, exit_code: int) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.meta is not None, "Run meta not yet created"

        query = "UPDATE run_meta SET end_time = ?, end_timezone = ?, exit_code = ? WHERE id = ?"
        await self.connection.execute(
            query, (end_time.timestamp(), end_time.tzname(), exit_code, self.meta)
        )
        await self.connection.commit()

    async def insert_scan_run(self, target: str) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.meta is not None, "Run meta not yet created"

        await self.connection.execute(
            "INSERT OR IGNORE INTO address(url) VALUES(?)", (target,)
        )

        query = (
            "INSERT INTO scan_run(address, meta) VALUES "
            "((SELECT id FROM address WHERE url = ?), ?)"
        )
        cursor = await self.connection.execute(query, (target, self.meta))

        self.scan_run = cursor.lastrowid
        self.target = target
        await self.connection.commit()

    async def insert_scan_run_properties_pre(
        self, properties_pre: dict[str, Any]
    ) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.scan_run is not None, "Scan run not yet created"

        query = "UPDATE scan_run SET properties_pre = ? WHERE id = ?"
        await self.connection.execute(
            query, (json.dumps(properties_pre), self.scan_run)
        )
        await self.connection.commit()

    async def complete_scan_run(self, properties_post: dict[str, Any]) -> None:
        assert self.connection is not None, "Not connected to the database"
        assert self.scan_run is not None, "Scan run not yet created"

        query = "UPDATE scan_run SET properties_post = ? WHERE id = ?"
        await self.connection.execute(
            query, (json.dumps(properties_post), self.scan_run)
        )
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

        await self.connection.execute(
            "INSERT OR IGNORE INTO address(url) VALUES(?)", (target,)
        )

        query = "INSERT INTO discovery_result(address, run) VALUES ((SELECT id FROM address WHERE url = ?), ?)"

        await self.connection.execute(query, (target, self.discovery_run))

    async def insert_scan_result(
        self,
        state: dict[str, Any],
        request: UDSRequest,
        response: UDSResponse | None,
        exception: Exception | None,
        send_time: datetime,
        receive_time: datetime | None,
        log_mode: LogMode,
        commit: bool = True,
    ) -> None:
        assert self.connection is not None, "Not connected to the database"
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

                if isinstance(value, (bytes, bytearray)):
                    request_attributes[attr] = bytes_repr(value)
                elif (
                    isinstance(value, list)
                    and len(value) > 0
                    and isinstance(value[0], (bytes, bytearray))
                ):
                    request_attributes[attr] = list(bytes_repr(v) for v in value)

        if response is not None:
            response_attributes = {"service_id": response.service_id}

            if isinstance(response, PositiveResponse):
                response_attributes["data"] = bytes_repr(response.data)

            if isinstance(response, SubFunctionResponse):
                response_attributes["sub_function"] = response.sub_function

            for attr, value in response.__dict__.items():
                if not attr.startswith("_") and attr not in ["trigger_request"]:
                    response_attributes[attr] = value

                    if isinstance(value, (bytes, bytearray)):
                        response_attributes[attr] = bytes_repr(value)
                    elif (
                        isinstance(value, list)
                        and len(value) > 0
                        and isinstance(value[0], (bytes, bytearray))
                    ):
                        response_attributes[attr] = list(bytes_repr(v) for v in value)

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
            receive_time.timestamp()
            if response is not None and receive_time is not None
            else None,
            receive_time.tzname()
            if response is not None and receive_time is not None
            else None,
            json.dumps(response_attributes) if response is not None else None,
            repr(exception) if exception is not None else None,
            log_mode.name,
        )

        async def execute() -> None:
            assert self.connection is not None, "Not connected to the database"

            done = False

            while not done:
                try:
                    await self.connection.execute(query, query_parameter)
                    done = True
                except aiosqlite.OperationalError:
                    self.logger.warning(
                        f"Could not log message for {query_parameter[5]} to database. Retrying ..."
                    )

            if commit:
                await self.connection.commit()

        self.tasks.append(asyncio.create_task(execute()))

    async def insert_session_transition(
        self, destination: int, steps: list[int]
    ) -> None:
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
        return list(x[0] for x in await cursor.fetchall())

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
