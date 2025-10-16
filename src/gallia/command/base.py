# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import dataclasses
import json
import os
import os.path
import signal
import sys
from abc import ABC, abstractmethod
from collections.abc import MutableMapping
from datetime import UTC, datetime
from enum import Enum, unique
from logging import WARNING
from pathlib import Path
from subprocess import CalledProcessError, run
from typing import Any, Protocol, cast

from pydantic import ConfigDict

from gallia import exitcodes
from gallia.command.config import Field, GalliaBaseModel
from gallia.db.handler import DBHandler
from gallia.log import _ZstdFileHandler, add_zst_log_handler, get_logger, remove_zst_log_handler, tz
from gallia.utils import camel_to_snake, get_file_log_level


@unique
class FileNames(Enum):
    PROPERTIES_PRE = "PROPERTIES_PRE.json"
    PROPERTIES_POST = "PROPERTIES_POST.json"
    META = "META.json"
    ENV = "ENV"
    LOGFILE = "log.json.zst"


@unique
class HookVariant(Enum):
    PRE = "pre"
    POST = "post"


@dataclasses.dataclass
class RunMeta:
    command: str
    start_time: str
    end_time: str
    exit_code: int
    config: MutableMapping[str, Any]

    def json(self) -> str:
        return json.dumps(dataclasses.asdict(self))


logger = get_logger(__name__)


if sys.platform.startswith("linux") or sys.platform == "darwin":
    import fcntl

    class Flockable(Protocol):
        @property
        def _lock_file_fd(self) -> int | None: ...

    class FlockMixin:
        def _open_lockfile(self, path: Path) -> int | None:
            if not path.exists():
                path.touch()

            logger.notice("opening lockfile…")
            return os.open(path, os.O_RDONLY)

        async def _aquire_flock(self: Flockable) -> None:
            assert self._lock_file_fd is not None

            try:
                # First do a non blocking flock. If waiting is required,
                # log a message and do a blocking wait afterwards.
                fcntl.flock(self._lock_file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                logger.notice("waiting for flock…")
                await asyncio.to_thread(fcntl.flock, self._lock_file_fd, fcntl.LOCK_EX)
            logger.info("Acquired lock. Continuing…")

        def _release_flock(self: Flockable) -> None:
            assert self._lock_file_fd is not None
            fcntl.flock(self._lock_file_fd, fcntl.LOCK_UN)
            os.close(self._lock_file_fd)


if sys.platform == "win32":

    class FlockMixin:
        def _open_lockfile(self, path: Path) -> int | None:
            logger.warn("lockfile in windows is not supported")
            return None

        async def _aquire_flock(self) -> None:
            pass

        def _release_flock(self) -> None:
            pass


class AsyncScriptConfig(GalliaBaseModel, cli_group="generic", config_section="gallia"):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    verbose: int = Field(
        0,
        description="Increase verbosity of the console log (0: INFO, 1: DEBUG, 2: TRACE)",
        short="v",
    )
    volatile_info: bool = Field(
        True, description="Overwrite log lines with level info or lower in terminal output"
    )
    trace_log: bool = Field(False, description="set the loglevel of the logfile to TRACE")
    pre_hook: str | None = Field(
        None,
        description="shell script to run before the main entry_point",
        metavar="SCRIPT",
        config_section="gallia.hooks",
    )
    post_hook: str | None = Field(
        None,
        description="shell script to run after the main entry_point",
        metavar="SCRIPT",
        config_section="gallia.hooks",
    )
    hooks: bool = Field(
        True, description="execute pre and post hooks", config_section="gallia.hooks"
    )
    lock_file: Path | None = Field(
        None, description="path to file used for a posix lock", metavar="PATH"
    )
    db: Path | None = Field(None, description="Path to sqlite3 database")
    artifacts_base: Path | None = Field(
        None,
        description="Base directory for artifacts. Required to save artifacts such as logs.",
        metavar="DIR",
        config_section="gallia",
    )


class AsyncScript(FlockMixin, ABC):
    """AsyncScript is the baseclass for all gallia commands.
    This class can be used in standalone scripts via the
    gallia command line interface facility.

    This class needs to be subclassed and all the abstract
    methods need to be implemented. The artifacts_dir is
    generated based on the COMMAND, GROUP, SUBGROUP
    properties (falls back to the class name if all three
    are not set).

    The main entry_point is :meth:`entry_point()`.
    """

    # The config type which is accepted by this class
    # This is used for automatically creating the CLI
    CONFIG_TYPE: type[AsyncScriptConfig] = AsyncScriptConfig

    #: The string which is shown on the cli with --help.
    SHORT_HELP: str | None = None
    #: The string which is shown at the bottom of --help.
    EPILOG: str | None = None

    #: A list of exception types for which tracebacks are
    #: suppressed at the top level. For these exceptions
    #: a log message with level critical is logged.
    CATCHED_EXCEPTIONS: list[type[Exception]] = []

    log_file_handlers: list[_ZstdFileHandler]

    def __init__(self, config: AsyncScriptConfig) -> None:
        self.id = camel_to_snake(self.__class__.__name__)
        self.config = config
        self.artifacts_dir: Path | None = None
        self.run_meta = RunMeta(
            command=f"{type(self).__module__}.{type(self).__name__}",
            start_time=datetime.now(tz).isoformat(),
            exit_code=0,
            end_time="",
            config=json.loads(config.model_dump_json()),
        )
        self._lock_file_fd: int | None = None
        self.db_handler: DBHandler | None = None
        self.log_file_handlers = []

    async def setup(self) -> None: ...

    @abstractmethod
    async def main(self) -> None: ...

    async def teardown(self) -> None: ...

    async def run(self) -> int:
        await self.setup()
        try:
            await self.main()
        finally:
            await self.teardown()
        # Note that above's try-except does not catch `SystemExit`s raised by sys.exit()
        # somewhere in main(), so OK is only returned if everything was fine!
        return exitcodes.OK

    def run_hook(self, variant: HookVariant, exit_code: int | None = None) -> None:
        script = self.config.pre_hook if variant == HookVariant.PRE else self.config.post_hook
        if script is None or script == "":
            return

        hook_id = f"{variant.value}-hook"

        argv = sys.argv[:]
        argv[0] = Path(argv[0]).name
        env = {
            "GALLIA_ARTIFACTS_DIR": str(self.artifacts_dir),
            "GALLIA_HOOK": variant.value,
            "GALLIA_INVOCATION": " ".join(argv),
        } | os.environ

        if variant == HookVariant.POST:
            env["GALLIA_META"] = self.run_meta.json()

        if exit_code is not None:
            env["GALLIA_EXIT_CODE"] = str(exit_code)

        try:
            p = run(script, env=env, text=True, capture_output=True, shell=True, check=True)
            stdout = p.stdout
            stderr = p.stderr
        except CalledProcessError as e:
            logger.warning(f"{variant.value}-hook failed (exit code: {e.returncode})")
            stdout = e.stdout
            stderr = e.stderr

        if stdout:
            logger.info(stdout.strip(), extra={"tags": [hook_id, "stdout"]})
        if stderr:
            logger.info(stderr.strip(), extra={"tags": [hook_id, "stderr"]})

    async def _db_connect_and_insert_run_meta(self, db_path: Path) -> None:
        self.db_handler = DBHandler(db_path)
        await self.db_handler.connect()

        await self.db_handler.insert_run_meta(
            script=self.run_meta.command,
            config=self.config,
            start_time=datetime.now(UTC).astimezone(),
            path=self.artifacts_dir,
        )

    async def _db_finish_run_meta_and_disconnect(self) -> None:
        if self.db_handler is not None and self.db_handler.connection is not None:
            if self.db_handler.meta is not None:
                try:
                    await self.db_handler.complete_run_meta(
                        datetime.now(UTC).astimezone(), self.run_meta.exit_code, self.artifacts_dir
                    )
                except Exception as e:
                    logger.warning(f"Could not write the run meta to the database: {e!r}")

            try:
                await self.db_handler.disconnect()
            # CancelledError appears only on windows; it is unclear why this happens…
            except Exception as e:
                logger.error(f"Could not close the database connection properly: {e!r}")
            except asyncio.exceptions.CancelledError as e:
                logger.error(f"BUG: {e!r} occured. This only seems to happen on windows")
                logger.error(
                    "If you can reproduce this, open an issue: https://github.com/Fraunhofer-AISEC/gallia"
                )

    def _dump_environment(self, path: Path) -> None:
        environ = cast(dict[str, str], os.environ)
        data = [f"{k}={v}" for k, v in environ.items()]
        path.write_text("\n".join(data) + "\n")

    def _add_latest_link(self, path: Path) -> None:
        dirs = list(path.glob("run-*"))
        dirs.sort(key=lambda x: x.name)

        latest_dir = dirs[-1].relative_to(path)

        symlink = path.joinpath("LATEST")
        symlink.unlink(missing_ok=True)
        try:
            symlink.symlink_to(latest_dir)
        except (OSError, NotImplementedError) as e:
            logger.warn(f"symlink error: {e}")

    def prepare_artifacts_dir(self) -> Path | None:
        if self.config.artifacts_base is None:
            logger.notice("Artifacts base folder not defined, no artifacts will be saved!")
            return None

        else:
            command_dir = self.config.artifacts_base.joinpath(self.id)

            _run_dir = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S.%f')}"
            artifacts_dir = command_dir.joinpath(_run_dir).absolute()
            artifacts_dir.mkdir(parents=True)

            self._dump_environment(artifacts_dir.joinpath(FileNames.ENV.value))
            self._add_latest_link(command_dir)

            return artifacts_dir.absolute()

    async def entry_point(self) -> int:
        if (p := self.config.lock_file) is not None:
            try:
                self._lock_file_fd = self._open_lockfile(p)
                await self._aquire_flock()
            except OSError as e:
                logger.critical(f"Unable to lock {p}: {e}")
                return exitcodes.OSFILE

        self.artifacts_dir = self.prepare_artifacts_dir()
        if self.artifacts_dir is not None:
            self.log_file_handlers.append(
                add_zst_log_handler(
                    logger_name="gallia",
                    filepath=self.artifacts_dir.joinpath(FileNames.LOGFILE.value),
                    file_log_level=get_file_log_level(self.config),
                )
            )

        if self.config.hooks:
            self.run_hook(HookVariant.PRE)

        if self.config.db is not None:
            # Explicitly set log level of aiosqlite to WARNING to avoid log spam
            db_logger = get_logger("aiosqlite")
            db_logger.setLevel(WARNING)
            await self._db_connect_and_insert_run_meta(self.config.db)

        exit_code = 0
        try:
            exit_code = await self.run()
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            logger.debug(f"{self.__class__} got interrupted: {e!r}")
            exit_code = 128 + signal.SIGINT
        # Ensure that META.json gets written in the case a
        # command calls sys.exit().
        except SystemExit as e:
            match e.code:
                case int():
                    exit_code = e.code
                case _:
                    exit_code = exitcodes.SOFTWARE
        except Exception as e:
            for t in self.CATCHED_EXCEPTIONS:
                if isinstance(e, t):
                    # TODO: Map the exitcode to superclass of builtin exceptions.
                    exit_code = exitcodes.IOERR
                    logger.critical(f"Caught expected exception, stack trace on debug level: {e!r}")
                    logger.debug(e, exc_info=True)
                    break
            else:
                exit_code = exitcodes.SOFTWARE
                logger.critical(e, exc_info=True)
        finally:
            self.run_meta.exit_code = exit_code
            self.run_meta.end_time = datetime.now(tz).isoformat()

            if self.db_handler is not None:
                await self._db_finish_run_meta_and_disconnect()

            if self.artifacts_dir is not None:
                self.artifacts_dir.joinpath(FileNames.META.value).write_text(
                    self.run_meta.json() + "\n"
                )
                logger.notice(f"Stored artifacts at {self.artifacts_dir}")

            # Close open log file handlers to ensure logs are properly written
            # to avoid memory leaks and cross-talking log files
            if len(self.log_file_handlers) > 0:
                logger.info("Syncing log files…")
                while len(self.log_file_handlers) > 0:
                    remove_zst_log_handler(
                        logger_name="gallia",
                        handler=self.log_file_handlers.pop(),
                    )

        if self.config.hooks:
            self.run_hook(HookVariant.POST, exit_code)

        if self._lock_file_fd is not None:
            self._release_flock()

        return exit_code
