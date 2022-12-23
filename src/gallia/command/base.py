# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import asyncio
import fcntl
import os
import os.path
import shutil
import signal
import sys
import traceback
from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from datetime import datetime, timezone
from enum import Enum, IntEnum, unique
from pathlib import Path
from subprocess import CalledProcessError, run
from tempfile import gettempdir
from typing import cast

import msgspec

from gallia.config import Config
from gallia.db.handler import DBHandler
from gallia.dumpcap import Dumpcap
from gallia.log import Loglevel, get_logger, setup_logging, tz
from gallia.plugins import load_transport
from gallia.powersupply import PowerSupply, PowerSupplyURI
from gallia.services.uds.core.exception import UDSException
from gallia.transports import BaseTransport, TargetURI
from gallia.utils import camel_to_snake


@unique
class ExitCodes(IntEnum):
    SUCCESS = 0
    GENERIC_ERROR = 1
    UNHANDLED_EXCEPTION = 2


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


class CommandMeta(msgspec.Struct):
    group: str
    subgroup: str | None
    command: str


class RunMeta(msgspec.Struct):
    command: list[str]
    command_meta: CommandMeta
    start_time: str
    end_time: str
    exit_code: int


class BaseCommand(ABC):
    """BaseCommand is the baseclass for all gallia commands.
    This class can be used in standalone scripts via the
    gallia command line interface facility.

    This class needs to be subclassed and all the abstract
    methods need to be implemented. The artifacts_dir is
    generated based on the COMMAND, GROUP, SUBGROUP
    properties (falls back to the class name if all three
    are not set).

    The main entry_point is :meth:`entry_point()`.
    """

    #: The command name when used in the gallia CLI.
    COMMAND: str | None = None
    #: The group name when used in the gallia CLI.
    GROUP: str | None = None
    #: The subgroup name when used in the gallia CLI.
    SUBGROUP: str | None = None
    #: The string which is shown on the cli with --help.
    SHORT_HELP: str | None = None
    #: The string which is shown at the bottom of --help.
    EPILOG: str | None = None

    #: The name of the logger when this command is run.
    LOGGER_NAME = "gallia"
    #: Enable a artifacts_dir. Setting this property to
    #: True enables the creation of a logfile.
    HAS_ARTIFACTS_DIR: bool = False
    #: A list of exception types for which tracebacks are
    #: suppressed at the top level. For these exceptions
    #: a log message with level critical is logged.
    CATCHED_EXCEPTIONS: list[type[Exception]] = []

    def __init__(self, parser: ArgumentParser, config: Config = Config()) -> None:
        self.id = camel_to_snake(self.__class__.__name__)
        self.logger = get_logger(self.LOGGER_NAME)
        self.parser = parser
        self.config = config
        self.artifacts_dir = Path(".")
        self.run_meta = RunMeta(
            command=sys.argv,
            command_meta=CommandMeta(
                command=self.COMMAND,
                group=self.GROUP,
                subgroup=self.SUBGROUP,
            ),
            start_time=datetime.now(tz).isoformat(),
            exit_code=0,
            end_time=0,
        )
        self._lock_file_fd: int | None = None
        self.configure_class_parser()
        self.configure_parser()

    @abstractmethod
    def run(self, args: Namespace) -> int:
        ...

    def get_log_level(self, args: Namespace) -> Loglevel:
        level = Loglevel.INFO
        if args.verbose == 1:
            level = Loglevel.DEBUG
        elif args.verbose >= 2:
            level = Loglevel.TRACE
        return level

    def get_file_log_level(self, args: Namespace) -> Loglevel:
        if args.trace_log:
            return Loglevel.TRACE
        return Loglevel.TRACE if args.verbose >= 2 else Loglevel.DEBUG

    def run_hook(
        self,
        variant: HookVariant,
        args: Namespace,
        exit_code: int | None = None,
    ) -> None:
        script = args.pre_hook if variant == HookVariant.PRE else args.post_hook
        if script is None or script == "":
            return

        hook_id = f"{variant.value}-hook"

        argv = sys.argv[:]
        argv[0] = os.path.basename(argv[0])
        env = {
            "GALLIA_ARTIFACTS_DIR": str(self.artifacts_dir),
            "GALLIA_HOOK": variant.value,
            "GALLIA_INVOCATION": " ".join(argv),
        } | os.environ

        if self.COMMAND is not None:
            env |= {"GALLIA_COMMAND": self.COMMAND}
        if self.GROUP is not None:
            env |= {"GALLIA_GROUP": self.GROUP}
        if self.SUBGROUP is not None:
            env |= {"GALLIA_GROUP": self.SUBGROUP}
        if exit_code is not None:
            env |= {"GALLIA_EXIT_CODE": str(exit_code)}

        try:
            p = run(
                script,
                env=env,
                text=True,
                capture_output=True,
                shell=True,
                check=True,
            )
            stdout = p.stdout
            stderr = p.stderr
        except CalledProcessError as e:
            self.logger.warning(
                f"{variant.value}-hook failed (exit code: {p.returncode})"
            )
            stdout = e.stdout
            stderr = e.stderr

        if stdout:
            self.logger.info(p.stdout.strip(), extra={"tags": [hook_id, "stdout"]})
        if stderr:
            self.logger.info(p.stderr.strip(), extra={"tags": [hook_id, "stderr"]})

    def configure_class_parser(self) -> None:
        group = self.parser.add_argument_group("generic arguments")
        group.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=self.config.get_value("gallia.verbosity", 0),
            help="increase verbosity on the console",
        )
        group.add_argument(
            "--trace-log",
            action=argparse.BooleanOptionalAction,
            default=self.config.get_value("gallia.trace_log", False),
            help="set the loglevel of the logfile to TRACE",
        )
        group.add_argument(
            "--pre-hook",
            metavar="SCRIPT",
            default=self.config.get_value("gallia.hooks.pre", None),
            help="shell script to run before the main entry_point",
        )
        group.add_argument(
            "--post-hook",
            metavar="SCRIPT",
            default=self.config.get_value("gallia.hooks.post", None),
            help="shell script to run after the main entry_point",
        )
        group.add_argument(
            "--hooks",
            action=argparse.BooleanOptionalAction,
            default=self.config.get_value("gallia.hooks.enable", True),
            help="execute pre and post hooks",
        )
        group.add_argument(
            "--lock-file",
            type=Path,
            metavar="PATH",
            default=self.config.get_value("gallia.lock_file", None),
            help="path to file used for a posix lock",
        )

        if self.HAS_ARTIFACTS_DIR:
            mutex_group = group.add_mutually_exclusive_group()
            mutex_group.add_argument(
                "--artifacts-dir",
                default=self.config.get_value("gallia.scanner.artifacts_dir"),
                type=Path,
                metavar="DIR",
                help="Folder for artifacts",
            )
            mutex_group.add_argument(
                "--artifacts-base",
                default=self.config.get_value(
                    "gallia.scanner.artifacts_base",
                    Path(gettempdir()).joinpath("gallia"),
                ),
                type=Path,
                metavar="DIR",
                help="Base directory for artifacts",
            )

    def configure_parser(self) -> None:
        ...

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
        symlink.symlink_to(latest_dir)

    def prepare_artifactsdir(
        self,
        base_dir: Path | None = None,
        force_path: Path | None = None,
    ) -> Path:
        if force_path is not None:
            if force_path.is_dir():
                return force_path

            force_path.mkdir(parents=True)
            return force_path

        if base_dir is not None:
            _command_dir = ""
            if self.GROUP is not None:
                _command_dir += self.GROUP
            if self.SUBGROUP is not None:
                _command_dir += f"_{self.SUBGROUP}"
            if self.COMMAND is not None:
                _command_dir += f"_{self.COMMAND}"

            # When self.GROUP is None, then
            # _command_dir starts with "_"; remove it.
            if _command_dir.startswith("_"):
                _command_dir = _command_dir.removeprefix("_")

            # If self.GROUP, self.SUBGROUP, and
            # self.COMMAND are None, then fallback to self.id.
            if _command_dir == "":
                _command_dir = self.id

            command_dir = base_dir.joinpath(_command_dir)

            _run_dir = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S.%f')}"
            artifacts_dir = command_dir.joinpath(_run_dir).absolute()
            artifacts_dir.mkdir(parents=True)

            self._dump_environment(artifacts_dir.joinpath(FileNames.ENV.value))
            self._add_latest_link(command_dir)

            return artifacts_dir.absolute()

        raise ValueError("base_dir or force_path must be different from None")

    def _aquire_flock(self, path: Path) -> None:
        if not path.exists():
            path.touch()
        self._lock_file_fd = os.open(path, os.O_RDONLY)
        try:
            # First do a non blocking flock. If waiting is required,
            # log a message and do a blocking wait afterwards.
            fcntl.flock(self._lock_file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.logger.notice(f"Waiting for flock: {path}")
            fcntl.flock(self._lock_file_fd, fcntl.LOCK_EX)
        self.logger.info("Acquired lock. Continuing.")

    def _release_flock(self) -> None:
        assert self._lock_file_fd
        fcntl.flock(self._lock_file_fd, fcntl.LOCK_UN)
        os.close(self._lock_file_fd)

    def entry_point(self, args: Namespace) -> int:
        if (p := args.lock_file) is not None:
            try:
                self._aquire_flock(p)
            except OSError as e:
                self.logger.critical(f"Unable to lock {p}: {e}")
                return ExitCodes.GENERIC_ERROR

        if self.HAS_ARTIFACTS_DIR:
            self.artifacts_dir = self.prepare_artifactsdir(
                args.artifacts_base,
                args.artifacts_dir,
            )
            setup_logging(
                self.get_log_level(args),
                self.get_file_log_level(args),
                self.artifacts_dir.joinpath(FileNames.LOGFILE.value),
            )
        else:
            setup_logging(self.get_log_level(args))

        if args.hooks:
            self.run_hook(HookVariant.PRE, args)

        exit_code = 0
        try:
            exit_code = self.run(args)
        except KeyboardInterrupt:
            exit_code = 128 + signal.SIGINT
        # Ensure that META.json gets written in the case a
        # command calls sys.exit().
        except SystemExit as e:
            match e.code:
                case int():
                    exit_code = e.code
                case _:
                    exit_code = ExitCodes.GENERIC_ERROR
        except Exception as e:
            for t in self.CATCHED_EXCEPTIONS:
                if isinstance(e, t):
                    exit_code = ExitCodes.GENERIC_ERROR
                    self.logger.critical(repr(e))
                    break
            else:
                exit_code = ExitCodes.UNHANDLED_EXCEPTION
                traceback.print_exc()
        finally:
            if self.HAS_ARTIFACTS_DIR:
                self.run_meta.exit_code = exit_code
                self.run_meta.end_time = datetime.now(tz).isoformat()
                data = msgspec.json.encode(self.run_meta)
                self.artifacts_dir.joinpath(FileNames.META.value).write_bytes(
                    data + b"\n"
                )
                self.logger.info(f"Stored artifacts at {self.artifacts_dir}")

        if args.hooks:
            code = exit_code.value if isinstance(exit_code, ExitCodes) else exit_code
            self.run_hook(HookVariant.POST, args, code)

        if self._lock_file_fd is not None:
            self._release_flock()

        return exit_code


class Script(BaseCommand, ABC):
    """Script is a base class for a syncronous gallia command.
    To implement a script, create a subclass and implement the
    .main() method."""

    GROUP = "script"

    def setup(self, args: Namespace) -> None:
        ...

    @abstractmethod
    def main(self, args: Namespace) -> None:
        ...

    def teardown(self, args: Namespace) -> None:
        ...

    def run(self, args: Namespace) -> int:
        self.setup(args)
        try:
            self.main(args)
        finally:
            self.teardown(args)

        return ExitCodes.SUCCESS


class AsyncScript(BaseCommand, ABC):
    """AsyncScript is a base class for a asyncronous gallia command.
    To implement an async script, create a subclass and implement
    the .main() method."""

    GROUP = "script"

    async def setup(self, args: Namespace) -> None:
        ...

    @abstractmethod
    async def main(self, args: Namespace) -> None:
        ...

    async def teardown(self, args: Namespace) -> None:
        ...

    async def _run(self, args: Namespace) -> None:
        await self.setup(args)
        try:
            await self.main(args)
        finally:
            await self.teardown(args)

    def run(self, args: Namespace) -> int:
        asyncio.run(self._run(args))
        return ExitCodes.SUCCESS


class Scanner(AsyncScript, ABC):
    """Scanner is a base class for all scanning related commands.
    A scanner has the following properties:

    - It is async.
    - It loads transports via TargetURIs; available via `self.transport`.
    - Controlling PowerSupplies via the opennetzteil API is supported.
    - `setup()` can be overwritten (do not forget to call `super().setup()`)
      for preparation tasks, such as estabshling a network connection or
      starting background tasks.
    - pcap logfiles can be recorded via a Dumpcap background task.
    - `teardown()` can be overwritten (do not forget to call `super().teardown()`)
      for cleanup tasks, such as terminating a network connection or background
      tasks.
    - `main()` is the relevant entry_point for the scanner and must be implemented.
    """

    GROUP = "scan"
    HAS_ARTIFACTS_DIR = True
    CATCHED_EXCEPTIONS: list[type[Exception]] = [
        ConnectionError,
        UDSException,
    ]

    def __init__(self, parser: ArgumentParser, config: Config = Config()) -> None:
        super().__init__(parser, config)
        self.db_handler: DBHandler | None = None
        self.power_supply: PowerSupply | None = None
        self.transport: BaseTransport
        self.dumpcap: Dumpcap | None = None

    @abstractmethod
    async def main(self, args: Namespace) -> None:
        ...

    async def _db_insert_run_meta(self, args: Namespace) -> None:
        if args.db is not None:
            self.db_handler = DBHandler(args.db)
            await self.db_handler.connect()

            await self.db_handler.insert_run_meta(
                script=sys.argv[0].split()[-1],
                arguments=sys.argv[1:],
                start_time=datetime.now(timezone.utc).astimezone(),
                path=self.artifacts_dir,
            )

    async def _db_finish_run_meta(self, args: Namespace, exit_code: int) -> None:
        if self.db_handler is not None and self.db_handler.connection is not None:
            if self.db_handler.meta is not None:
                try:
                    await self.db_handler.complete_run_meta(
                        datetime.now(timezone.utc).astimezone(),
                        exit_code,
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Could not write the run meta to the database: {e!r}"
                    )

            try:
                await self.db_handler.disconnect()
            except Exception as e:
                self.logger.error(
                    f"Could not close the database connection properly: {e!r}"
                )

    async def setup(self, args: Namespace) -> None:
        if args.target is None:
            self.parser.error("--target is required")

        if args.power_supply is not None:
            self.power_supply = await PowerSupply.connect(args.power_supply)
            if args.power_cycle is True:
                await self.power_supply.power_cycle(
                    args.power_cycle_sleep, lambda: asyncio.sleep(2)
                )
        elif args.power_cycle is True:
            self.parser.error("--power-cycle needs --power-supply")

        # Start dumpcap as the first subprocess; otherwise network
        # traffic might be missing.
        if args.dumpcap:
            if shutil.which("dumpcap") is None:
                self.parser.error("--dumpcap specified but `dumpcap` is not available")
            self.dumpcap = await Dumpcap.start(args.target, self.artifacts_dir)
            await self.dumpcap.sync()

        self.transport = await load_transport(args.target).connect(args.target)

    async def teardown(self, args: Namespace) -> None:
        await self.transport.close()

        if self.dumpcap:
            await self.dumpcap.stop()

    def configure_class_parser(self) -> None:
        super().configure_class_parser()

        group = self.parser.add_argument_group("scanner related arguments")
        group.add_argument(
            "--db",
            default=self.config.get_value("gallia.scanner.db"),
            type=Path,
            help="Path to sqlite3 database",
        )
        group.add_argument(
            "--dumpcap",
            action=argparse.BooleanOptionalAction,
            default=self.config.get_value("gallia.scanner.dumpcap", default=True),
            help="Enable/Disable creating a pcap file",
        )

        group = self.parser.add_argument_group("transport mode related arguments")
        group.add_argument(
            "--target",
            metavar="TARGET",
            default=self.config.get_value("gallia.scanner.target"),
            type=TargetURI,
            help="URI that describes the target",
        )

        group = self.parser.add_argument_group("power supply related arguments")
        group.add_argument(
            "--power-supply",
            metavar="URI",
            default=self.config.get_value("gallia.scanner.power_supply"),
            type=PowerSupplyURI,
            help="URI specifying the location of the relevant opennetzteil server",
        )
        group.add_argument(
            "--power-cycle",
            action=argparse.BooleanOptionalAction,
            default=self.config.get_value("gallia.scanner.power_cycle", False),
            help="trigger a powercycle before starting the scan",
        )
        group.add_argument(
            "--power-cycle-sleep",
            metavar="SECs",
            type=float,
            default=self.config.get_value("gallia.scanner.power_cycle_sleep", 5.0),
            help="time to sleep after the power-cycle",
        )

    def entry_point(self, args: Namespace) -> int:
        asyncio.run(self._db_insert_run_meta(args))
        exit_code = super().entry_point(args)
        asyncio.run(self._db_finish_run_meta(args, exit_code))
        return exit_code
