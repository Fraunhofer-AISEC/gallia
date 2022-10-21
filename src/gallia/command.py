# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import asyncio
import fcntl
import json
import os
import signal
import sys
import traceback
from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from datetime import datetime, timezone
from enum import Enum, IntEnum, unique
from importlib.metadata import entry_points
from pathlib import Path
from subprocess import run
from tempfile import gettempdir
from typing import cast

import aiofiles
import msgspec

from gallia.config import Config
from gallia.db.db_handler import DBHandler
from gallia.dumpcap import Dumpcap
from gallia.log import Loglevel, get_logger, setup_logging, tz
from gallia.powersupply import PowerSupply, PowerSupplyURI
from gallia.services.uds.core.exception import UDSException
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.ecu import ECU
from gallia.services.uds.helpers import raise_for_error
from gallia.transports import load_transport
from gallia.transports.base import BaseTransport, TargetURI
from gallia.utils import camel_to_snake, g_repr


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
    category: str
    subcategory: str | None
    command: str


class RunMeta(msgspec.Struct):
    command: list[str]
    command_meta: CommandMeta
    start_time: str
    end_time: str
    exit_code: int


def load_ecus() -> list[type[ECU]]:
    ecus = []
    eps = entry_points()
    for ep in eps.select(group="gallia_uds_ecus"):
        for t in ep.load():
            if not issubclass(t, ECU):
                raise ValueError(f"entry_point {t} is not derived from ECU")
            ecus.append(t)
    return ecus


def load_ecu(vendor: str) -> type[ECU]:
    if vendor == "default":
        return ECU

    for ecu in load_ecus():
        if vendor == ecu.OEM:
            return ecu

    raise ValueError(f"no such OEM: '{vendor}'")


class BaseCommand(ABC):
    """GalliaBase is a baseclass for all gallia commands.
    In order to register cli arguments:

    - `configure_class_parser()` can be overwritten to create
       e.g. scanner related arguments shared by all scanners
    - `configure_parser()` can be overwritten to create specific
      arguments for a specific scanner.

    The main entry_point is `run()`.
    """

    COMMAND: str
    CATEGORY: str
    SUBCATEGORY: str | None
    SHORT_HELP: str
    EPILOG: str | None = None

    LOGGER_NAME = "gallia"
    HAS_ARTIFACTS_DIR: bool = False
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
                category=self.CATEGORY,
                subcategory=self.SUBCATEGORY,
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

    def run_hook(self, variant: HookVariant, args: Namespace) -> None:
        script = args.pre_hook if variant == HookVariant.PRE else args.post_hook
        if script is None:
            return

        hook_id = f"{variant.value}-hook"

        env = {
            "GALLIA_ARTIFACTS_DIR": str(self.artifacts_dir),
            "GALLIA_HOOK": variant.value,
        } | os.environ

        p = run(  # pylint: disable=subprocess-run-check
            script, env=env, text=True, capture_output=True, shell=True
        )
        if p.returncode != 0:
            self.logger.warning(
                f"{variant.value}-hook failed (exit code: {p.returncode})"
            )

        if p.stdout:
            self.logger.info(p.stdout.strip(), extra={"tags": [hook_id, "stdout"]})
        if p.stderr:
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
            action="store_true",
            default=self.config.get_value("gallia.trace_log", False),
            help="set the loglevel of the logfile to TRACE",
        )
        group.add_argument(
            "--pre-hook",
            metavar="SCRIPT",
            default=self.config.get_value("gallia.pre_hook", None),
            help="shell script to run before the main entry_point",
        )
        group.add_argument(
            "--post-hook",
            metavar="SCRIPT",
            default=self.config.get_value("gallia.post_hook", None),
            help="shell script to run after the main entry_point",
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
            _command_dir = self.CATEGORY
            if self.SUBCATEGORY is not None:
                _command_dir += f"_{self.SUBCATEGORY}"
            _command_dir += f"_{self.COMMAND}"
            command_dir = base_dir.joinpath(_command_dir)

            _run_dir = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S.%f')}"
            artifacts_dir = command_dir.joinpath(_run_dir).absolute()
            artifacts_dir.mkdir(parents=True)

            self._dump_environment(artifacts_dir.joinpath(FileNames.ENV.value))
            self._add_latest_link(command_dir)

            return artifacts_dir.absolute()

        raise ValueError("base_dir or force_path must be different from None")

    def _aquire_flock(self, path: Path) -> None:
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

        self.run_hook(HookVariant.PRE, args)

        exit_code = 0
        try:
            exit_code = self.run(args)
        except KeyboardInterrupt:
            exit_code = 128 + signal.SIGINT
        # Ensure that META.json gets written in the case a
        # command calls sys.exit().
        except SystemExit as e:
            exit_code = e.code
        except Exception as e:
            for t in self.CATCHED_EXCEPTIONS:
                if isinstance(e, t):
                    exit_code = ExitCodes.GENERIC_ERROR
                    self.logger.critical(g_repr(e))
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

        self.run_hook(HookVariant.POST, args)

        if self._lock_file_fd is not None:
            self._release_flock()

        return exit_code


class Script(BaseCommand, ABC):
    """Script is a base class for a syncronous gallia command.
    To implement a script, create a subclass and implement the
    .main() method."""

    CATEGORY = "script"
    SUBCATEGORY: str | None = None

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

    CATEGORY = "script"
    SUBCATEGORY: str | None = None

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

    CATEGORY = "scan"
    HAS_ARTIFACTS_DIR = True
    CATCHED_EXCEPTIONS: list[type[Exception]] = [
        BrokenPipeError,
        ConnectionRefusedError,
        ConnectionResetError,
        UDSException,
    ]

    def __init__(self, parser: ArgumentParser, config: Config = Config()) -> None:
        super().__init__(parser, config)
        self.db_handler: DBHandler | None = None
        self.power_supply: PowerSupply | None = None
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
                        f"Could not write the run meta to the database: {g_repr(e)}"
                    )

            try:
                await self.db_handler.disconnect()
            except Exception as e:
                self.logger.error(
                    f"Could not close the database connection properly: {g_repr(e)}"
                )

    async def setup(self, args: Namespace) -> None:
        if args.target is None:
            self.parser.error("--target is required")

        if args.power_supply is not None:
            self.power_supply = await PowerSupply.connect(args.power_supply)
            if (time_ := args.power_cycle) is not None:
                await self.power_supply.power_cycle(time_, lambda: asyncio.sleep(2))
        elif args.power_cycle is not None:
            self.parser.error("--power-cycle needs --power-supply")

        # Start dumpcap as the first subprocess; otherwise network
        # traffic might be missing.
        if args.dumpcap:
            self.dumpcap = await Dumpcap.start(args.target, self.artifacts_dir)
            await self.dumpcap.sync()

    async def teardown(self, args: Namespace) -> None:
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
            default=self.config.get_value("gallia.scanner.power_cycle"),
            const=5.0,
            nargs="?",
            type=float,
            help=(
                "trigger a powercycle before starting the scan; "
                "optional argument specifies the sleep time in secs"
            ),
        )

    def entry_point(self, args: Namespace) -> int:
        asyncio.run(self._db_insert_run_meta(args))
        exit_code = super().entry_point(args)
        asyncio.run(self._db_finish_run_meta(args, exit_code))
        return exit_code


class UDSScanner(Scanner):
    """UDSScanner is a baseclass, particularly for scanning tasks
    related to the UDS protocol. The differences to Scanner are:

    - `self.ecu` contains a OEM specific UDS client object.
    - A background tasks sends TesterPresent regularly to avoid timeouts.
    """

    CATEGORY = "scan"
    SUBCATEGORY: str | None = "uds"

    def __init__(self, parser: ArgumentParser, config: Config = Config()) -> None:
        super().__init__(parser, config)
        self.ecu: ECU
        self.transport: BaseTransport
        self._implicit_logging = True

    def configure_class_parser(self) -> None:
        super().configure_class_parser()

        group = self.parser.add_argument_group("UDS scanner related arguments")

        choices = ["default"] + [x.OEM for x in load_ecus()]
        group.add_argument(
            "--ecu-reset",
            const=0x01,
            nargs="?",
            default=self.config.get_value("gallia.protocols.uds.ecu_reset"),
            help="Trigger an initial ecu_reset via UDS; reset level is optional",
        )
        group.add_argument(
            "--oem",
            default=self.config.get_value("gallia.protocols.uds.oem", "default"),
            choices=choices,
            metavar="OEM",
            help="The OEM of the ECU, used to choose a OEM specific ECU implementation",
        )
        group.add_argument(
            "--timeout",
            default=self.config.get_value("gallia.protocols.uds.timeout", 2),
            type=float,
            metavar="SECONDS",
            help="Timeout value to wait for a response from the ECU",
        )
        group.add_argument(
            "--max-retries",
            default=self.config.get_value("gallia.protocols.uds.max_retries", 3),
            type=int,
            metavar="INT",
            help="Number of maximum retries while sending UDS requests",
        )
        group.add_argument(
            "--ping",
            action=argparse.BooleanOptionalAction,
            default=self.config.get_value("gallia.protocols.uds.ping", True),
            help="Enable/Disable initial TesterPresent request",
        )
        group.add_argument(
            "--tester-present-interval",
            default=self.config.get_value(
                "gallia.protocols.uds.tester_present_interval", 0.5
            ),
            type=float,
            metavar="SECONDS",
            help="Modify the interval of the cyclic tester present packets",
        )
        group.add_argument(
            "--tester-present",
            action=argparse.BooleanOptionalAction,
            default=self.config.get_value("gallia.protocols.uds.tester_present", True),
            help="Enable/Disable tester present background worker",
        )
        group.add_argument(
            "--properties",
            default=self.config.get_value("gallia.protocols.uds.properties", True),
            action=argparse.BooleanOptionalAction,
            help="Read and store the ECU proporties prior and after scan",
        )
        group.add_argument(
            "--compare-properties",
            default=self.config.get_value(
                "gallia.protocols.uds.compare_properties", True
            ),
            action=argparse.BooleanOptionalAction,
            help="Compare properties before and after the scan",
        )

    @property
    def implicit_logging(self) -> bool:
        return self._implicit_logging

    @implicit_logging.setter
    def implicit_logging(self, value: bool) -> None:
        self._implicit_logging = value

        if self.db_handler is not None:
            self._apply_implicit_logging_setting()

    def _apply_implicit_logging_setting(self) -> None:
        if self._implicit_logging:
            self.ecu.db_handler = self.db_handler
        else:
            self.ecu.db_handler = None

    async def setup(self, args: Namespace) -> None:
        await super().setup(args)

        self.transport = await load_transport(args.target).connect(args.target)

        self.ecu = load_ecu(args.oem)(
            self.transport,
            timeout=args.timeout,
            max_retry=args.max_retries,
            power_supply=self.power_supply,
        )

        if self.db_handler is not None:
            try:
                # No idea, but str(args.target) fails with a strange traceback.
                # Lets use the attribute directly…
                await self.db_handler.insert_scan_run(args.target.raw)
                self._apply_implicit_logging_setting()
            except Exception as e:
                self.logger.warning(
                    f"Could not write the scan run to the database: {g_repr(e)}"
                )

        if args.ecu_reset is not None:
            resp: UDSResponse = await self.ecu.ecu_reset(args.ecu_reset)
            if isinstance(resp, NegativeResponse):
                self.logger.warning(f"ECUReset failed: {resp}")
                self.logger.warning("Switching to default session")
                raise_for_error(await self.ecu.set_session(0x01))
                resp = await self.ecu.ecu_reset(args.ecu_reset)
                if isinstance(resp, NegativeResponse):
                    self.logger.warning(f"ECUReset in session 0x01 failed: {resp}")

        # Handles connecting to the target and waits
        # until it is ready.
        if args.ping:
            await self.ecu.wait_for_ecu()

        await self.ecu.connect()

        if args.tester_present:
            await self.ecu.start_cyclic_tester_present(args.tester_present_interval)

        if args.properties is True:
            path = self.artifacts_dir.joinpath(FileNames.PROPERTIES_PRE.value)
            async with aiofiles.open(path, "w") as file:
                await file.write(json.dumps(await self.ecu.properties(True), indent=4))
                await file.write("\n")

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_scan_run_properties_pre(
                    await self.ecu.properties()
                )
                self._apply_implicit_logging_setting()
            except Exception as e:
                self.logger.warning(
                    f"Could not write the properties_pre to the database: {g_repr(e)}"
                )

    async def teardown(self, args: Namespace) -> None:
        if args.properties is True and not self.ecu.transport.is_closed:
            path = self.artifacts_dir.joinpath(FileNames.PROPERTIES_POST.value)
            async with aiofiles.open(path, "w") as file:
                await file.write(json.dumps(await self.ecu.properties(True), indent=4))
                await file.write("\n")

            path_pre = self.artifacts_dir.joinpath(FileNames.PROPERTIES_PRE.value)
            async with aiofiles.open(path_pre, "r") as file:
                prop_pre = json.loads(await file.read())

            if args.compare_properties and await self.ecu.properties(False) != prop_pre:
                self.logger.warning("ecu properties differ, please investigate!")

        if self.db_handler is not None:
            try:
                await self.db_handler.complete_scan_run(
                    await self.ecu.properties(False)
                )
            except Exception as e:
                self.logger.warning(
                    f"Could not write the scan run to the database: {g_repr(e)}"
                )

        if args.tester_present:
            await self.ecu.stop_cyclic_tester_present()

        await self.transport.close()

        # This must be the last one.
        await super().teardown(args)


class DiscoveryScanner(Scanner):
    CATEGORY = "discover"

    def configure_class_parser(self) -> None:
        super().configure_class_parser()

        self.parser.add_argument(
            "--timeout",
            type=float,
            default=self.config.get_value("gallia.scanner.timeout", 0.5),
            help="timeout value for request",
        )

    async def setup(self, args: Namespace) -> None:
        await super().setup(args)

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run(args.target.url.scheme)
            except Exception as e:
                self.logger.warning(
                    f"Could not write the discovery run to the database: {g_repr(e)}"
                )
