# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import asyncio
import json
import signal
import sys
import time
import traceback
from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from asyncio import Task
from copy import deepcopy
from datetime import datetime, timezone
from enum import Enum, IntEnum, unique
from importlib.metadata import EntryPoint, entry_points, version
from pathlib import Path
from secrets import token_urlsafe
from tempfile import gettempdir
from typing import Any, Optional, cast

import aiofiles

from gallia.db.db_handler import DBHandler
from gallia.penlab import Dumpcap, PowerSupply, PowerSupplyURI
from gallia.penlog import Logger
from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.can import ISOTPTransport, RawCANTransport
from gallia.transports.doip import DoIPTransport
from gallia.transports.tcp import TCPLineSepTransport
from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.uds.ecu import ECU
from gallia.uds.helpers import raise_for_error
from gallia.utils import camel_to_snake, g_repr


@unique
class ExitCodes(IntEnum):
    SUCCESS = 0
    GENERIC_ERROR = 1
    SETUP_FAILED = 10
    TEARDOWN_FAILED = 11


@unique
class FileNames(Enum):
    PROPERTIES_PRE = "PROPERTIES_PRE.json"
    PROPERTIES_POST = "PROPERTIES_POST.json"


def load_transport(target: TargetURI) -> BaseTransport:
    transports = [
        ISOTPTransport,
        RawCANTransport,
        DoIPTransport,
        TCPLineSepTransport,
    ]

    def func(x: EntryPoint) -> type[BaseTransport]:
        t = x.load()
        if not issubclass(t, BaseTransport):
            raise ValueError(f"{type(x)} is not derived from BaseTransport")
        return cast(type[BaseTransport], t)

    eps = entry_points()
    if "gallia_transports" in eps:
        transports_eps = map(func, eps["gallia_transports"])
        transports += transports_eps

    for transport in transports:
        if target.scheme == transport.SCHEME:  # type: ignore
            t = transport(target)
            return t

    raise ValueError(f"no transport for {target}")


def load_ecu(vendor: str) -> type[ECU]:
    if vendor == "default":
        return ECU

    eps = entry_points()
    if "gallia_uds_ecus" in eps:
        for entry_point in eps["gallia_uds_ecus"]:
            if vendor == entry_point.name:
                return entry_point.load()

    raise ValueError(f"no such OEM: '{vendor}'")


class BaseCommand(ABC):
    """GalliaBase is a baseclass for all gallia commands.
    In order to register cli arguments:

    - `add_class_parser()` can be overwritten to create
       e.g. scanner related arguments shared by all scanners
    - `add_parser()` can be overwritten to create specific
      arguments for a specific scanner.

    The main entry_point is `run()`.
    """

    COMMAND: str
    CATEGORY: str
    SUBCATEGORY: Optional[str]
    SHORT_HELP: str
    EPILOG: Optional[str] = None

    def __init__(self, parser: ArgumentParser, config: dict[str, Any]) -> None:
        self.id = camel_to_snake(self.__class__.__name__)
        self.logger = Logger(component="gallia", flush=True)
        self.parser = parser
        self.config = config
        self.add_class_parser()
        self.add_parser()

    def get_config_value(
        self,
        key: str,
        default: Optional[Any] = None,
    ) -> Optional[Any]:
        parts = key.split(".")
        subdict: Optional[dict[str, Any]] = self.config
        val: Optional[Any] = None

        for part in parts:
            if subdict is None:
                return default

            val = subdict.get(part)
            subdict = val if isinstance(val, dict) else None

        return val if val is not None else default

    def add_class_parser(self) -> None:
        ...

    def add_parser(self) -> None:
        ...

    @abstractmethod
    def run(self, args: Namespace) -> int:
        ...


class Script(BaseCommand, ABC):
    """Script is a base class for a syncronous gallia command.
    To implement a script, create a subclass and implement the
    .main() method."""

    CATEGORY = "script"
    SUBCATEGORY = None

    @abstractmethod
    def main(self, args: Namespace) -> None:
        ...

    def run(self, args: Namespace) -> int:
        try:
            self.main(args)
            return 0
        except KeyboardInterrupt:
            return 128 + signal.SIGINT


class AsyncScript(BaseCommand, ABC):
    """AsyncScript is a base class for a asyncronous gallia command.
    To implement an async script, create a subclass and implement
    the .main() method."""

    CATEGORY = "script"
    SUBCATEGORY = None

    @abstractmethod
    async def main(self, args: Namespace) -> None:
        ...

    def run(self, args: Namespace) -> int:
        try:
            asyncio.run(self.main(args))
            return 0
        except KeyboardInterrupt:
            return 128 + signal.SIGINT


class Scanner(BaseCommand, ABC):
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

    def __init__(self, parser: ArgumentParser, config: dict[str, Any]) -> None:
        super().__init__(parser, config)
        self.artifacts_dir: Path
        self.db_handler: Optional[DBHandler] = None
        self.power_supply: Optional[PowerSupply] = None
        self.dumpcap: Optional[Dumpcap] = None

    @abstractmethod
    async def main(self, args: Namespace) -> None:
        ...

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

    def add_class_parser(self) -> None:
        super().add_class_parser()

        group = self.parser.add_argument_group("generic gallia arguments")

        _mutex_group = group.add_mutually_exclusive_group()
        _mutex_group.add_argument(
            "--artifacts-dir",
            default=self.config.get("gallia.scanner.artifacts_dir"),
            type=Path,
            help="Folder for artifacts",
        )
        _mutex_group.add_argument(
            "--artifacts-base",
            default=self.config.get("gallia.scanner.artifacts_base"),
            type=Path,
            help="Base directory for artifacts",
        )

        group.add_argument(
            "--db",
            default=self.get_config_value("gallia.scanner.db"),
            type=Path,
            help="Path to sqlite3 database",
        )

        group = self.parser.add_argument_group("transport mode related arguments")
        group.add_argument(
            "--target",
            metavar="TARGET",
            default=self.get_config_value("gallia.scanner.target"),
            type=TargetURI,
            help="URI that describes the target",
        )

        group = self.parser.add_argument_group("power supply related arguments")
        group.add_argument(
            "--power-supply",
            metavar="URI",
            default=self.get_config_value("gallia.scanner.power_supply"),
            type=PowerSupplyURI,
            help="URI specifying the location of the relevant opennetzteil server",
        )
        group.add_argument(
            "--power-cycle",
            default=self.get_config_value("gallia.scanner.power_cycle"),
            const=5.0,
            nargs="?",
            type=float,
            help=(
                "trigger a powercycle before starting the scan; "
                "optional argument specifies the sleep time in secs"
            ),
        )
        group.add_argument(
            "--dumpcap",
            action=argparse.BooleanOptionalAction,
            default=self.get_config_value("gallia.scanner.dumpcap", default=True),
            help="Enable/Disable creating a pcap file",
        )

    def prepare_artifactsdir(self, path: Optional[Path]) -> Path:
        if path is None:
            base = Path(gettempdir())
            p = base.joinpath(
                f'{self.id}_{time.strftime("%Y%m%d-%H%M%S")}_{token_urlsafe(6)}'
            )
            p.mkdir(parents=True)
            return p

        if path.is_dir():
            return path

        self.logger.log_error(f"Data directory {path} is not an existing directory.")
        sys.exit(1)

    async def _run(self, args: Namespace) -> int:
        exit_code: int = ExitCodes.SUCCESS

        try:
            if args.db is not None:
                self.db_handler = DBHandler(args.db)
                await self.db_handler.connect()

                await self.db_handler.insert_run_meta(
                    script=sys.argv[0].split()[-1],
                    arguments=sys.argv[1:],
                    start_time=datetime.now(timezone.utc).astimezone(),
                    path=self.artifacts_dir,
                )

            try:
                await self.setup(args)
            except BrokenPipeError as e:
                exit_code = ExitCodes.GENERIC_ERROR
                self.logger.log_critical(g_repr(e))
            except Exception as e:
                self.logger.log_critical(f"setup failed: {g_repr(e)}")
                sys.exit(ExitCodes.SETUP_FAILED)

            try:
                try:
                    await self.main(args)
                except Exception as e:
                    exit_code = ExitCodes.GENERIC_ERROR
                    self.logger.log_critical(g_repr(e))
                    traceback.print_exc()
            finally:
                try:
                    await self.teardown(args)
                except Exception as e:
                    self.logger.log_critical(f"teardown failed: {g_repr(e)}")
                    sys.exit(ExitCodes.TEARDOWN_FAILED)
            return exit_code
        except KeyboardInterrupt:
            exit_code = 128 + signal.SIGINT
            raise
        except SystemExit as se:
            exit_code = se.code
            raise
        finally:
            if self.db_handler is not None and self.db_handler.connection is not None:
                if self.db_handler.meta is not None:
                    try:
                        await self.db_handler.complete_run_meta(
                            datetime.now(timezone.utc).astimezone(), exit_code
                        )
                    except Exception as e:
                        self.logger.log_warning(
                            f"Could not write the run meta to the database: {g_repr(e)}"
                        )

                try:
                    await self.db_handler.disconnect()
                except Exception as e:
                    self.logger.log_error(
                        f"Could not close the database connection properly: {g_repr(e)}"
                    )

    def run(self, args: Namespace) -> int:
        self.artifacts_dir = self.prepare_artifactsdir(args.artifacts_dir)
        self.logger.log_preamble(f"Storing artifacts at {self.artifacts_dir}")

        argv = deepcopy(sys.argv)
        argv[0] = Path(sys.argv[0]).name
        self.logger.log_preamble(
            f'Starting "{sys.argv[0]}" ({version("gallia")}) with [{" ".join(argv)}]'
        )

        try:
            return asyncio.run(self._run(args))
        except KeyboardInterrupt:
            self.logger.log_critical("ctrl+c received. Terminating…")
            return 128 + signal.SIGINT


class UDSScanner(Scanner):
    """UDSScanner is a baseclass, particularly for scanning tasks
    related to the UDS protocol. The differences to Scanner are:

    - `self.ecu` contains a OEM specific UDS client object.
    - A background tasks sends TesterPresent regularly to avoid timeouts.
    """

    CATEGORY = "scan"
    SUBCATEGORY = "uds"

    def __init__(self, parser: ArgumentParser, config: dict[str, Any]) -> None:
        super().__init__(parser, config)
        self.ecu: ECU
        self.transport: BaseTransport
        self.tester_present_task: Optional[Task] = None
        self._implicit_logging = True

    def add_class_parser(self) -> None:
        super().add_class_parser()

        group = self.parser.add_argument_group("UDS scanner related arguments")

        eps = entry_points()
        choices = (
            [x.name for x in eps["gallia_uds_ecus"]]
            if "gallia_uds_ecus" in eps
            else ["default"]
        )
        choices = ["default"] + choices
        group.add_argument(
            "--ecu-reset",
            const=0x01,
            nargs="?",
            default=self.get_config_value("gallia.protocols.uds.ecu_reset"),
            help="Trigger an initial ecu_reset via UDS; reset level is optional",
        )
        group.add_argument(
            "--oem",
            default=self.get_config_value("gallia.protocols.uds.oem", "default"),
            choices=choices,
            metavar="OEM",
            help="The OEM of the ECU, used to choose a OEM specific ECU implementation",
        )
        group.add_argument(
            "--timeout",
            default=self.get_config_value("gallia.protocols.uds.timeout", 2),
            type=float,
            metavar="SECONDS",
            help="Timeout value to wait for a response from the ECU",
        )
        group.add_argument(
            "--max-retries",
            default=self.get_config_value("gallia.protocols.uds.max_retries", 3),
            type=int,
            metavar="INT",
            help="Number of maximum retries while sending UDS requests",
        )
        group.add_argument(
            "--ping",
            action=argparse.BooleanOptionalAction,
            default=self.get_config_value("gallia.protocols.uds.ping", True),
            help="Enable/Disable initial TesterPresent request",
        )
        group.add_argument(
            "--tester-present-interval",
            default=self.get_config_value(
                "gallia.protocols.uds.tester_present_interval", 0.5
            ),
            type=float,
            metavar="SECONDS",
            help="Modify the interval of the cyclic tester present packets",
        )
        group.add_argument(
            "--tester-present",
            action=argparse.BooleanOptionalAction,
            default=self.get_config_value("gallia.protocols.uds.tester_present", True),
            help="Enable/Disable tester present background worker",
        )
        group.add_argument(
            "--properties",
            default=self.get_config_value("gallia.protocols.uds.properties", True),
            action=argparse.BooleanOptionalAction,
            help="Read and store the ECU proporties prior and after scan",
        )
        group.add_argument(
            "--compare-properties",
            default=self.get_config_value(
                "gallia.protocols.uds.compare_properties", True
            ),
            action=argparse.BooleanOptionalAction,
            help="Compare properties before and after the scan",
        )

    async def _tester_present_worker(self, interval: int) -> None:
        assert self.transport
        self.logger.log_debug("tester present worker started")
        while True:
            try:
                async with self.transport.mutex:
                    await self.transport.write(bytes([0x3E, 0x80]), tags=["IGNORE"])

                    # Hold the mutex for 10 ms to synchronize this background
                    # worker with the main sender task.
                    await asyncio.sleep(0.01)

                    # The BCP might send us an error. Everything
                    # will break if we do not read it back. Since
                    # this read() call is only intended to flush
                    # errors caused by the previous write(), it is
                    # sane to ignore the error here.
                    try:
                        await self.transport.read(timeout=0.01)
                    except asyncio.TimeoutError:
                        pass
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                self.logger.log_debug("tester present worker terminated")
                break
            except Exception as e:
                self.logger.log_debug(f"tester present got {g_repr(e)}")
                # Wait until the stack recovers, but not for too long…
                await asyncio.sleep(1)

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

        self.transport = load_transport(args.target)
        await self.transport.connect(None)

        self.ecu = load_ecu(args.oem)(
            self.transport,
            timeout=args.timeout,
            max_retry=args.max_retries,
            power_supply=self.power_supply,
        )

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_scan_run(str(args.target))
                self._apply_implicit_logging_setting()
            except Exception as e:
                self.logger.log_warning(
                    f"Could not write the scan run to the database: {g_repr(e)}"
                )

        if args.ecu_reset is not None:
            resp: UDSResponse = await self.ecu.ecu_reset(args.ecu_reset)
            if isinstance(resp, NegativeResponse):
                self.logger.log_warning(f"ECUReset failed: {resp}")
                self.logger.log_warning("Switching to default session")
                raise_for_error(await self.ecu.set_session(0x01))
                resp = await self.ecu.ecu_reset(args.ecu_reset)
                if isinstance(resp, NegativeResponse):
                    self.logger.log_warning(f"ECUReset in session 0x01 failed: {resp}")

        # Handles connecting to the target and waits
        # until it is ready.
        if args.ping:
            await self.ecu.wait_for_ecu()
        await self.ecu.connect()

        if args.tester_present:
            coroutine = self._tester_present_worker(args.tester_present_interval)
            self.tester_present_task = asyncio.create_task(coroutine)

            # enforce context switch
            # this ensures, that the task is executed at least once
            # if the task is not executed, task.cancel will fail with CancelledError
            await asyncio.sleep(0)

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
                self.logger.log_warning(
                    f"Could not write the properties_pre to the database: {g_repr(e)}"
                )

    async def teardown(self, args: Namespace) -> None:
        if args.properties is True:
            path = self.artifacts_dir.joinpath(FileNames.PROPERTIES_POST.value)
            async with aiofiles.open(path, "w") as file:
                await file.write(json.dumps(await self.ecu.properties(True), indent=4))
                await file.write("\n")

            path_pre = self.artifacts_dir.joinpath(FileNames.PROPERTIES_PRE.value)
            async with aiofiles.open(path_pre, "r") as file:
                prop_pre = json.loads(await file.read())

            if args.compare_properties and await self.ecu.properties(False) != prop_pre:
                self.logger.log_warning("ecu properties differ, please investigate!")

        if self.db_handler is not None:
            try:
                await self.db_handler.complete_scan_run(
                    await self.ecu.properties(False)
                )
            except Exception as e:
                self.logger.log_warning(
                    f"Could not write the scan run to the database: {g_repr(e)}"
                )

        if self.tester_present_task:
            self.tester_present_task.cancel()
            await self.tester_present_task

        await self.transport.close()

        # This must be the last one.
        await super().teardown(args)


class DiscoveryScanner(Scanner):
    CATEGORY = "discover"

    def add_class_parser(self) -> None:
        super().add_class_parser()

        self.parser.add_argument(
            "--timeout",
            type=float,
            default=self.get_config_value("gallia.scanner.timeout", 0.5),
            help="timeout value for request",
        )

    async def setup(self, args: Namespace) -> None:
        await super().setup(args)

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run(args.target.url.scheme)
            except Exception as e:
                self.logger.log_warning(
                    f"Could not write the discovery run to the database: {g_repr(e)}"
                )