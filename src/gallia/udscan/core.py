# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import asyncio
import json
import os
import signal
import sys
import time
import traceback
from abc import ABC, abstractmethod
from argparse import ArgumentDefaultsHelpFormatter, Namespace
from asyncio import Task
from datetime import datetime, timezone
from enum import Enum, IntEnum
from importlib.metadata import EntryPoint, entry_points, version
from pathlib import Path
from secrets import token_urlsafe
from tempfile import gettempdir
from typing import Any, Optional, cast

import aiofiles
import argcomplete

from gallia.db.db_handler import DBHandler
from gallia.penlab import Dumpcap, PowerSupply, PowerSupplyURI
from gallia.penlog import Logger
from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.can import ISOTPTransport, RawCANTransport
from gallia.transports.doip import DoIPTransport
from gallia.transports.tcp import TCPLineSepTransport
from gallia.uds.ecu import ECU
from gallia.utils import camel_to_snake, g_repr


class ExitCodes(IntEnum):
    SUCCESS = 0
    GENERIC_ERROR = 1
    SETUP_FAILED = 10
    TEARDOWN_FAILED = 11


class FileNames(Enum):
    PROPERTIES_PRE = "PROPERTIES_PRE.json"
    PROPERTIES_POST = "PROPERTIES_POST.json"


class Formatter(ArgumentDefaultsHelpFormatter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # This is for steff.
        help_width = os.getenv("GALLIA_HELP_WIDTH")
        if help_width is not None:
            kwargs["width"] = int(help_width)
        super().__init__(*args, **kwargs)


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
    if "gallia_ecus" in eps:
        for entry_point in eps["gallia_ecus"]:
            if vendor == entry_point.name:
                return entry_point.load()

    raise ValueError(f"no such OEM: '{vendor}'")


class GalliaBase(ABC):
    """GalliaBase is a baseclass for all gallia commands.
    In order to register cli arguments:

    - `add_class_parser()` can be overwritten to create
       e.g. scanner related arguments shared by all scanners
    - `add_parser()` can be overwritten to create specific
      arguments for a specific scanner.

    The main entry_point is `run()`.
    """

    def __init__(self) -> None:
        self.description = self.__class__.__doc__
        self.logger = Logger(component="gallia", flush=True)
        self.db_handler: Optional[DBHandler] = None
        self.parser = argparse.ArgumentParser(
            description=self.description, formatter_class=Formatter
        )
        self.id = camel_to_snake(self.__class__.__name__)
        self.add_class_parser()
        self.add_parser()

    def add_class_parser(self) -> None:
        ...

    def add_parser(self) -> None:
        ...

    @abstractmethod
    def run(self) -> int:
        ...


class Script(GalliaBase, ABC):
    """Script is a base class for a syncronous gallia command.
    To implement a script, create a subclass and implement the
    .main() method."""

    @abstractmethod
    def main(self, args: Namespace) -> None:
        ...

    def run(self) -> int:
        argcomplete.autocomplete(self.parser)
        args = self.parser.parse_args()

        try:
            self.main(args)
            return 0
        except KeyboardInterrupt:
            return 128 + signal.SIGINT


class AsyncScript(GalliaBase, ABC):
    """AsyncScript is a base class for a asyncronous gallia command.
    To implement an async script, create a subclass and implement
    the .main() method."""

    @abstractmethod
    async def main(self, args: Namespace) -> None:
        ...

    def run(self) -> int:
        argcomplete.autocomplete(self.parser)
        args = self.parser.parse_args()

        try:
            asyncio.run(self.main(args))
            return 0
        except KeyboardInterrupt:
            return 128 + signal.SIGINT


class Scanner(GalliaBase, ABC):
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

    def __init__(self) -> None:
        super().__init__()
        self.artifacts_dir: Path
        self.power_supply: Optional[PowerSupply] = None
        self.dumpcap: Optional[Dumpcap] = None

    @abstractmethod
    async def main(self, args: Namespace) -> None:
        ...

    async def setup(self, args: Namespace) -> None:
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
        group.add_argument(
            "--data-dir",
            default=os.environ.get("PENRUN_ARTIFACTS"),
            type=Path,
            help="Folder for artifacts",
        )
        group.add_argument(
            "--db",
            default=os.environ.get("GALLIA_DB"),
            type=Path,
            help="Path to sqlite3 database",
        )

        group = self.parser.add_argument_group("transport mode related arguments")
        group.add_argument(
            "--target",
            metavar="TARGET",
            default=os.environ.get("GALLIA_TARGET"),
            type=TargetURI,
            help="URI that describes the target",
        )

        group = self.parser.add_argument_group("power supply related arguments")
        group.add_argument(
            "--power-supply",
            metavar="URI",
            default=os.environ.get("GALLIA_POWER_SUPPLY"),
            type=PowerSupplyURI,
            help="URI specifying the location of the relevant opennetzteil server",
        )
        group.add_argument(
            "--power-cycle",
            default=os.environ.get("GALLIA_POWER_CYCLE"),
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
            default=True,
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

    def run(self) -> int:
        argcomplete.autocomplete(self.parser)
        args = self.parser.parse_args()

        self.artifacts_dir = self.prepare_artifactsdir(args.data_dir)
        self.logger.log_preamble(f"Storing artifacts at {self.artifacts_dir}")
        self.logger.log_preamble(
            f'Starting "{sys.argv[0]}" ({version("gallia")}) with [{" ".join(sys.argv)}]'
        )

        try:
            return asyncio.run(self._run(args))
        except KeyboardInterrupt:
            self.logger.log_critical("ctrl+c received. Terminating…")
            return 128 + signal.SIGINT
        finally:
            self.logger.log_info(
                f"The scan results are located at: {self.artifacts_dir}"
            )


class UDSScanner(Scanner):
    """UDSScanner is a baseclass, particularly for scanning tasks
    related to the UDS protocol. The differences to Scanner are:

    - `self.ecu` contains a OEM specific UDS client object.
    - A background tasks sends TesterPresent regularly to avoid timeouts.
    """

    def __init__(self) -> None:
        super().__init__()
        self.ecu: ECU
        self.transport: BaseTransport
        self.tester_present_task: Optional[Task] = None
        self._implicit_logging = True
        self.log_scan_run = True  # TODO: Remove this as soon as find-endpoint is fixed

    def add_class_parser(self) -> None:
        super().add_class_parser()

        group = self.parser.add_argument_group("UDS scanner related arguments")

        eps = entry_points()
        choices = (
            [x.name for x in eps["gallia_ecus"]]
            if "gallia_ecus" in eps
            else ["default"]
        )
        choices = ["default"] + choices
        group.add_argument(
            "--oem",
            default=os.environ.get("GALLIA_OEM", "default"),
            choices=choices,
            metavar="OEM",
            help="The OEM of the ECU, used to choose a OEM specific ECU implementation",
        )
        group.add_argument(
            "--timeout",
            default=2,
            type=float,
            metavar="SECONDS",
            help="Timeout value to wait for a response from the ECU",
        )
        group.add_argument(
            "--max-retries",
            default=3,
            type=int,
            metavar="INT",
            help="Number of maximum retries while sending UDS requests",
        )
        group.add_argument(
            "--ping",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="Enable/Disable initial TesterPresent request",
        )
        group.add_argument(
            "--tester-present-interval",
            default=0.5,
            type=float,
            metavar="SECONDS",
            help="Modify the interval of the cyclic tester present packets",
        )
        group.add_argument(
            "--tester-present",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="Enable/Disable tester present background worker",
        )
        group.add_argument(
            "--properties",
            default=True,
            action=argparse.BooleanOptionalAction,
            help="Read and store the ECU proporties prior and after scan",
        )
        group.add_argument(
            "--compare-properties",
            default=True,
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

        if self.db_handler is not None and self.log_scan_run:
            try:
                await self.db_handler.insert_scan_run(str(args.target))
                self._apply_implicit_logging_setting()
            except Exception as e:
                self.logger.log_warning(
                    f"Could not write the scan run to the database: {g_repr(e)}"
                )

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

        if self.db_handler is not None and self.log_scan_run:
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

        if self.db_handler is not None and self.log_scan_run:
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
    def add_class_parser(self) -> None:
        super().add_class_parser()

        self.parser.add_argument(
            "--timeout",
            type=float,
            default=0.5,
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
