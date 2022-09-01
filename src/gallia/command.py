# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import traceback
from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace
from datetime import datetime, timezone
from enum import Enum, IntEnum, unique
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from tempfile import gettempdir
from typing import Any, Optional, cast

import aiofiles
import msgspec

from gallia.config import ConfigType
from gallia.db.db_handler import DBHandler
from gallia.dumpcap import Dumpcap
from gallia.log import get_logger, setup_logging, tz
from gallia.powersupply import PowerSupply, PowerSupplyURI
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
    UNHANDLED_EXCEPTION = 2


@unique
class FileNames(Enum):
    PROPERTIES_PRE = "PROPERTIES_PRE.json"
    PROPERTIES_POST = "PROPERTIES_POST.json"
    META = "META.json"
    ENV = "ENV"


class CommandMeta(msgspec.Struct):
    category: str
    subcategory: Optional[str]
    command: str


class RunMeta(msgspec.Struct):
    command: list[str]
    command_meta: CommandMeta
    start_time: str
    end_time: str
    exit_code: int


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

    - `configure_class_parser()` can be overwritten to create
       e.g. scanner related arguments shared by all scanners
    - `configure_parser()` can be overwritten to create specific
      arguments for a specific scanner.

    The main entry_point is `run()`.
    """

    COMMAND: str
    CATEGORY: str
    SUBCATEGORY: Optional[str]
    SHORT_HELP: str
    EPILOG: Optional[str] = None

    LOGGER_NAME = "gallia"
    HAS_ARTIFACTS_DIR: bool = False
    CATCHED_EXCEPTIONS: list[type[Exception]] = []

    def __init__(self, parser: ArgumentParser, config: ConfigType) -> None:
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
        self.configure_class_parser()
        self.configure_parser()

    @abstractmethod
    def run(self, args: Namespace) -> int:
        ...

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

    def get_log_level(self, args: Namespace) -> int:
        level = logging.INFO
        if args.verbose == 1:
            level = logging.DEBUG
        elif args.verbose >= 2:
            level = logging.TRACE  # type: ignore
        return level

    def get_file_log_level(self, args: Namespace) -> int:
        return logging.TRACE if args.verbose >= 2 else logging.DEBUG  # type: ignore

    def configure_class_parser(self) -> None:
        group = self.parser.add_argument_group("generic arguments")
        group.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=self.get_config_value("gallia.verbosity", 0),
            help="increase verbosity on the console",
        )

        if self.HAS_ARTIFACTS_DIR is False:
            return

        _mutex_group = group.add_mutually_exclusive_group()
        _mutex_group.add_argument(
            "--artifacts-dir",
            default=self.config.get("gallia.scanner.artifacts_dir"),
            type=Path,
            metavar="DIR",
            help="Folder for artifacts",
        )
        _mutex_group.add_argument(
            "--artifacts-base",
            default=self.config.get(
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
        base_dir: Optional[Path] = None,
        force_path: Optional[Path] = None,
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

    def entry_point(self, args: Namespace) -> int:
        if self.HAS_ARTIFACTS_DIR:
            self.artifacts_dir = self.prepare_artifactsdir(
                args.artifacts_base,
                args.artifacts_dir,
            )
            setup_logging(
                self.get_log_level(args),
                self.get_file_log_level(args),
                self.artifacts_dir.joinpath("log.json.zst"),
            )
        else:
            setup_logging(self.get_log_level(args))

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

        return exit_code


class Script(BaseCommand, ABC):
    """Script is a base class for a syncronous gallia command.
    To implement a script, create a subclass and implement the
    .main() method."""

    CATEGORY = "script"
    SUBCATEGORY: Optional[str] = None

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
    SUBCATEGORY: Optional[str] = None

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
    ]

    def __init__(self, parser: ArgumentParser, config: dict[str, Any]) -> None:
        super().__init__(parser, config)
        self.db_handler: Optional[DBHandler] = None
        self.power_supply: Optional[PowerSupply] = None
        self.dumpcap: Optional[Dumpcap] = None

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
            default=self.get_config_value("gallia.scanner.db"),
            type=Path,
            help="Path to sqlite3 database",
        )
        group.add_argument(
            "--dumpcap",
            action=argparse.BooleanOptionalAction,
            default=self.get_config_value("gallia.scanner.dumpcap", default=True),
            help="Enable/Disable creating a pcap file",
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
    SUBCATEGORY = "uds"

    def __init__(self, parser: ArgumentParser, config: dict[str, Any]) -> None:
        super().__init__(parser, config)
        self.ecu: ECU
        self.transport: BaseTransport
        self._implicit_logging = True

    def configure_class_parser(self) -> None:
        super().configure_class_parser()

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
        if args.properties is True:
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
            default=self.get_config_value("gallia.scanner.timeout", 0.5),
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
