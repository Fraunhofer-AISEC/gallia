# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import json
from argparse import ArgumentParser, BooleanOptionalAction, Namespace

import aiofiles

from gallia.command.base import FileNames, Scanner
from gallia.config import Config
from gallia.plugins import load_ecu, load_ecu_plugins
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.ecu import ECU
from gallia.services.uds.helpers import raise_for_error


class UDSScanner(Scanner):
    """UDSScanner is a baseclass, particularly for scanning tasks
    related to the UDS protocol. The differences to Scanner are:

    - `self.ecu` contains a OEM specific UDS client object.
    - A background tasks sends TesterPresent regularly to avoid timeouts.
    """

    GROUP = "scan"
    SUBGROUP: str | None = "uds"

    def __init__(self, parser: ArgumentParser, config: Config = Config()) -> None:
        super().__init__(parser, config)
        self.ecu: ECU
        self._implicit_logging = True

    def configure_class_parser(self) -> None:
        super().configure_class_parser()

        group = self.parser.add_argument_group("UDS scanner related arguments")

        choices = ["default"] + [x.OEM for x in load_ecu_plugins()]
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
            action=BooleanOptionalAction,
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
            action=BooleanOptionalAction,
            default=self.config.get_value("gallia.protocols.uds.tester_present", True),
            help="Enable/Disable tester present background worker",
        )
        group.add_argument(
            "--properties",
            default=self.config.get_value("gallia.protocols.uds.properties", True),
            action=BooleanOptionalAction,
            help="Read and store the ECU proporties prior and after scan",
        )
        group.add_argument(
            "--compare-properties",
            default=self.config.get_value(
                "gallia.protocols.uds.compare_properties", True
            ),
            action=BooleanOptionalAction,
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
        self.ecu.implicit_logging = self._implicit_logging

    async def setup(self, args: Namespace) -> None:
        await super().setup(args)

        self.ecu = load_ecu(args.oem)(
            self.transport,
            timeout=args.timeout,
            max_retry=args.max_retries,
            power_supply=self.power_supply,
        )

        self.ecu.db_handler = self.db_handler

        if self.db_handler is not None:
            try:
                # No idea, but str(args.target) fails with a strange traceback.
                # Lets use the attribute directly…
                await self.db_handler.insert_scan_run(args.target.raw)
                self._apply_implicit_logging_setting()
            except Exception as e:
                self.logger.warning(
                    f"Could not write the scan run to the database: {e:!r}"
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
                    f"Could not write the properties_pre to the database: {e!r}"
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
                    f"Could not write the scan run to the database: {e!r}"
                )

        if args.tester_present:
            await self.ecu.stop_cyclic_tester_present()

        # This must be the last one.
        await super().teardown(args)


class UDSDiscoveryScanner(Scanner):
    GROUP = "discover"

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
                    f"Could not write the discovery run to the database: {e!r}"
                )
