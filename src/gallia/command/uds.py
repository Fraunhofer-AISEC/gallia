# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import json
from abc import ABC

from pydantic import field_validator

from gallia.command.base import FileNames, Scanner, ScannerConfig
from gallia.command.config import Field
from gallia.log import get_logger
from gallia.plugins.plugin import load_ecu, load_ecus
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.ecu import ECU
from gallia.services.uds.helpers import raise_for_error

logger = get_logger(__name__)


class UDSScannerConfig(ScannerConfig, cli_group="uds", config_section="gallia.protocols.uds"):
    ecu_reset: int | None = Field(
        None,
        description="Trigger an initial ecu_reset via UDS; reset level is optional",
        const=0x01,
    )
    oem: str = Field(
        ECU.OEM,
        description="The OEM of the ECU, used to choose a OEM specific ECU implementation",
        metavar="OEM",
    )
    timeout: float = Field(
        2, description="Timeout value to wait for a response from the ECU", metavar="SECONDS"
    )
    max_retries: int = Field(
        3,
        description="Number of maximum retries while sending UDS requests. If supported by the transport, this will trigger reconnects if required.",
        metavar="INT",
    )
    ping: bool = Field(True, description="Enable/Disable initial TesterPresent request")
    tester_present_interval: float = Field(
        0.5,
        description="Modify the interval of the cyclic tester present packets",
        metavar="SECONDS",
    )
    tester_present: bool = Field(
        True, description="Enable/Disable tester present background worker"
    )
    properties: bool = Field(
        True, description="Read and store the ECU proporties prior and after scan"
    )
    compare_properties: bool = Field(
        True, description="Compare properties before and after the scan"
    )

    @field_validator("oem")
    @classmethod
    def check_oem(cls, v: str) -> str:
        ecu_names = [ecu.OEM for ecu in load_ecus()]

        if v not in ecu_names:
            raise ValueError(f"Not a valid OEM. Use any of {ecu_names}.")

        return v


class UDSScanner(Scanner, ABC):
    """UDSScanner is a baseclass, particularly for scanning tasks
    related to the UDS protocol. The differences to Scanner are:

    - `self.ecu` contains a OEM specific UDS client object.
    - A background tasks sends TesterPresent regularly to avoid timeouts.
    """

    SUBGROUP: str | None = "uds"

    def __init__(self, config: UDSScannerConfig):
        super().__init__(config)
        self.config: UDSScannerConfig = config
        self.ecu: ECU
        self._implicit_logging = True

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

    async def setup(self) -> None:
        await super().setup()

        self.ecu = load_ecu(self.config.oem)(
            self.transport,
            timeout=self.config.timeout,
            max_retry=self.config.max_retries,
            power_supply=self.power_supply,
        )

        self.ecu.db_handler = self.db_handler

        if self.db_handler is not None:
            try:
                # No idea, but str(args.target) fails with a strange traceback.
                # Lets use the attribute directly…
                await self.db_handler.insert_scan_run(self.config.target.raw)
                self._apply_implicit_logging_setting()
            except Exception as e:
                logger.warning(f"Could not write the scan run to the database: {e:!r}")

        if self.config.ecu_reset is not None:
            resp: UDSResponse = await self.ecu.ecu_reset(self.config.ecu_reset)
            if isinstance(resp, NegativeResponse):
                logger.warning(f"ECUReset failed: {resp}")
                logger.warning("Switching to default session")
                raise_for_error(await self.ecu.set_session(0x01))
                resp = await self.ecu.ecu_reset(self.config.ecu_reset)
                if isinstance(resp, NegativeResponse):
                    logger.warning(f"ECUReset in session 0x01 failed: {resp}")

        # Handles connecting to the target and waits
        # until it is ready.
        if self.config.ping:
            await self.ecu.wait_for_ecu()

        await self.ecu.connect()

        if self.config.tester_present:
            await self.ecu.start_cyclic_tester_present(self.config.tester_present_interval)

        if self.config.properties is True:
            path = self.artifacts_dir.joinpath(FileNames.PROPERTIES_PRE.value)
            path.write_text(json.dumps(await self.ecu.properties(True), indent=4) + "\n")

        if self.db_handler is not None:
            self._apply_implicit_logging_setting()

            if self.config.properties is True:
                try:
                    await self.db_handler.insert_scan_run_properties_pre(
                        await self.ecu.properties()
                    )
                except Exception as e:
                    logger.warning(f"Could not write the properties_pre to the database: {e!r}")

    async def teardown(self) -> None:
        if self.config.properties is True and (not self.ecu.transport.is_closed):
            path = self.artifacts_dir.joinpath(FileNames.PROPERTIES_POST.value)
            path.write_text(json.dumps(await self.ecu.properties(True), indent=4) + "\n")

            path_pre = self.artifacts_dir.joinpath(FileNames.PROPERTIES_PRE.value)
            prop_pre = json.loads(path_pre.read_text())

            if self.config.compare_properties and await self.ecu.properties(False) != prop_pre:
                logger.warning("ecu properties differ, please investigate!")

        if self.db_handler is not None and self.config.properties is True:
            try:
                await self.db_handler.complete_scan_run(await self.ecu.properties(False))
            except Exception as e:
                logger.warning(f"Could not write the scan run to the database: {e!r}")

        if self.config.tester_present:
            await self.ecu.stop_cyclic_tester_present()

        # This must be the last one.
        await super().teardown()


class UDSDiscoveryScannerConfig(ScannerConfig):
    timeout: float = Field(0.5, description="timeout value for request")


class UDSDiscoveryScanner(Scanner, ABC):
    def __init__(self, config: UDSDiscoveryScannerConfig):
        super().__init__(config)
        self.config: UDSDiscoveryScannerConfig = config

    async def setup(self) -> None:
        await super().setup()

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run(self.config.target.url.scheme)
            except Exception as e:
                logger.warning(f"Could not write the discovery run to the database: {e!r}")
