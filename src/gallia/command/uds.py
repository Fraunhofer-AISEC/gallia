# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from abc import ABC
from typing import Any, Self

from pydantic import field_serializer, field_validator, model_validator

from gallia.command.base import AsyncScript, AsyncScriptConfig, FileNames
from gallia.command.config import Field, InitializeIdempotent
from gallia.log import get_logger
from gallia.plugins.plugin import load_ecu, load_ecus, load_transport
from gallia.power_supply import PowerSupply
from gallia.power_supply.uri import PowerSupplyURI
from gallia.services.uds.core.exception import UDSException
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.ecu import ECU
from gallia.services.uds.helpers import raise_for_error
from gallia.transports.base import BaseTransport, TargetURI

logger = get_logger(__name__)


class UDSScannerConfig(AsyncScriptConfig, cli_group="uds", config_section="gallia.uds"):
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
        description="Time interval between cyclic tester present requests of the background worker",
        metavar="SECONDS",
    )
    tester_present: bool = Field(
        True, description="Enable/Disable tester present background worker"
    )
    tester_present_timeout: float = Field(
        1, description="Timeout of requests send by tester present background worker"
    )
    tester_present_ignore_activity: bool = Field(
        False,
        description="TesterPresent messages are sent if there is no UDS-activity for `interval` amount of time. If setting this to 'true', messages are instead sent every `interval` seconds.",
    )
    properties: bool = Field(
        True, description="Read and store the ECU proporties prior and after scan"
    )
    compare_properties: bool = Field(
        True, description="Compare properties before and after the scan"
    )
    dumpcap: bool = Field(
        sys.platform.startswith("linux"), description="Enable/Disable creating a pcap file"
    )
    target: InitializeIdempotent[TargetURI] = Field(
        description="URI that describes the target", metavar="TARGET"
    )
    power_supply: InitializeIdempotent[PowerSupplyURI] | None = Field(
        None,
        description="URI specifying the location of the relevant opennetzteil server",
        metavar="URI",
    )
    power_cycle: bool = Field(
        False,
        description="use the configured power supply to power-cycle the ECU when needed (e.g. before starting the scan, or to recover bad state during scanning)",
    )
    power_cycle_sleep: float = Field(
        5.0, description="time to sleep after the power-cycle", metavar="SECs"
    )
    transport: BaseTransport | None = Field(
        None,
        description="If a transport is provided, it basically overrides 'target' and skips 'load_transport'.",
        hidden=True,
        exclude=True,
    )

    @field_serializer("target", "power_supply")
    def serialize_target_uri(self, target_uri: TargetURI | None) -> Any:
        if target_uri is None:
            return None

        return target_uri.raw

    @model_validator(mode="after")
    def check_power_supply_required(self) -> Self:
        if self.power_cycle and self.power_supply is None:
            raise ValueError("power-cycle needs power-supply")

        return self

    @field_validator("oem")
    @classmethod
    def check_oem(cls, v: str) -> str:
        ecu_names = [ecu.OEM for ecu in load_ecus()]

        if v not in ecu_names:
            raise ValueError(f"Not a valid OEM. Use any of {ecu_names}.")

        return v


class UDSScanner(AsyncScript, ABC):
    """UDSScanner is a baseclass, particularly for scanning tasks
    related to the UDS protocol. It has the following properties:

    - It loads transports via TargetURIs; available via `self.transport`.
    - `main()` is the relevant entry_point for the scanner and must be implemented.
    - Controlling PowerSupplies via the opennetzteil API is supported.
    - `setup()` can be overwritten (do not forget to call `super().setup()`)
      for preparation tasks, such as establishing a network connection or
      starting background tasks.
    - `teardown()` can be overwritten (do not forget to call `super().teardown()`)
      for cleanup tasks, such as terminating a network connection or background
      tasks.
    - `self.ecu` contains a OEM specific UDS client object.
    - A background tasks sends TesterPresent regularly to avoid timeouts.
    """

    SUBGROUP: str | None = "uds"
    CAUGHT_EXCEPTIONS: list[type[Exception]] = [ConnectionError, UDSException]

    #: Depending on the Subclass of `UDSScanner` this property can contain results of various types.
    #: By default, it is `None`.
    result: Any = None

    def __init__(self, config: UDSScannerConfig):
        super().__init__(config)
        self.config: UDSScannerConfig = config
        self.power_supply: PowerSupply | None = None
        self._ecu: ECU | None = None
        self._implicit_logging = True

    @property
    def ecu(self) -> ECU:
        assert self._ecu is not None, "ECU accessed before first initialization!"
        return self._ecu

    @ecu.setter
    def ecu(self, ecu: ECU) -> None:
        self._ecu = ecu

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
        if self.config.power_supply is not None:
            self.power_supply = await PowerSupply.connect(self.config.power_supply)
            if self.config.power_cycle is True:
                await self.power_supply.power_cycle(
                    self.config.power_cycle_sleep, lambda: asyncio.sleep(2)
                )

        # Check whether `transport` was provided and use it over `target`
        if self.config.transport is None:
            logger.debug(f"No transport given, loading from target string: '{self.config.target}'")
            transport = load_transport(self.config.target)
        else:
            logger.debug("Transport given, ignoring target string")
            transport = self.config.transport

        # Start dumpcap as the first subprocess; otherwise network traffic might be missing.
        if self.artifacts_dir is not None and self.config.dumpcap is True:
            await transport.dumpcap_start(self.artifacts_dir)

        await transport.connect()

        self.ecu = load_ecu(self.config.oem)(
            transport,
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

        if self.config.tester_present is True:
            await self.ecu.attach_tester_present_sender(
                interval=self.config.tester_present_interval,
                ignore_activity=self.config.tester_present_ignore_activity,
                task_timeout=self.config.tester_present_timeout,
            )

        if self.config.properties is True:
            properties = await self.ecu.properties(True)

            if self.artifacts_dir is not None:
                path = self.artifacts_dir.joinpath(FileNames.PROPERTIES_PRE.value)
                path.write_text(properties.to_json(indent=4) + "\n")

            if self.db_handler is not None:
                self._apply_implicit_logging_setting()

                try:
                    await self.db_handler.insert_scan_run_properties_pre(properties)
                except Exception as e:
                    logger.warning(f"Could not write the properties_pre to the database: {e!r}")

    async def teardown(self) -> None:
        if self.config.properties is True and (not self.ecu.transport.is_closed):
            properties = await self.ecu.properties(True)

            if self.artifacts_dir is not None:
                prop_curr = properties.to_json(indent=4) + "\n"
                path = self.artifacts_dir.joinpath(FileNames.PROPERTIES_POST.value)
                path.write_text(prop_curr)

                path_pre = self.artifacts_dir.joinpath(FileNames.PROPERTIES_PRE.value)
                prop_pre = path_pre.read_text()

                if self.config.compare_properties and prop_curr != prop_pre:
                    logger.warning("ecu properties differ, please investigate!")

            if self.db_handler is not None:
                try:
                    await self.db_handler.complete_scan_run(properties)
                except Exception as e:
                    logger.warning(f"Could not write the scan run to the database: {e!r}")

        if self.ecu.tester_present_task is not None:
            await self.ecu.detach_tester_present_sender()

        logger.debug("Closing transport object of ECU/UDSClient")
        await self.ecu.transport.close()
        await self.ecu.transport.dumpcap_stop()
