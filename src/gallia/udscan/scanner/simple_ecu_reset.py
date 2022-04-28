import asyncio
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import auto_int


class EcuReset(UDSScanner):
    """ECU_Reset"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session", type=auto_int, default=0x01, help="set session perform test in"
        )
        self.parser.add_argument(
            "-f", "--subfunc", type=auto_int, default=0x01, help="subfunc"
        )

    async def main(self, args: Namespace) -> None:
        resp: UDSResponse = await self.ecu.set_session(args.session)
        if isinstance(resp, NegativeResponse):
            self.logger.log_error(f"could not change to session: 0x{args.session:02x}")
            return

        try:
            self.logger.log_info(f"try sub-func: 0x{args.subfunc:02x}")
            resp = await self.ecu.ecu_reset(args.subfunc)
            if isinstance(resp, NegativeResponse):
                msg = f"ECU Reset 0x{args.subfunc:02x} failed in session: 0x{args.session:02x}: {resp}"
                self.logger.log_error(msg)
            else:
                self.logger.log_summary(f"ECU Reset 0x{args.subfunc:02x} succeeded")
        except asyncio.TimeoutError:
            self.logger.log_error("Timeout")
            await asyncio.sleep(10)
        except ConnectionError:
            msg = f"Lost connection to ECU, session: 0x{args.session:02x} subFunc: 0x{args.subfunc:02x}"
            self.logger.log_error(msg)
            return
