import asyncio
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import auto_int, find_sessions


class ReadErrorLog(UDSScanner):
    """read_error_log"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--sessions",
            type=auto_int,
            nargs="*",
            help="set list of sessions to perform test in, or all",
        )
        self.parser.add_argument(
            "--clear-dtc",
            action="store_true",
            help="Clear DTC log",
        )

    async def main(self, args: Namespace) -> None:
        sessions = args.sessions
        if sessions is None or len(sessions) == 0:
            sessions = list(range(1, 0x80))
            sessions = await find_sessions(self.ecu, sessions)
            msg = f'Found {len(sessions)} sessions: {" ".join([hex(i) for i in sessions])}'
            self.logger.log_summary(msg)

        for sess in sessions:
            await self.ecu.set_session(sess)
            resp = await self.ecu.read_dtc()
            if isinstance(resp, NegativeResponse):
                self.logger.log_warning(resp)
            else:
                self.logger.log_summary(resp.dtc_and_status_record)
            await self.ecu.leave_session(sess)

        if args.clear_dtc:
            await self.ecu.clear_dtc()
            await self.ecu.read_dtc()
            self.logger.log_info("Rebooting ECU...")
            await self.ecu.ecu_reset(1)
            await asyncio.sleep(2)
            await self.ecu.read_dtc()
