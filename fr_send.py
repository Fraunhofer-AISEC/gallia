import asyncio
import sys

assert sys.platform == "win32"

from gallia.log import Loglevel, setup_logging
from gallia.transports import FlexRayTPLegacyTransport, TargetURI


async def main() -> None:
    setup_logging(level=Loglevel.TRACE, no_volatile_info=True)

    # TODO: rename dst->target
    url = TargetURI(
        "flexray-tp-legacy://?dst_slot_id=59&src_slot_id=33&dst_address=0x307c&src_address=0x6100&payload_rx_start_index=0&payload_rx_end_index=12"
    )
    tp = await FlexRayTPLegacyTransport.connect(url, None)

    await tp.write(bytes.fromhex("3e 00"))

    data = await tp.read()
    print(data.hex())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
