import asyncio
import sys

assert sys.platform == "win32"

from gallia.transports import RawFlexrayTransport, TargetURI


async def main() -> None:
    url = TargetURI("flexray-raw://?slot_id=59")
    tp = await RawFlexrayTransport.connect(url, None)

    await tp.write(bytes.fromhex("30 7c 61 00 02 3e 00 00").ljust(37, b"\0"))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
