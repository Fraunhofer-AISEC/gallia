import asyncio
import sys

assert sys.platform == "win32"

from gallia.transports import RawFlexrayTransport, TargetURI


async def main() -> None:
    url = TargetURI("flexray://?slot_id=0x42")
    tp = await RawFlexrayTransport.connect(url, None)
    await tp.write(b"affe")


if __name__ == "__main__":
    asyncio.run(main())
