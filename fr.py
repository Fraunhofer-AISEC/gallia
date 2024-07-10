import asyncio
import sys

assert sys.platform == "win32"

from gallia.transports import RawFlexrayTransport, TargetURI


async def main() -> None:
    url = TargetURI("flexray://?slot_id=59")
    tp = await RawFlexrayTransport.connect(url, None)

    # await tp.write(bytes.fromhex("1C307C6100023E00"))

    while True:
        data = await tp.read(timeout=20)
        print(data)


if __name__ == "__main__":
    asyncio.run(main())
