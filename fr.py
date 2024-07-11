import asyncio
import sys

assert sys.platform == "win32"

from gallia.transports import RawFlexrayTransport, TargetURI


async def main() -> None:
    url = TargetURI("flexray-raw://?slot_id=59")
    tp = await RawFlexrayTransport.connect(url, None)

    # await tp.write(bytes.fromhex("1C307C6100023E00"))

    timeout = int(sys.argv[1]) if len(sys.argv) == 2 else None
    while True:
        frame = await tp.read_frame(timeout=timeout)
        print(f"slot_id: {frame.slotID}; data: {frame.data}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except TimeoutError:
        pass

