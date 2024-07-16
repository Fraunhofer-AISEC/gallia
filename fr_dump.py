import asyncio
import sys

assert sys.platform == "win32"

from gallia.transports import RawFlexrayTransport, TargetURI


async def main() -> None:
    url = TargetURI("flexray-raw:")
    tp = await RawFlexrayTransport.connect(url, None)
    tp.add_block_all_filter()
    tp.set_acceptance_filter(33, 33)
    tp.set_acceptance_filter(59, 59)
    tp.activate_channel()

    while True:
        frame = await tp.read_frame()

        print(f"raw event: {frame.raw}")
        print(f"   -> slot_id: {frame.slot_id}; data: {frame.data.hex()}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except TimeoutError:
        pass
    except KeyboardInterrupt:
        pass

