import asyncio
import sys

assert sys.platform == "win32"

from gallia.transports import RawFlexrayTransport, TargetURI


async def main() -> None:
    url = TargetURI("flexray-raw:")
    tp = await RawFlexrayTransport.connect(url, None)
    tp.add_block_all_filter()
    tp.set_acceptance_filter(0x33, 0x33)
    tp.activate_channel()

    while True:
        frame = await tp.read_frame()
        fr_rx_frame = frame.tagData.frRxFrame
        data_raw = bytes(fr_rx_frame.data[:fr_rx_frame.payloadLength])

        print(f"raw event: {frame}")
        print(f"   -> slot_id: {fr_rx_frame.slotID}; data: {data_raw.hex()}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except TimeoutError:
        pass
    except KeyboardInterrupt:
        pass

