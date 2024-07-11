import asyncio
import sys

assert sys.platform == "win32"

from gallia.transports import RawFlexrayTransport, TargetURI


async def main() -> None:
    url = TargetURI("flexray-raw://?slot_id=59")
    tp = await RawFlexrayTransport.connect(url, None)

    # await tp.write(bytes.fromhex("1C307C6100023E00"))

    while True:
        frame = await tp.read_frame()
        fr_rx_frame = frame.tagData.frRxFrame
        data_raw = bytes(fr_rx_frame.data[:fr_rx_frame.payloadLength])
        data = data_raw[4:12]

        print(f"raw event: {frame}")
        print(f"   -> slot_id: {frame.slotID}; data: {data_raw.hex()}")
        print(f"       -> {data.hex()}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except TimeoutError:
        pass
    except KeyboardInterrupt:
        pass

