<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Transports

All scanner share the same basic connection args.
Transports are subclasses of {class}`gallia.transports.BaseTransport`.

## URIs

The argument `--target` specifies **all** parameters which are required to establish a connection to the device under test.
The argument to `--target` is specified as a URI.
An URI consists of these components:

``` text
scheme://host:port?param1=foo&param2=bar
        |location |
```

The parameters support: string, int (use 0x prefix for hex values) and bool (true/false) values.
The relevant transport protocol is specified in the scheme.

### isotp

ISO-TP (ISO 15765-2) as provided by the Linux [socket API](https://www.kernel.org/doc/html/latest/networking/can.html).

The can interface is specified as a host, e.g. `can0`.
The following parameters are available (these are ISOTP transport settings):

`src_addr` (required)
: The ISOTP source address as int.

`dst_addr` (required)
: The ISOTP destination address as int.

`is_extended` (optional)
: Use extended CAN identifiers.

`is_fd` (optional)
: Use CAN-FD frames.

`frame_txtime` (optional)
: The time in milliseconds the kernel waits before sending a ISOTP consecutive frame.

`ext_address` (optional)
: The extended ISOTP address as int.

`rx_ext_address` (optional)
: The extended ISOTP rx address.

`tx_padding` (optional)
: Use padding in sent frames.

`rx_padding` (optional)
: Expect padding in received frames.

`tx_dl` (optional)
: CAN-FD max payload size.

Example:

``` text
isotp://can0?src_addr=0x6f4&dst_addr=0x654&rx_ext_address=0xf4&ext_address=0x54&is_fd=false
```

### can-raw

`src_addr` (required)
: The ISOTP source address as int.

`dst_addr` (required)
: The ISOTP destination address as int.

`is_extended` (optional)
: Use extended CAN identifiers.

`is_fd` (optional)
: Use CAN-FD frames.

Example:

``` text
can-raw://can1?is_fd=true
```

### doip

The DoIP gateway address is specified in the location.

`src_addr` (required)
: The source address as int.

`target_addr` (required)
: The target address as int.

Example:

``` text
doip://169.254.100.100:13400?src_addr=0x0e00&target_addr=0x1d
```

### hsfz

The gateway address is specified in the location.

* `src_addr` (required): The source address as int.
* `dst_addr` (required): The destination address as int.
* `ack_timeout`: Specify the HSFZ acknowledge timeout in ms.
* `nocheck_src_addr`: Do not check the source address in received HSFZ frames.
* `nocheck_dst_addr`: Do not check the destination address in received HSFZ frames.

Example:

``` text
hsfz://169.254.100.100:6801?src_addr=0xf4&dst_addr=0x1d
```

### tcp-lines

A simple tcp based transport.
UDS messages are sent linebased in ascii hex encoding.
Mainly useful for testing.

Example:

``` text
tcp-lines://127.0.0.1:1234
```


## API

Transports can also be used in own standalone scripts; transports are created with the `.connect()` method which takes a URI.

``` python
import asyncio

from gallia.log import setup_logging
from gallia.transports import DOiPTransport


async def main():
    transport = await DOiPTransport.connect("doip://192.0.2.5:13400?src_addr=0xf4&dst_addr=0x1d")
    await transport.write(bytes([0x10, 0x01]))


setup_logging()
asyncio.run(main())
```
