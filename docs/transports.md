<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Transports

All scanner share the same basic connection args.
The argument `--target` specifies **all** parameters which are required to establish a connection to the device under test.
The argument to `--target` is specified as a URI.
An URI consists of these components:

``` text
scheme://host:port?param1=foo&param2=bar
        |location |
```

The parameters support: string, int (use 0x prefix for hex values) and bool (true/false) values.
The relevant transport protocol is specified in the scheme.

## isotp

The can interface is specified as a host, e.g. `can0`.
The following parameters are available (these are ISOTP transport settings):

* `src_addr` (required): The ISOTP source address as int.
* `dst_addr` (required): The ISOTP destination address as int.
* `is_extended` (optional): Use extended CAN identifiers.
* `is_fd` (optional): Use CAN-FD frames.
* `frame_txtime` (optional): The time in milliseconds the kernel waits before sending a ISOTP consecutive frame.
* `ext_address` (optional): The extended ISOTP address as int.
* `rx_ext_address` (optional): The extended ISOTP rx address.
* `tx_padding` (optional): Use padding in sent frames.
* `rx_padding` (optional): Expect padding in received frames.
* `tx_dl` (optional): CAN-FD max payload size.

Example:

``` text
isotp://can0?src_addr=0x6f4&dst_addr=0x654&rx_ext_address=0xf4&ext_address=0x54&is_fd=false
```

## can-raw

* `is_fd` (optional): Use CAN-FD frames.

Example:

``` text
can-raw://can1?is_fd=true
```

## doip

The DoIP gateway address is specified in the location.

* `src_addr` (required): The source address as int.
* `dst_addr` (required): The destination address as int.

Example:

``` text
doip://169.254.100.100:6801?src_addr=0xf4&dst_addr=0x1d
```

## tcp-lines

A simple tcp based transport.
UDS messages are sent linebased in ascii hex encoding.
Mainly useful for testing.

Example:

``` text
tcp-lines://127.0.0.1:6801
```

