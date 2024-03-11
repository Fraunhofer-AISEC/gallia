<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Automation
## Power Supply

`gallia` has support for controlling power supplies either directly via builtin drivers.
Power supplies are mostly used for power cycling the current device under test.
There is no limit in accessing power supplies, e.g. voltage or current settings can be controlled as well.

Own drivers can be included by implementing the {class}`opennetzteil.netzteil.BaseNetzteil` interface[^1].
On the commandline there is the `--power-supply` argument to specify a relevant power supply.
Further, there is `--power-cycle` to automatically power-cycle the device under test.
There is an experimental cli tool `opennetzteil` included in `gallia`.
This cli tool can be used to control all supported power supplies via the cli.

[^1]: `opennetzteil` is included and shipped with `gallia`.

The argument for `--power-supply` is a URI of the following form:

``` text
SCHEME://HOST:PORT/PATH?channel=CHANNEL?product_id=PRODUCT_ID
```

Some schemes might take additional arguments in the query string.

SCHEME
: The used protocol scheme; could be `tcp`, `http`, …

HOST:PORT
: For e.g. `tcp` or `https` this is the relevant host and port.

PATH
: If the power supply is exposed as a local file, this might be the path.

channel
: The relevant channel where the device is connected; the master channel is `0`.

product_id
: The product_id of the used power supply.

## Supported Power Supplies

Power supplies are chosen depending on the `product_id` setting in the URI.
The following power supplies are supported.

### [R&S®HMC804x](https://www.rohde-schwarz.com/de/produkt/hmc804x-produkt-startseite_63493-61542.html)

product_id 
: `hmc804`

scheme
: `tcp`

HOST
: IP address

PORT
: TCP port, the device most likely uses `5025`

Example:

```
tcp://192.0.2.5:5025?product_id=hmc804
```

### HTTP

This is a client to the [opennetzteil API](https://github.com/rumpelsepp/opennetzteil/blob/master/man/netzteil-http.7.adoc) which can expose power supplies over HTTP.

product_id
: `http`

scheme
: `http` or `https`

HOST
: IP address

PORT
: TCP port, most likely `8000` or the http defaults `80`, or `443`
