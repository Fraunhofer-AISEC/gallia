<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Automation
## Power Supply

`gallia` has support for controlling power supplies either directly via builtin drivers.
Power supplies are mostly used for power cycling the current device under test.
There is no limit in accessing power supplies, e.g. voltage or current settings can be controlled as well.

Own drivers can be included by implementing the {class}`gallia.power_supply.BasePowerSupply` interface.
On the commandline there is the `--power-supply` argument to specify a relevant power supply.
Further, there is `--power-cycle` to automatically power-cycle the device under test.
There is an experimental cli tool `netzteil` included in `gallia`.
This cli tool can be used to control all supported power supplies via the cli.

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

