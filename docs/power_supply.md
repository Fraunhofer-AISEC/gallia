# Power Supply

Gallia supports the [opennetzteil API](https://codeberg.org/rumpelsepp/opennetzteil) via a builtin client.
The location to the opennetzteil server is specified via `--power-supply`.
The argument is a URI of the following form:

``` text
(http|https)://example.org:1234?id=1&channel=1
```

The `id` paramater specifies the device id within the opennetzteil server; `channel` specifies the channel of the power supply.
Channel can be specified multiple times; channel 0 stands for the master channel.

