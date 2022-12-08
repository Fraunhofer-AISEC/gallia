<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Environment Variables

For some cases `gallia` can be configured with environment variables.
`gallia`-specific variables begin with `GALLIA_`.

GALLIA_CONFIG
: The path to the config file usually called `gallia.toml`.
  Disables autodiscovery of the config.

GALLIA_LOGLEVEL
: When {meth}`gallia.log.setup_logging()` is called without an argument this environment variable is read to set the loglevel.
  Supported value are: `trace`, `debug`, `info`, `notice`, `warning`, `error`, `critical`.
  As an alternative, the int values from 0 to 7 can be used.
  Mostly useful in own scripts or tests.
  This variable is not read when using the gallia cli.

NO_COLOR
: If this variable is set, `gallia` by default does not use color codes, see: https://no-color.org/
