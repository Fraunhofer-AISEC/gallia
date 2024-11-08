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

GALLIA_LOGGING_SYSTEMD
: Tells gallia to omit colors and status bars in logging output.
  Additionally, the priority information gets added such that the journal can add it.

NO_COLOR
: If this variable is set, `gallia` by default does not use color codes, see: https://no-color.org/
