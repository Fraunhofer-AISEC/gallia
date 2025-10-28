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

NO_COLOR
: If this variable is set, `gallia` by default does not use color codes, see: https://no-color.org/
