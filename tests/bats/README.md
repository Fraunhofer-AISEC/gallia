<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Bats Testsuite

This directory contains code which is part of the `gallia` testsuite using [`bats`](https://bats-core.readthedocs.io).

* 0XX: Tests for the tool `gallia`
* 1XX: Tests for the tool `hr`

## Run the Bats Testsuite

A virtual ECU must be online and listening on the unix socket `/tmp/vecu.sock`.
`run_bats.sh` takes care of starting the virtual ECU.
If the testsuite is started plain, then the virtual ECU needs to be started separately.
