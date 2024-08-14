#!/usr/bin/env bats

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

load "helpers"

setup_file() {
	setup_gallia_toml
}

setup() {
	common_setup
}

teardown() {
	check_artifactsdir "$BATS_TMPDIR"/gallia/*/run-*
}

@test "primitive ecu-reset" {
	gallia primitive uds ecu-reset
}

@test "primitive vin" {
	gallia primitive uds vin
}

@test "primitive ping" {
	gallia primitive uds ping --count 2
}

@test "primitive rdbi" {
	gallia primitive uds rdbi 0x108d
}

@test "primitive pdu" {
	gallia primitive uds pdu 1001
}

@test "primitive wdbi" {
	gallia primitive uds wdbi 0x2266 --data 00
}

@test "primitive dtc read" {
	gallia primitive uds dtc read
}

@test "primitive dtc clear" {
	gallia primitive uds dtc clear
}

@test "primitive dtc control stop" {
	gallia primitive uds dtc control --stop
}

@test "primitive dtc control resume" {
	gallia primitive uds dtc control --resume
}

@test "primitive iocbi reset-to-default" {
	gallia primitive uds iocbi 0x1000 reset-to-default
}
