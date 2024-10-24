#!/usr/bin/env bats

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

load "helpers"

@test "invoke gallia without parameters" {
	# Should fail and print help page.
	run -64 gallia
}

@test "invoke gallia without config" {
	run -78 gallia --show-config
}

@test "invoke gallia with config" {
	setup_gallia_toml
	gallia --show-config
	rm_gallia_toml
}

@test "invoke gallia -h" {
	gallia -h
}

@test "invoke hr -h" {
	hr -h
}

@test "invoke netzteil -h" {
	netzteil -h
}

@test "invoke cursed-hr -h" {
	cursed-hr -h
}
