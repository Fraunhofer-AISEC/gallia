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

@test "scan services" {
	gallia scan uds services --sessions 1 2 --check-session
}

@test "scan services with database" {
    local db_file="${BATS_TEST_NAME}.sqlite"

	gallia scan uds services --db "$db_file" --sessions 1 2 --check-session


    # TODO: This is not finished; check here that the database contains expected fields
    sqlite3 "$db_file" "SELECT * FROM run_meta;" >&3
}

@test "scan sessions" {
	gallia scan uds sessions
}

@test "scan sessions thorough" {
	gallia scan uds sessions --thorough
}

@test "scan identifiers sid 0x22" {
	gallia scan uds identifiers --start 0 --end 100 --service 0x22
}

@test "scan identifiers sid 0x2e" {
	gallia scan uds identifiers --start 0 --end 100 --service 0x2e
}

@test "scan identifiers sid 0x31" {
	gallia scan uds identifiers --start 0 --end 100 --service 0x31
}

@test "scan reset" {
	gallia scan uds reset
}

@test "scan dump-seeds" {
	gallia scan uds dump-seeds --duration 0.01 --level 0x2f
}

@test "scan memory" {
	for sid in 0x23 0x34 0x35 0x3d; do
		gallia scan uds memory --service "$sid"
	done
}
