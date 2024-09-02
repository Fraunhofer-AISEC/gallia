#!/usr/bin/env bats

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

@test "read logs from .zst file" {
	hr "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst"
}

@test "read logs from .gz file" {
	zstdcat "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst" | gzip - >"$BATS_TMPDIR/log-01.json.gz"
	hr "$BATS_TMPDIR/log-01.json.gz"
}

@test "read logs from stdin" {
	zstdcat "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst" | hr -
}

@test "read multiple .zst files" {
	hr "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst" "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst"
}

@test "read file with priority prefix" {
	zstdcat "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst" | awk '{print "<6>" $0}' | hr -
}

@test "pipe invalid data" {
	run -65 bash -c "echo 'invalid json' | hr -"
}

@test "pipe to head and handle SIGPIPE" {
	hr "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst" | head
}

@test "filter priority" {
	local additional_line
	additional_line='{"module": "foo", "data": "I am the line!", "host": "kronos", "datetime":"2020-04-23T15:21:50.620310", "priority": 5, "version": 2}'
	cat <(zstdcat "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst") <(echo "$additional_line") | gzip - >"$BATS_TMPDIR/log.json.gz"

	run -0 hr -p notice "$BATS_TMPDIR/log.json.gz"

	[[ "$output" =~ "I am the line!" ]]
}

@test "filter priority with priority prefix" {
	local additional_line
	additional_line='<5>{"module": "foo", "data": "I am the line!", "host": "kronos", "datetime":"2020-04-23T15:21:50.620310", "priority": 5, "version": 2}'
	cat <(zstdcat "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst") <(echo "$additional_line") | gzip - >"$BATS_TMPDIR/log.json.gz"

	run -0 hr -p notice "$BATS_TMPDIR/log.json.gz"

	[[ "$output" =~ "I am the line!" ]]
}
