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

@test "filter expression" {
	run -0 hr -p trace -f 'tag=preamble' "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst"

	[[ "$output" =~ "2iE42E?GBxV}qqtwOyzJvj:QN" ]]
	[[ ! "$output" =~ "Ffz" ]]
}

@test "invalid filter expression" {
	run -2 hr -f 'foo=bar' "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst"
	run -2 hr -f 'data~(' "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst"
}

@test "tail and reverse" {
	local tail
	local reverse
	tail="$(hr -p trace --tail -n 3 "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst")"
	reverse="$(hr -p trace --reverse "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst" | head -n 3 | tac)"

	[[ "$tail" == "$reverse" ]]
}

@test "cursed supports a single file only" {
	run -2 hr --cursed "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst" "$BATS_TEST_DIRNAME/testfiles/log-01.json.zst"
}

@test "output options" {
	local line
	line='{"module": "uds", "data": "22f190", "host": "kronos", "datetime":"2020-04-23T15:21:50.620310", "priority": 6, "version": 2}'

	run -0 hr --no-prefix --dissect - <<<"$line"
	[[ "$output" == "22f190  # ReadDataByIdentifierRequest"* ]]

	run -0 hr --relative-timings - <<<"$line"
	[[ "$output" == *"+0d 00:00:00.000 uds: 22f190"* ]]
}
