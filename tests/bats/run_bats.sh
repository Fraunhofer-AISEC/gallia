#!/usr/bin/env bash

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

set -eu

gallia script vecu rng "unix-lines:///tmp/vecu.sock" \
	--no-volatile-info \
	--seed 3 \
	--mandatory-sessions 1 2 3 \
	--mandatory-services DiagnosticSessionControl EcuReset ReadDataByIdentifier WriteDataByIdentifier RoutineControl SecurityAccess ReadMemoryByAddress WriteMemoryByAddress RequestDownload RequestUpload TesterPresent ReadDTCInformation ClearDiagnosticInformation InputOutputControlByIdentifier 2>vecu.log &

# https://superuser.com/a/553236
trap 'kill "$(jobs -p)"' SIGINT SIGTERM EXIT

if ! bats -r "$(dirname "$BASH_ARGV0")"; then
	echo "vecu log:"
	cat vecu.log
	exit 1
fi
