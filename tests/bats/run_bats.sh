#!/usr/bin/env bash

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

set -eu

gallia script vecu --no-volatile-info "unix-lines:///tmp/vecu.sock" rng \
	--seed 3 \
	--mandatory_sessions "[1, 2, 3]" \
	--mandatory_services "[DiagnosticSessionControl, EcuReset, ReadDataByIdentifier, WriteDataByIdentifier, RoutineControl, SecurityAccess, ReadMemoryByAddress, WriteMemoryByAddress, RequestDownload, RequestUpload, TesterPresent, ReadDTCInformation, ClearDiagnosticInformation, InputOutputControlByIdentifier]" 2>vecu.log &

# https://superuser.com/a/553236
trap 'kill "$(jobs -p)"' SIGINT SIGTERM EXIT

if ! bats -r "$(dirname "$BASH_ARGV0")"; then
	cat vecu.log
	exit 1
fi
