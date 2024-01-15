#!/usr/bin/env bats

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

load helpers.sh

run_vecu() {
	close_non_std_fds
    gallia script vecu "unix-lines:///tmp/vecu.sock" rng --seed 3 --mandatory_sessions "[1, 2, 3]" --mandatory_services "[DiagnosticSessionControl, EcuReset, ReadDataByIdentifier, WriteDataByIdentifier, RoutineControl, SecurityAccess, ReadMemoryByAddress, WriteMemoryByAddress, RequestDownload, RequestUpload, TesterPresent, ReadDTCInformation, ClearDiagnosticInformation, InputOutputControlByIdentifier]"
}

setup_file() {
	{
	    echo "[gallia]"
	    echo "[gallia.scanner]"
	    echo 'target = "unix-lines:///tmp/vecu.sock"'
	    echo 'dumpcap = false'

	    echo "[gallia.protocols.uds]"
	    echo 'ecu_reset = 0x01'
	} > "$BATS_FILE_TMPDIR/gallia.toml"

	export GALLIA_CONFIG="$BATS_FILE_TMPDIR/gallia.toml"

	run_vecu &
}

teardown_file() {
	kill -9 "$(pgrep gallia)"
	rm -f /tmp/vecu.sock
}

@test "scan services" {
	gallia scan uds services --sessions 1 2 --check-session
}
