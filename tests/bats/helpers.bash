# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

setup_gallia_toml() {
	{
		echo "[gallia]"
		echo "no-volatile-info = true"
		echo "verbosity = 1"

		echo "[gallia.scanner]"
		echo 'target = "unix-lines:///tmp/vecu.sock"'
		echo 'dumpcap = false'

		echo "[gallia.protocols.uds]"
		echo 'ecu_reset = 0x01'
	} >"$BATS_FILE_TMPDIR/gallia.toml"

	export GALLIA_CONFIG="$BATS_FILE_TMPDIR/gallia.toml"
}

rm_gallia_toml() {
	if [[ -r "$GALLIA_CONFIG" ]]; then
		rm -f "$GALLIA_CONFIG"
	fi
}
