# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

common_setup() {
	# https://bats-core.readthedocs.io/en/stable/tutorial.html#let-s-do-some-setup
	DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")" >/dev/null 2>&1 && pwd)"
	PATH="$DIR/..:$PATH"

	cd "$BATS_TEST_TMPDIR" || exit 1
}

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

check_artifactsdir() {
	# There is only one (tm) artifactsdir per run.
	local artifactsdir
	artifactsdir="$1"

	if [[ ! -r "$artifactsdir/log.json.zst" ]]; then
		return 1
	fi

	if [[ ! -r "$artifactsdir/META.json" ]]; then
		return 1
	fi

	if [[ ! -r "$artifactsdir/ENV" ]]; then
		return 1
	fi
}
