# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

setup_suite() {
	bats_require_minimum_version 1.5.0

	# https://bats-core.readthedocs.io/en/stable/tutorial.html#let-s-do-some-setup
	DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")" >/dev/null 2>&1 && pwd)"
	PATH="$DIR/..:$PATH"

	cd "$BATS_TEST_TMPDIR" || exit 1
}
