#!/usr/bin/env bats

# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

@test "invoke gallia without parameters" {
	# Should fail and print help page.
	run -64 gallia
}
