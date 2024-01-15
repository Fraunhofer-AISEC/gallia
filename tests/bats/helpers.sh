# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

close_non_std_fds() {
    for fd in $(ls /proc/$BASHPID/fd); do
        if [[ $fd -gt 2 ]]; then
            eval "exec $fd>&-" || true
        fi
    done
}
