# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0
#
# Preferred system exit codes as defined by sysexits.h
#
# Exit code constants intended to be passed to `sys.exit()`;
# inspired by https://docs.rs/exitcode.

# Copy and pasted from: https://github.com/rumpelsepp/exitcode/blob/176eaaf8b70905fe18a904670b481f7a00edfc68/exitcode/__init__.py

# Successful exit
OK = 0

# The command was used incorrectly, e.g., with the
# wrong number of arguments, a bad flag, a bad syntax
# in a parameter, etc.
USAGE = 64

# The input data was incorrect in some way.  This
# should only be used for user's data and not system
# files.
DATAERR = 65

# An input file (not a system file) did not exist or
# was not readable.  This could also include errors
# like "No message" to a mailer (if it cared to
# catch it).
NOINPUT = 66

# The user specified did not exist.  This might be
# used for mail addresses or remote logins.
NOUSER = 67

# The host specified did not exist.  This is used in
# mail addresses or network requests.
NOHOST = 68

# A service is unavailable.  This can occur if a
# support program or file does not exist. This can also
# be used as a catchall message when something you
# wanted to do doesn't work, but you don't know why.
UNAVAILABLE = 69

# An internal software error has been detected.  This
# should be limited to non-operating system related
# errors as possible.
SOFTWARE = 70

# An operating system error has been detected.  This
# is intended to be used for such things as "cannot
# fork", "cannot create pipe", or the like.  It
# includes things like getuid returning a user that
# does not exist in the passwd file.
OSERR = 71

# Some system file (e.g., /etc/passwd, /var/run/utmp,
# etc.) does not exist, cannot be opened, or has some
# sort of error (e.g., syntax error).
OSFILE = 72

# A (user specified) output file cannot be created.
CANTCREAT = 73

# An error occurred while doing I/O on some file.
IOERR = 74

# Temporary failure, indicating something that is not
# really an error.  In sendmail, this means that a
# mailer (e.g.) could not create a connection, and
# the request should be reattempted later.
TEMPFAIL = 75

# The remote system returned something that was
# "not possible" during a protocol exchange.
PROTOCOL = 76

# You did not have sufficient permission to perform
# the operation.  This is not intended for file system
# problems, which should use `NOINPUT` or `CANTCREAT`,
# but rather for higher level permissions.
NOPERM = 77

# Something was found in an unconfigured or misconfigured state.
CONFIG = 78
