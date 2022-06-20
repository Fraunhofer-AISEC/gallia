# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# stolen from sudo.fish

function __fish_penrun_no_subcommand
    if test -n "$argv"
        and not string match -qr '^-' $argv[1]
        return 1
    else
        return 0
    end
end

complete -c penrun -n __fish_penrun_no_subcommand -s C -r -d "Compression command for OUTPUT"
complete -c penrun -n __fish_penrun_no_subcommand -s S -r -d "Sleep this time beetween jobs"
complete -c penrun -n __fish_penrun_no_subcommand -s T -r -d "A command template for batch processing"
complete -c penrun -n __fish_penrun_no_subcommand -s c -r -d "Use this config file exclusively"
complete -c penrun -n __fish_penrun_no_subcommand -s d -r -d "Use artifactsdir DIR"
complete -c penrun -n __fish_penrun_no_subcommand -s e -r -d "File extension for OUTPUT"
complete -c penrun -n __fish_penrun_no_subcommand -s j -r -d "In batch mode process these number of jobs at a time"
complete -c penrun -n __fish_penrun_no_subcommand -s n -d "Do not use DEFAULT_ARGS from config"
complete -c penrun -n __fish_penrun_no_subcommand -s p -r -d "Pipe output through CMD"

complete -c penrun -n __fish_penrun_no_subcommand -s s -d "Skip hooks"
complete -c penrun -n __fish_penrun_no_subcommand -s t -r -d "Add a tag to this run"
complete -c penrun -n __fish_penrun_no_subcommand -s u -d "Run until the first error occurs and exit"
complete -c penrun -n __fish_penrun_no_subcommand -s h -d "Show this page and exit"

# Complete the command we are executed under penrun
complete -c penrun -x -n 'not __fish_seen_argument -s e' -a "(__fish_complete_subcommand)"
