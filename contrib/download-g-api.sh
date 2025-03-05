#!/usr/bin/env bash

set -eu

# There is no API. If the download does not work any more (or if there are updates)
# please check this page: 
#
#   https://www.goepel.com/automotive-test-solutions/support/software/g-api-software
#
ARCHIVE_NAME="g-api-Setup-2.2.10974_Release_Linux.run.zip"
RUN_SCRIPT_NAME="${ARCHIVE_NAME%.*}"
DOWNLOAD_URL="https://www.goepel.com/fileadmin/files/ats/software/g-api/$ARCHIVE_NAME"

is_running_under_podman() {
    if [[ -n "${container:-}" && "$container" == "podman" ]]; then
        return 0
    fi
    return 1
}

main() {
    # If this script is not running under podman, then spawn podman and run
    # itself within the container.

    # Outside the container.
    local extractdir
    extractdir="/mnt$PWD/out"
    if ! is_running_under_podman; then
        podman run -it -v "$PWD:/mnt/$PWD" -w "/mnt/$PWD" --rm debian:trixie "$BASH_ARGV0" "$extractdir"

        # Exit the parent script outside the container.
        exit
    fi

    # Inside the container.
    # Catch the directory from the commandline; supplied outside the container.
    extractdir="$1"

    apt-get install -U -y curl unzip make pciutils xdg-user-dirs

    local tmpdir
    tmpdir="$(mktemp -d)"

    cd "$tmpdir"
    curl -L -o "$ARCHIVE_NAME" "$DOWNLOAD_URL"

    unzip "$ARCHIVE_NAME"

    if [[ ! -r "$RUN_SCRIPT_NAME" ]]; then
        echo "error: $ARCHIVE_NAME is not there!"
        exit 1
    fi

    chmod +x "$RUN_SCRIPT_NAME"
    mkdir -p "$extractdir"

    echo "The goepel installer script is going to be executed now."
    echo "This scipt will break your system and we do not recommend this to be run on a production system."
    echo "For reference (especially point 1.4 and 1.5):"
    echo ""
    echo "  https://wiki.debian.org/DontBreakDebian"
    echo ""
    echo "For this reason, the install script is run in a podman container."
    echo "The installer will fail but it extracts the library and .so files."

    "./$RUN_SCRIPT_NAME" --target "$extractdir" > "$extractdir/installer.log" 2>&1 || true

    mkdir -p "$extractdir/lib"
    cd "$extractdir/lib"
    tar -xvf "../bin/g_api_lib.tar.gz"

    echo "The extracted library will be available in: $extractdir"
    echo "Headers are in: $extractdir/bin"
    echo "Shared objects are in: $extractdir/lib"
}

main "$@"
