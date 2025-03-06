#!/usr/bin/env bash

set -eu

if [[ "$#" != 1 ]]; then
    echo "usage: $BASH_ARGV0 GAPID_PATH"
    exit 1
fi

GAPID_PATH="$(realpath "$1")"

systemd-run \
    --service-type=forking \
    -p "PrivateTmp=true" \
    -p "ProtectSystem=strict" \
    -p "PrivateUsers=true" \
    --unit "gapid.service" \
    --user \
    --collect \
    unshare --map-root-user -- "$GAPID_PATH" -s 7

echo 'goepel gapid is running. Stop with "systemctl --user stop gapid.service"'.
