#!/bin/sh

set -o pipefail

{
    ip --color=never "$@"
} | {
    # some versions embed spaces in the middle and/or end of the
    # output (but not the beginning).
    sed -e 's/\([^ ]\)  /\1 /g' -e 's/ $//'
}
