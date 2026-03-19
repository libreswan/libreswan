#!/bin/bash

set -o pipefail
set -e

n=
if test $# -gt 0 ; then
    case $1 in
	-[46] ) n=$1 ; shift ;;
    esac
fi

{
    ip --color=never $n route "$@"
} | {
    # some versions embed spaces in the middle and/or end of the
    # output (but not the beginning).
    sed \
	-e 's/\([^ ]\)  /\1 /g' \
	-e 's/ $//'
} | {
    # namespaces don't have trailing proto stack
    sed -e 's/ proto static onlink$//' \
	-e 's/ proto static$//' \
	-e 's/ proto static onlink / /' \
	-e 's/ proto static / /'
}
