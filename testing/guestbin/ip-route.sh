#!/bin/bash

set -o pipefail
set -e

v=
n=
while test $# -gt 0 ; do
    case $1 in
	-[46] ) v=$1 ; shift ;;
	-n ) n="-n $2" ; shift ; shift ;;
	* ) break ;;
    esac
done

{
    ip --color=never ${v} ${n} route "$@"
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
