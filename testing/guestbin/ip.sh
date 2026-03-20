#!/bin/bash

set -o pipefail

{
    ip --color=never "$@"
} | {
    # some versions embed spaces in the middle and/or end of the
    # output (but not the beginning).
    case " $* " in
	*" link "* ) cat ;; # don't edit
	*" rule "* ) cat ;; # don't edit
	*" route "* ) echo Use ip-route.sh 1>&2 ; exit 1 ;;
	*) sed -e 's/\([^ ]\)  /\1 /g' -e 's/ $//' ;;
    esac
} | {
    sed -e '/^[[:space:]]*altname /d'
}
