#!/bin/sh

# pluck out leading -4 and -6 when present; needs to appear between IP
# and ROUTE.
ip=
if test $# -gt 0 ; then
    case "$1" in
	-4 ) ip=-4 ; shift ;;
	-6 ) ip=-6 ; shift ;;
    esac
fi

{
    ip --color=never ${ip} route "$@"
} | {
    # some versions embed spaces in the middle and/or end of the
    # output
    sed -e 's/  / /g' -e 's/ $//'
}
