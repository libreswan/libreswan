#!/bin/sh

timeout=30
match=false

if test $# -eq 0; then
    cat <<EOF 1>&2

Usage:

    $0 [ --timeout <seconds> | --no-match <regex> | --match <regex> ] -- <command>...

Repeatedly grep the output from <command>... until <regex> either
matches (--match) or does not match (--no-match); Pause for one second
between grep attempts.

Options:

   --timeout <seconds>

         Set the timeout (nr attempts * 1 second); defaut is
         ${timeout} attempts which is roughly ${timeout} seconds.

   --match <regex>

         Keep trying until the <regex> matches the output from <command>...

   --no-match <regex>

         Keep trying until the <regex> does not match the output from
         <command>...

For instance, to wait for the connection east-west appears:

    $0 --match east-west -- ipsec whack --trafficstatus

and to then wait for it to disappear:

    $0 --no-match east-west -- ipsec whack --trafficstatus

EOF
    exit 1
fi

# parse options

regex=
match=
while test "$#" -gt 1; do
    case "$1" in
	--timeout ) shift ; timeout=$1 ; shift ;;
	--match ) match=true ; shift ; regex=$1 ; shift ;;
	--no-match ) match=false ; shift ; regex=$1 ; shift ;;
	-- ) shift; break ;;
	--* ) echo "unknown option: $1" 1>&2 ; exit 1 ;;
	* ) break ;;
    esac
done
if test "${regex}" = ""; then
    echo "missing --match <regex> or --no-match <regex>" 1>&2
    exit 1
fi

# parse <command>...

if test "$#" -eq 0; then
    echo "missing command" 1>&2
    exit 1
fi

# "$@" is left containing grep expression

count=0
while true ; do
    if output=$("$@" | grep "${regex}"); then
	if ${match} ; then
	    echo "$output"
	    exit 0
	fi
    elif ! ${match} ; then
	exit 0
    fi
    count=$(expr ${count} + 1)
    if test ${count} -ge ${timeout} ; then
	echo timeout waiting ${timeout} seconds for "$@" to $(${match} && echo match || echo mismatch) "${regex}" 1>&2
	exit 1
    fi
    sleep 1
done
