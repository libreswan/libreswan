#!/bin/sh

# see https://github.com/nmap/nmap/issues/962 for why
# ncat doesn't cut it.

port=7

while test $# -gt 0 ; do
    case "$1" in
	*:* | *.* ) echo addresses are not implemented ; exit 1 ;;
	* )
	    port=$1
	    echo listening on port ${port}
	    ;;
    esac
    shift
done

socat -v tcp-l:${port},fork exec:'/bin/cat' > OUTPUT/echod.log 2>&1 &
