#!/bin/sh

# see https://github.com/nmap/nmap/issues/962 for why
# ncat doesn't cut it.

port=7
ipv=4

while test $# -gt 0 ; do
    case "$1" in
	*:* | *.* ) echo addresses are not implemented ; exit 1 ;;
	-[46] ) ipv=$(expr "$1" : '-\(.\)') ;;
	* ) port=$1 ;;
    esac
    shift
done

echo listening on IPv${ipv} port ${port} 1>&2
socat -v -${ipv} \
      TCP-LISTEN:${port},fork \
      EXEC:'/bin/cat' \
      > OUTPUT/$(hostname).echo.${ipv}.${port}.log 2>&1 &
