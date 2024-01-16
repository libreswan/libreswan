#!/bin/sh

# see https://github.com/nmap/nmap/issues/962 for why
# ncat doesn't cut it.

if test $# -eq 0 ; then
    cat <<EOF 1>&2
Usage:
  $0 -{4,6} -{udp,tcp} [-daemon] <port>
connect using TCP and EPHEM source port:
  socat - TCP:192.1.2.23:7
connect using UDP and EPHEM source port:
  socat - UDP:192.1.2.23:500
also specify source port et.al.:
  socat - TCP:192.1.2.23:7,bind=192.1.2.45,sourceport=7
EOF
    exit 1
fi

port=
version=
protocol=
daemon=false

while test $# -gt 0 ; do
    case "$1" in
	*:* | *.* ) echo addresses are not implemented ; exit 1 ;;
	-[46] ) version=$(expr "$1" : '-\(.\)') ;;
	-udp ) protocol=UDP ;;
	-tcp ) protocol=TCP ;;
	[0-9]* ) port=$1 ;;
	-daemon ) daemon=true ;;
	* ) echo "invalid option $1" 1>&2 ; exit 1 ;;
    esac
    shift
done

if test -z "${port}" -o -z "${protocol}" -o -z "${version}" ; then
    echo "missing port, protocol or version" 1>&2
    exit 1
fi

echo listening on IPv${version} ${protocol} port ${port} 1>&2

socat="socat -v ${protocol}${version}-LISTEN:${port},fork EXEC:/bin/cat"

if ${daemon} ; then
    output=OUTPUT/$(hostname).echo-server.IPv${version}.${protocol}.${port}
    ${socat} > ${output}.log 2>&1 &
    echo $? > ${output}.pid
    exit 0
fi

exec ${socat}
