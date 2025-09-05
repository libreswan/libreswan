# algo-{ikev1,ikev2}-<ike>-{esp,ah}-<esp|ah>

set -eu

wait_until_alive_param="-I 192.0.1.254 192.0.2.254"
connection_name=algo

if test $# -lt 1 ; then
    cat <<EOF 1>&3
Usage:
   $0 [ <connection-param> ... ] [ -- <wait-until-alive-param> ... ]
Run:
- ipsec start
  always start afresh so state and connection numbers are deterministic
- ipsec addconn --name ${connection_name} also=<hostname> <connection-param>
  the also= lets generic parameters be in ipsec.conf
- ipsec up ${connection_name}
  it is assumed it will establish
- wait-until-alive <wait-until-alive-param>
  the default is WESTNET to EASTNET -- ${wait_until_alive_param}
- ipsec stop
  clean up ready for next test
EOF
    exit 1
fi

RUN() {
    echo " $@"
    "$@"
}

connection_param=
while test $# -gt 0 ; do
    if test "$1" = "--" ; then
	shift
	break
    fi
    connection_param="${connection_param} $1" ; shift
done

if test $# -gt 0 ; then
    wait_until_alive_param="$@"
fi

RUN ipsec start
../../guestbin/wait-until-pluto-started
RUN ipsec addconn \
    --name ${connection_name} \
    also=`hostname` \
    ${connection_param}
RUN ipsec up ${connection_name}
RUN ../../guestbin/wait-until-alive ${wait_until_alive_param}
RUN ipsec stop
