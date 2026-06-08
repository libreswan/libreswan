# algo-{ikev1,ikev2}-<ike>-{esp,ah}-<esp|ah>

set -eu

connection_name=algo

if test $# -lt 1 ; then
    cat <<EOF 1>&3
Usage:

   $0 <connection-name> [ <connection-param> ... ] [ -- <wait-until-alive-param> ... ]

Runs the following commands in sequence:

- ipsec start

- ipsec addconn --name ${connection_name} <connection-param>

- ipsec up ${connection_name}

- wait-until-alive <wait-until-alive-param>

  but only when <wait-until-alive-param> are specified

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

wait_until_alive_param=
if test $# -gt 0 ; then
    wait_until_alive_param="$@"
fi

RUN ipsec start
../../guestbin/wait-until-pluto-started
RUN ipsec addconn \
    --name ${connection_name} \
    ${connection_param}
RUN ipsec up ${connection_name}
if test -n "${wait_until_alive_param}" ; then
    RUN ../../guestbin/wait-until-alive ${wait_until_alive_param}
fi
RUN ipsec stop
