#!/bin/sh

set -eu

op=$1 ; shift

hostname=$(hostname)
pidfile=$PWD/OUTPUT/${hostname}.sshd.pid
logfile=$PWD/OUTPUT/${hostname}.sshd.log

RUN() {
    cat <<EOF 1>&2
==== cut ====
+ "$@"
==== tuc ====
EOF
    "$@"
}


start_sshd() {
    if expr "${SUDO_COMMAND:+}" : '.*/nsenter ' > /dev/null ||
	    ! systemctl is-active --quiet service ; then
	RUN /usr/sbin/sshd -o PidFile=${pidfile} -E ${logfile}
    else
	RUN : SSHD is already running
    fi
}

stop_sshd() {
    if test -r ${pidfile} ; then
	pid=$(cat ${pidfile})
	rm ${pidfile}
	RUN kill ${pid}
    else
	RUN : SSHD is not running
    fi
}

case ${op} in
    start ) start_sshd ;;
    stop ) stop_sshd ;;
    * ) echo "unrecognized $@" 1>&2 ;;
esac
