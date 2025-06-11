#!/bin/ksh

daemon="@@LIBEXECDIR@@/pluto"
daemon_flags="--config @@IPSEC_CONF@@ --leak-detective"

. /etc/rc.d/rc.subr

#pidfile="@@RUNDIR@@/${name}.pid"
#required_files="@@IPSEC_CONF@@"

case $1 in
onestart ) set start ;;
onestop ) set stop ;;
esac

rc_pre()
{
    @@SBINDIR@@/ipsec checknss
}

rc_cmd $1
