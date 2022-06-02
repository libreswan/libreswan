#!/bin/ksh

daemon="@FINALLIBEXECDIR@/pluto"
daemon_flags="--logfile @FINALLOGDIR@/pluto.log --config @FINALSYSCONFDIR@/ipsec.conf --leak-detective"

. /etc/rc.d/rc.subr

#pidfile="@IPSEC_RUNDIR@/${name}.pid"
#required_files="@FINALSYSCONFDIR@/ipsec.conf"

case $1 in
onestart ) set start ;;
onestop ) set stop ;;
esac

rc_pre()
{
    @FINALSBINDIR@/ipsec checknss
}

rc_cmd $1
