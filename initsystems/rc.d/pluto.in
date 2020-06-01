#!/bin/sh

# mimic racoon

# PROVIDE: ike
# REQUIRE: isdnd kdc ppp
# BEFORE:  SERVERS
# KEYWORD: shutdown

$_rc_subr_loaded . /etc/rc.subr

name="pluto"
rcvar=$name
pidfile="@IPSEC_RUNDIR@/${name}.pid"
command="@FINALLIBEXECDIR@/pluto"
command_args="--logfile @FINALLOGDIR@/pluto.log --config @FINALSYSCONFDIR@/ipsec.conf --leak-detective"
required_files="@FINALSYSCONFDIR@/ipsec.conf"
start_precmd="@FINALSBINDIR@/ipsec checknss"

load_rc_config $name
run_rc_command "$1"
