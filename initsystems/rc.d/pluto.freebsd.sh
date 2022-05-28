#!/bin/sh

# mimic ipsec

# PROVIDE: ike
# REQUIRE: FILESYSTEMS isdnd kdc ppp
# BEFORE:  DAEMON mountcritremote
# KEYWORD: nojailvnet

. /etc/rc.subr

name="pluto"
desc="Libreswan IKE Daemon"
required_modules=ipsec
rcvar=${name}_enable

command="@FINALLIBEXECDIR@/pluto"
command_args="--logfile @FINALLOGDIR@/pluto.log --config @FINALSYSCONFDIR@/ipsec.conf --leak-detective"
required_files="@FINALSYSCONFDIR@/ipsec.conf"

pidfile="@IPSEC_RUNDIR@/${name}.pid"

start_precmd="@FINALSBINDIR@/ipsec checknss"

load_rc_config $name
run_rc_command "$1"
