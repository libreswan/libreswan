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
command="@@LIBEXECDIR@@/pluto"
command_args="--logfile @@LOGDIR@@/pluto.log --config @@SYSCONFDIR@@/ipsec.conf --leak-detective"
required_files="@@SYSCONFDIR@@/ipsec.conf"
start_precmd="@@SBINDIR@@/ipsec checknss"

load_rc_config $name
run_rc_command "$1"
