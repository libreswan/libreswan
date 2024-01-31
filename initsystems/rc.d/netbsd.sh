#!/bin/sh

# mimic racoon

# PROVIDE: ike
# REQUIRE: isdnd kdc ppp
# BEFORE:  SERVERS
# KEYWORD: shutdown

$_rc_subr_loaded . /etc/rc.subr

# standardize PATH, and export it for everything else's benefit;
# should config.mk generate this?
IPSEC_SBINDIR="${IPSEC_SBINDIR:-@@SBINDIR@@}"
NSS_BINDIR="${NSS_BINDIR:-@@NSS_BINDIR@@}"
PATH="${NSS_BINDIR}:${PATH#${NSS_BINDIR}:}"
PATH="${IPSEC_SBINDIR}:${PATH#${IPSEC_SBINDIR}:}"
export PATH

name="pluto"
rcvar=$name
pidfile="@@RUNDIR@@/${name}.pid"
command="@@LIBEXECDIR@@/pluto"
command_args="--logfile @@LOGDIR@@/pluto.log --config @@IPSEC_CONF@@ --leak-detective"
required_files="@@IPSEC_CONF@@"
start_precmd="@@SBINDIR@@/ipsec checknss"

load_rc_config $name
run_rc_command "$1"
