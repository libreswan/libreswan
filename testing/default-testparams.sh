#!/bin/sh

REF_CONSOLE_FIXUPS=""

# start by stripping out trailing CR (aka ^M) from \n being printed to
# a TTY
REF_CONSOLE_FIXUPS+=" nocr.sed"

REF_CONSOLE_FIXUPS+=" kernel.sed"

# basic prompt et.al. cleanup
REF_CONSOLE_FIXUPS+=" prompt.sed"

REF_CONSOLE_FIXUPS+=" ipsec-start.sed"
REF_CONSOLE_FIXUPS+=" ipsec-pluto.sed"
REF_CONSOLE_FIXUPS+=" ipsec-stop.sed"
REF_CONSOLE_FIXUPS+=" ipsec-restart.sed"

REF_CONSOLE_FIXUPS+=" pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS+=" host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS+=" namespace.sed"
REF_CONSOLE_FIXUPS+=" xfrmi.sed"
# note order, sed goes first
REF_CONSOLE_FIXUPS+=" sanitize-retransmits.sed"
REF_CONSOLE_FIXUPS+=" ipsec-status.sed"
REF_CONSOLE_FIXUPS+=" systemd-fixup.sed"
REF_CONSOLE_FIXUPS+=" retransmit-sanitize.sed"
REF_CONSOLE_FIXUPS+=" misc-sanitize.sed"
REF_CONSOLE_FIXUPS+=" tcpdump.sed"
REF_CONSOLE_FIXUPS+=" iptables.sed"
REF_CONSOLE_FIXUPS+=" ikev2-proposal-sanitize.sed"
REF_CONSOLE_FIXUPS+=" seccomp.sed"
REF_CONSOLE_FIXUPS+=" all-date-sanitize.sed"
REF_CONSOLE_FIXUPS+=" impair.sed"
REF_CONSOLE_FIXUPS+=" strongswan.sed"
REF_CONSOLE_FIXUPS+=" linux-audit.sed"

# The following sanitizers are written to only modify specific commands
REF_CONSOLE_FIXUPS+=" ipsec-kernel-state.sed"		# includes ip xfrm state
REF_CONSOLE_FIXUPS+=" ipsec-kernel-policy.sed"	# includes ip xfrm policy
REF_CONSOLE_FIXUPS+=" nft.sed"
REF_CONSOLE_FIXUPS+=" ephemeral-ports.sed"
REF_CONSOLE_FIXUPS+=" ipsec-certutil.sed"
REF_CONSOLE_FIXUPS+=" ipsec-up.sed"
REF_CONSOLE_FIXUPS+=" pem.sed"

# all.console.txt gets it's own list; add as necessary.  .sed-f
# scripts are all run from a single sed!

ALL_CONSOLE_FIXUPS=""
ALL_CONSOLE_FIXUPS+=" prompt.sed-f"
ALL_CONSOLE_FIXUPS+=" pluto-whack-sanitize.sed-f"
ALL_CONSOLE_FIXUPS+=" all-date-sanitize.sed-f"
ALL_CONSOLE_FIXUPS+=" ipsec-start.sed-f"
ALL_CONSOLE_FIXUPS+=" ipsec-kernel-state.sed-f"		# includes ip xfrm state
ALL_CONSOLE_FIXUPS+=" ipsec-kernel-policy.sed-f"	# includes ip xfrm policy
