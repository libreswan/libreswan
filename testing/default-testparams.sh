#!/bin/sh

# start by stripping out trailing CR (aka ^M) from \n being printed to
# a TTY
REF_CONSOLE_FIXUPS="nocr.sed"

REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS kernel.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS kernel-failed-to-disable-lr0.sed"

REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cut-postfinal.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-prompt-sanitize.sed"

REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS post-mortem.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS wilog.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS routes.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS namespace.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS xfrmi.sed"
# note order, sed goes first
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS sanitize-retransmits.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-status.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS systemd-fixup.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS initscripts-fixup.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS retransmit-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS misc-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS tcpdump.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS iptables.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ikev2-proposal-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS seccomp.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS all-date-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS impair.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS strongswan.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS linux-audit.sed"

# The following sanitizers are written to only modify specific commands
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-start.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-kernel-state.sed"		# includes ip xfrm state
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-kernel-policy.sed"	# includes ip xfrm policy
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS nft.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ephemeral-ports.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ip-addr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ip-link.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS swan-prep.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-certutil.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-taskset.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-auto-up.sed-n"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pem.sed-n"
# this is last
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-prompt-double.sed"
