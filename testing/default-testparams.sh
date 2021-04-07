#!/bin/sh

# start by stripping out trailing CR (aka ^M) from \n being printed to
# a TTY
REF_CONSOLE_FIXUPS="nocr.sed"

REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS kern-list-fixups.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS kernel-failed-to-disable-lr0.sed"

REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cut-postfinal.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-prompt-sanitize.sed"

REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS cutout.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS post-mortem.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS wilog.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS routes.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS klips-debug-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-setup-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-whack-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS host-ping-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS namespace.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS xfrmi.sed"
# note order, sed goes first
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS sanitize-retransmits.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-look-esp-sanitize.pl"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-ver-remove.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-status.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS systemd-fixup.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS initscripts-fixup.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS pluto-log-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS retransmit-sanitize.sed"
# always included so we can hot-swap libreswan for openswan in any test
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS openswan.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS misc-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS tcpdump.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ikev2-proposal-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS seccomp.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS all-date-sanitize.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS debug.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS impair.sed"

# The following sanitizers are written to only modify specific commands
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ephemeral-ports.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-ip-route.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-ip-addr.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-ip-link.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-ip-xfrm-state.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-ip-xfrm-policy.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-swan-prep.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-certutil.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-cp.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-tcpdump.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-taskset.sed"
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS ipsec-auto-up.n.sed"
# this is last
REF_CONSOLE_FIXUPS="$REF_CONSOLE_FIXUPS guest-prompt-double.sed"
