#!/bin/sh

set +o emacs

: ==== start ====

D=/testing/scripts/ipsec.conf-myid-01

export IPSEC_CONFS="$D/etc-nomyid"

ipsec setup start
sleep 4
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --status
ipsec setup stop

ipsec eroute

export IPSEC_CONFS="$D/etc-myid"

ipsec setup start
sleep 4
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --status
ipsec setup stop

: ==== end ====
