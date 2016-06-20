#!/bin/sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add block
ipsec auto --add us-block
ipsec auto --add clear
ipsec auto --add us-clear
ipsec auto --add private-or-clear
ipsec auto --add us-private-or-clear
ipsec auto --add private
ipsec auto --add us-private

ipsec auto --route block
ipsec auto --route us-block
ipsec auto --route clear
ipsec auto --route us-clear
ipsec auto --route private-or-clear
ipsec auto --route us-private-or-clear
ipsec auto --route private
ipsec auto --route us-private

# now, re-read the policy groups
ipsec whack --listen

ipsec eroute




