#!/bin/sh

/testing/pluto/bin/wait-until-network-ready

# Seems our root-36 Lenny does not cause sysctl -p to be run.
# Redirect because we don't want to see diffs or ipv6 errors
sysctl -p >/dev/null 2> /dev/null

# if ipsec is running, stop it
pidof pluto && ipsec setup stop

rm -f /tmp/pluto.log
ln -s /testing/pluto/$TESTNAME/OUTPUT/pluto.road.log /tmp/pluto.log

# clear firewall from previous test rules
iptables -F
# prepare the LOGDROP table for use
iptables -N LOGDROP
iptables -A LOGDROP -j LOG --log-prefix "LOGDROP "
iptables -A LOGDROP -j DROP


export HOST=road
source /testing/pluto/bin/hostlocal.sh
