#!/bin/sh

# this script is used by "north" UMLs that want to have per-test
# configuration files, and will be hitting sunrise-oe to test with.

/testing/pluto/bin/wait-until-network-ready

# Seems our root-36 Lenny does not cause sysctl -p to be run.
# Redirect because we don't want to see diffs or ipv6 errors
sysctl -p >/dev/null 2> /dev/null

# if ipsec is running, stop it
pidof pluto && ipsec setup stop

rm -f /tmp/pluto.log
ln -s /testing/pluto/$TESTNAME/OUTPUT/pluto.north.log /tmp/pluto.log

# clear firewall from previous test rules
iptables -F
# prepare the LOGDROP table for use
iptables -N LOGDROP
iptables -A LOGDROP -j LOG --log-prefix "LOGDROP "
iptables -A LOGDROP -j DROP

TESTING=${TESTING-/testing}

mkdir -p /tmp/$TESTNAME
cp ${TESTING}/pluto/$TESTNAME/north.conf /tmp/$TESTNAME/ipsec.conf
cp /etc/ipsec.secrets                    /tmp/$TESTNAME

mkdir -p /tmp/$TESTNAME/ipsec.d/policies
cp /etc/ipsec.d/policies/* /tmp/$TESTNAME/ipsec.d/policies
cp -r /etc/ipsec.d/*          /tmp/$TESTNAME/ipsec.d

IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS
