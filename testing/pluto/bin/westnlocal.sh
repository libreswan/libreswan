#!/bin/sh

# this script is used by "west" UMLs that want to have per-test
# configuration files.

/testing/pluto/bin/wait-until-network-ready

# Seems our root-36 Lenny does not cause sysctl -p to be run.
# Redirect because we don't want to see diffs or ipv6 errors
sysctl -p >/dev/null 2> /dev/null

# if ipsec is running, stop it
pidof pluto && ipsec setup stop

rm -f /tmp/pluto.log
ln -s /testing/pluto/$TESTNAME/OUTPUT/pluto.east.log /tmp/pluto.log

# clear firewall from previous test rules
iptables -F
# prepare the LOGDROP table for use
iptables -N LOGDROP
iptables -A LOGDROP -j LOG --log-prefix "LOGDROP "
iptables -A LOGDROP -j DROP

if [ "$WEST_USERLAND" == "strongswan" ]
then
	# setup strongswan
	mkdir -p /tmp/strongswan/etc/ipsec.d/certs /tmp/strongswan/etc/ipsec.d/cacerts /tmp/strongswan/etc/ipsec.d/aacerts /tmp/strongswan/etc/ipsec.d/ocspcerts /tmp/strongswan/etc/ipsec.d/crls
	cp /testing/pluto/$TESTNAME/west.conf    /tmp/strongswan/etc/ipsec.conf
	cp /testing/pluto/$TESTNAME/west.secrets /tmp/strongswan/etc/ipsec.secrets
	chmod 600 /tmp/strongswan/etc/ipsec.secrets
	touch /tmp/strongswan/etc/ipsec.secrets

elif [ "$WEST_USERLAND" == "racoon2" ]
then
	# setup racoon
	# note: tests do this manual - needs to be merged in
	echo "racoon2 not yet merged into local scripts"
else
	# setup pluto
	mkdir -p /tmp/$TESTNAME
	mkdir -p /tmp/$TESTNAME/ipsec.d/cacerts
	mkdir -p /tmp/$TESTNAME/ipsec.d/crls
	mkdir -p /tmp/$TESTNAME/ipsec.d/certs
	mkdir -p /tmp/$TESTNAME/ipsec.d/private

	cp /testing/pluto/$TESTNAME/west.conf /tmp/$TESTNAME/ipsec.conf
	cp /etc/ipsec.secrets                    /tmp/$TESTNAME
	
	# this differs from westlocal.sh right here, where we copy
	# rather than append.
	if [ -f /testing/pluto/$TESTNAME/west.secrets ]
	then
	    	cp /testing/pluto/$TESTNAME/west.secrets /tmp/$TESTNAME/ipsec.secrets
	fi

	mkdir -p /tmp/$TESTNAME/ipsec.d/policies
	cp -r /etc/ipsec.d/*          /tmp/$TESTNAME/ipsec.d

	IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS
fi
