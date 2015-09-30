#!/bin/sh

# this script is used by "$HOST" UMLs that want to have per-test
# configuration files, and will be hitting sunrise-oe to test with.

/testing/pluto/bin/wait-until-network-ready

mkdir -p /tmp/$TESTNAME
mkdir -p /tmp/$TESTNAME/ipsec.d/cacerts
mkdir -p /tmp/$TESTNAME/ipsec.d/crls
mkdir -p /tmp/$TESTNAME/ipsec.d/certs
mkdir -p /tmp/$TESTNAME/ipsec.d/private
cp /testing/pluto/$TESTNAME/$HOST.conf /tmp/$TESTNAME/ipsec.conf
cp /etc/ipsec.secrets                    /tmp/$TESTNAME
if [ -f /testing/pluto/$TESTNAME/$HOST.secrets ]
then
    cat /testing/pluto/$TESTNAME/$HOST.secrets >>/tmp/$TESTNAME/ipsec.secrets
fi


mkdir -p /tmp/$TESTNAME/ipsec.d/policies
cp /etc/ipsec.d/policies/* /tmp/$TESTNAME/ipsec.d/policies

: make sure that target is in policy private!
echo 192.0.2.2/32	>>/tmp/$TESTNAME/ipsec.d/policies/private

IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS
