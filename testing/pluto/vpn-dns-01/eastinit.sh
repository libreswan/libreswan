named

TESTNAME=vpn-dns-01
mkdir -p /tmp/$TESTNAME

cp /testing/pluto/$TESTNAME/east.conf  /tmp/$TESTNAME/ipsec.conf
cp /etc/ipsec.secrets                  /tmp/$TESTNAME

mkdir -p /tmp/$TESTNAME/ipsec.d/policies
cp /etc/ipsec.d/policies/* /tmp/$TESTNAME/ipsec.d/policies

IPSEC_CONFS=/tmp/$TESTNAME export IPSEC_CONFS

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

dig eastkey.uml.freeswan.org. key
dig westtxt.uml.freeswan.org. txt

ipsec whack --debug-control

#SHOW=--show

: BAD/KEY - will fail
ipsec auto $SHOW --add    westnet-eastnet-bad-key
ipsec auto $SHOW --delete westnet-eastnet-bad-key

: TXT/BAD - will fail
ipsec auto $SHOW --add    westnet-eastnet-txt-bad
ipsec auto $SHOW --delete westnet-eastnet-txt-bad

: KEY/KEY
ipsec auto $SHOW --add    westnet-eastnet-key-key
ipsec auto $SHOW --delete westnet-eastnet-key-key

: KEY/TXT
ipsec auto $SHOW --add    westnet-eastnet-key-txt
ipsec auto $SHOW --delete westnet-eastnet-key-txt

: TXT/TXT
ipsec auto $SHOW --add    westnet-eastnet-txt-txt
ipsec auto $SHOW --delete westnet-eastnet-txt-txt

: TXT/KEY
ipsec auto $SHOW --add    westnet-eastnet-txt-key
ipsec auto $SHOW --delete westnet-eastnet-txt-key

